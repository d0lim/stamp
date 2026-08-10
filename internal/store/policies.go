package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/d0lim/stamp/internal/policy"
)

// Origin is a policy's authoring origin. It decides which authoring path owns
// the policy, and it exists because the file path's desired-state comparison
// has to be restricted to file-authored policies: without it, the next apply
// computes every console-authored policy as a deletion.
type Origin string

// The authoring origins.
const (
	OriginForm Origin = "form"
	OriginFile Origin = "file"
)

// Valid reports whether o is a known origin.
func (o Origin) Valid() bool { return o == OriginForm || o == OriginFile }

// ErrOriginTransfer reports a write that would move a policy between authoring
// paths without saying so. Origin only moves on an explicit handover
// declaration; there is no implicit move.
var ErrOriginTransfer = errors.New("store: policy origin transfer must be declared explicitly")

// SchemaRecord is a stored schema version.
type SchemaRecord struct {
	Version     int64
	Document    string
	ContentHash [32]byte
	Origin      Origin
	CreatedAt   time.Time
	CreatedBy   string
}

// PolicyRecord is a stored policy version.
type PolicyRecord struct {
	ID               string
	Version          int64
	SchemaVersion    int64
	Origin           Origin
	Document         string
	ContentHash      [32]byte
	RequiresDecision bool
	Deleted          bool
	CreatedAt        time.Time
	CreatedBy        string
	SupersededAt     *time.Time
}

// Policy decodes the stored document back into a policy value.
func (r PolicyRecord) Policy() (*policy.Policy, error) {
	set, err := policy.Decode(strings.NewReader(r.Document))
	if err != nil {
		return nil, fmt.Errorf("store: decode stored policy %q v%d: %w", r.ID, r.Version, err)
	}
	if len(set.Policies) != 1 {
		return nil, fmt.Errorf("store: stored policy %q v%d holds %d documents, want 1", r.ID, r.Version, len(set.Policies))
	}
	return &set.Policies[0], nil
}

// PolicyInput is a request to store a new version of a policy.
type PolicyInput struct {
	Policy        *policy.Policy
	SchemaVersion int64
	Origin        Origin
	Author        string

	// AssumeOwnership permits this write to change the policy's authoring
	// origin. It is the explicit handover declaration; without it a write that
	// would move a policy between paths is refused rather than performed
	// silently.
	AssumeOwnership bool
}

// PutSchema stores a new schema version and returns it.
//
// Schema versions accumulate rather than overwrite. A decision row points at a
// policy version, a policy version points at a schema version, and both
// pointers have to stay resolvable for as long as the audit log refers to them.
func PutSchema(ctx context.Context, q Querier, schema *policy.Schema, origin Origin, author string) (SchemaRecord, error) {
	if !origin.Valid() {
		return SchemaRecord{}, fmt.Errorf("store: schema origin %q must be %q or %q", origin, OriginForm, OriginFile)
	}
	doc, err := policy.Marshal(&policy.Set{Schema: *schema})
	if err != nil {
		return SchemaRecord{}, fmt.Errorf("store: encode schema: %w", err)
	}

	var next int64
	if err := q.QueryRow(ctx, `SELECT coalesce(max(version), 0) + 1 FROM policy_schemas`).Scan(&next); err != nil {
		return SchemaRecord{}, fmt.Errorf("store: next schema version: %w", err)
	}
	rec := SchemaRecord{
		Version:     next,
		Document:    string(doc),
		ContentHash: sha256.Sum256(doc),
		Origin:      origin,
		CreatedBy:   author,
	}
	err = q.QueryRow(ctx, `
		INSERT INTO policy_schemas (version, document, content_hash, origin, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at`,
		rec.Version, rec.Document, rec.ContentHash[:], string(rec.Origin), rec.CreatedBy).Scan(&rec.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return SchemaRecord{}, fmt.Errorf("store: schema version %d already exists: %w", next, ErrConflict)
		}
		return SchemaRecord{}, fmt.Errorf("store: store schema: %w", err)
	}
	rec.CreatedAt = rec.CreatedAt.UTC()
	return rec, nil
}

// LatestSchema returns the newest schema version.
func LatestSchema(ctx context.Context, q Querier) (SchemaRecord, error) {
	return scanSchema(q.QueryRow(ctx, `
		SELECT version, document, content_hash, origin, created_at, created_by
		FROM policy_schemas ORDER BY version DESC LIMIT 1`))
}

// GetSchema returns one schema version.
func GetSchema(ctx context.Context, q Querier, version int64) (SchemaRecord, error) {
	return scanSchema(q.QueryRow(ctx, `
		SELECT version, document, content_hash, origin, created_at, created_by
		FROM policy_schemas WHERE version = $1`, version))
}

func scanSchema(row pgx.Row) (SchemaRecord, error) {
	var (
		rec  SchemaRecord
		hash []byte
		orig string
	)
	err := row.Scan(&rec.Version, &rec.Document, &hash, &orig, &rec.CreatedAt, &rec.CreatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return SchemaRecord{}, ErrNotFound
	}
	if err != nil {
		return SchemaRecord{}, fmt.Errorf("store: read schema: %w", err)
	}
	copy(rec.ContentHash[:], hash)
	rec.Origin = Origin(orig)
	rec.CreatedAt = rec.CreatedAt.UTC()
	return rec, nil
}

// PutPolicy stores a new version of a policy, superseding the live one.
//
// The caller is expected to have validated the policy already; this records
// what the governance path decided, it does not decide it.
func PutPolicy(ctx context.Context, q Querier, in PolicyInput) (PolicyRecord, error) {
	if in.Policy == nil {
		return PolicyRecord{}, errors.New("store: PutPolicy needs a policy")
	}
	if !in.Origin.Valid() {
		return PolicyRecord{}, fmt.Errorf("store: policy origin %q must be %q or %q", in.Origin, OriginForm, OriginFile)
	}
	doc, err := policy.Marshal(&policy.Set{Policies: []policy.Policy{*in.Policy}})
	if err != nil {
		return PolicyRecord{}, fmt.Errorf("store: encode policy %q: %w", in.Policy.ID, err)
	}

	var (
		nextVersion  int64
		liveOrigin   *string
		liveExists   bool
		currentPolID = in.Policy.ID
	)
	err = q.QueryRow(ctx, `
		SELECT coalesce(max(version), 0) + 1,
		       (SELECT origin FROM policies WHERE id = $1 AND superseded_at IS NULL)
		FROM policies WHERE id = $1`, currentPolID).Scan(&nextVersion, &liveOrigin)
	if err != nil {
		return PolicyRecord{}, fmt.Errorf("store: next policy version for %q: %w", currentPolID, err)
	}
	liveExists = liveOrigin != nil
	if liveExists && Origin(*liveOrigin) != in.Origin && !in.AssumeOwnership {
		return PolicyRecord{}, fmt.Errorf("store: policy %q is owned by the %q path and this write claims %q: %w",
			currentPolID, *liveOrigin, in.Origin, ErrOriginTransfer)
	}

	if liveExists {
		if _, err := q.Exec(ctx,
			`UPDATE policies SET superseded_at = now() WHERE id = $1 AND superseded_at IS NULL`,
			currentPolID); err != nil {
			return PolicyRecord{}, fmt.Errorf("store: supersede policy %q: %w", currentPolID, err)
		}
	}

	rec := PolicyRecord{
		ID:               currentPolID,
		Version:          nextVersion,
		SchemaVersion:    in.SchemaVersion,
		Origin:           in.Origin,
		Document:         string(doc),
		ContentHash:      sha256.Sum256(doc),
		RequiresDecision: in.Policy.RequiresDecision(),
		CreatedBy:        in.Author,
	}
	err = q.QueryRow(ctx, `
		INSERT INTO policies
			(id, version, schema_version, origin, document, content_hash, requires_decision, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at`,
		rec.ID, rec.Version, rec.SchemaVersion, string(rec.Origin), rec.Document,
		rec.ContentHash[:], rec.RequiresDecision, rec.CreatedBy).Scan(&rec.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return PolicyRecord{}, fmt.Errorf("store: policy %q version %d already exists: %w",
				rec.ID, rec.Version, ErrConflict)
		}
		return PolicyRecord{}, fmt.Errorf("store: store policy %q: %w", rec.ID, err)
	}
	rec.CreatedAt = rec.CreatedAt.UTC()
	return rec, nil
}

// DeletePolicy tombstones a policy.
//
// The row is not removed. Decision rows reference (policy_id, policy_version)
// and an audit entry refers to the identifier, so a delete that removed history
// would break the pointer that makes a past decision explainable. The tombstone
// is a new version carrying the last document with deleted set.
func DeletePolicy(ctx context.Context, q Querier, id, author string) (PolicyRecord, error) {
	live, err := EffectivePolicy(ctx, q, id)
	if err != nil {
		return PolicyRecord{}, err
	}
	if _, err := q.Exec(ctx,
		`UPDATE policies SET superseded_at = now() WHERE id = $1 AND superseded_at IS NULL`, id); err != nil {
		return PolicyRecord{}, fmt.Errorf("store: supersede policy %q: %w", id, err)
	}

	rec := live
	rec.Version = live.Version + 1
	rec.Deleted = true
	rec.CreatedBy = author
	rec.SupersededAt = nil
	err = q.QueryRow(ctx, `
		INSERT INTO policies
			(id, version, schema_version, origin, document, content_hash, requires_decision, deleted, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8)
		RETURNING created_at`,
		rec.ID, rec.Version, rec.SchemaVersion, string(rec.Origin), rec.Document,
		rec.ContentHash[:], rec.RequiresDecision, rec.CreatedBy).Scan(&rec.CreatedAt)
	if err != nil {
		return PolicyRecord{}, fmt.Errorf("store: tombstone policy %q: %w", id, err)
	}
	rec.CreatedAt = rec.CreatedAt.UTC()
	return rec, nil
}

const policyColumns = `id, version, schema_version, origin, document, content_hash,
	requires_decision, deleted, created_at, created_by, superseded_at`

// GetPolicy returns one stored version, deleted or not.
func GetPolicy(ctx context.Context, q Querier, id string, version int64) (PolicyRecord, error) {
	return scanPolicy(q.QueryRow(ctx,
		`SELECT `+policyColumns+` FROM policies WHERE id = $1 AND version = $2`, id, version))
}

// EffectivePolicy returns the live version of a policy, including a tombstone.
func EffectivePolicy(ctx context.Context, q Querier, id string) (PolicyRecord, error) {
	return scanPolicy(q.QueryRow(ctx,
		`SELECT `+policyColumns+` FROM policies WHERE id = $1 AND superseded_at IS NULL`, id))
}

// PolicyVersions returns every stored version of a policy, oldest first.
func PolicyVersions(ctx context.Context, q Querier, id string) ([]PolicyRecord, error) {
	rows, err := q.Query(ctx,
		`SELECT `+policyColumns+` FROM policies WHERE id = $1 ORDER BY version`, id)
	if err != nil {
		return nil, fmt.Errorf("store: read policy versions: %w", err)
	}
	return collectPolicies(rows)
}

// EffectivePolicies returns the live, non-deleted policies. Passing origins
// restricts the result to those authoring paths, which is how the file path
// scopes its desired-state comparison.
func EffectivePolicies(ctx context.Context, q Querier, origins ...Origin) ([]PolicyRecord, error) {
	sql := `SELECT ` + policyColumns + ` FROM policies WHERE superseded_at IS NULL AND NOT deleted`
	args := []any{}
	if len(origins) > 0 {
		names := make([]string, len(origins))
		for i, o := range origins {
			names[i] = string(o)
		}
		sql += ` AND origin = ANY($1)`
		args = append(args, names)
	}
	sql += ` ORDER BY id`
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("store: read effective policies: %w", err)
	}
	return collectPolicies(rows)
}

// LoadEffectiveSet assembles the live policy set: the newest schema plus every
// live, non-deleted policy.
//
// The documents are re-parsed rather than reconstructed from columns, because
// the stored document is the artifact that was validated and the one a diff is
// taken against. Validation is not re-run — a policy only gets stored after it
// passes — so this is a decode, not a load.
func LoadEffectiveSet(ctx context.Context, q Querier) (*policy.Set, int64, error) {
	schema, err := LatestSchema(ctx, q)
	if err != nil {
		return nil, 0, err
	}
	policies, err := EffectivePolicies(ctx, q)
	if err != nil {
		return nil, 0, err
	}
	// Each stored document is a complete YAML document, so reassembling the set
	// means rebuilding the stream: the separator has to go back between them or
	// the second document's keys are read as part of the first.
	var doc strings.Builder
	doc.WriteString(schema.Document)
	for _, p := range policies {
		appendDocument(&doc, p.Document)
	}
	set, err := policy.Decode(strings.NewReader(doc.String()))
	if err != nil {
		return nil, 0, fmt.Errorf("store: decode effective policy set: %w", err)
	}
	return set, schema.Version, nil
}

// appendDocument writes a YAML document into a stream, inserting the separator
// the encoder omitted because each document was encoded on its own.
func appendDocument(b *strings.Builder, doc string) {
	if b.Len() > 0 {
		if !strings.HasSuffix(b.String(), "\n") {
			b.WriteString("\n")
		}
		b.WriteString("---\n")
	}
	b.WriteString(doc)
}

func scanPolicy(row pgx.Row) (PolicyRecord, error) {
	var (
		rec  PolicyRecord
		hash []byte
		orig string
	)
	err := row.Scan(&rec.ID, &rec.Version, &rec.SchemaVersion, &orig, &rec.Document, &hash,
		&rec.RequiresDecision, &rec.Deleted, &rec.CreatedAt, &rec.CreatedBy, &rec.SupersededAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return PolicyRecord{}, ErrNotFound
	}
	if err != nil {
		return PolicyRecord{}, fmt.Errorf("store: read policy: %w", err)
	}
	copy(rec.ContentHash[:], hash)
	rec.Origin = Origin(orig)
	rec.CreatedAt = rec.CreatedAt.UTC()
	return rec, nil
}

func collectPolicies(rows pgx.Rows) ([]PolicyRecord, error) {
	defer rows.Close()
	var out []PolicyRecord
	for rows.Next() {
		rec, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read policies: %w", err)
	}
	return out, nil
}
