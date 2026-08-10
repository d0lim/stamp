package runtime

// snapshot.go turns the stored policy set into something the evaluator can
// judge with. It is the one place the store and the engine meet, and it lives
// here rather than in either package because it is composition: the engine must
// not learn about pgx, and the store must not learn how a snapshot is versioned.
//
// Three things it does are load-bearing.
//
// The reserved governance policy is excluded. It is written against its own
// schema and binds entity types the tenant schema has never declared, so a
// snapshot that contained it would not compile — [store.LoadEffectiveSet] is
// therefore not usable here, and [revision.IsReserved] is the filter.
//
// Every policy gets a version identifier that is unique per policy. The compile
// cache is keyed by the (schema version, policy version) pair and carries no
// policy identifier, and the store's version counter restarts at 1 for each
// policy — so stringifying the row's version would hand every policy in the set
// the same key and let one policy be evaluated with another's compiled
// condition. The identifier is "id@version" for that reason.
//
// A schema is verified against the deployment's configured sources on every
// load. A policy set that names a source this process cannot serve is refused
// here, before it becomes the set an instance judges with.
//
// That verification is a list rather than one call, and the list is the whole
// of the gate. There are three source planes — the synchronous fact registry,
// the velocity sources, the group directories — and each one checks the kinds
// it serves and skips the rest, deliberately: [fact.Registry.VerifySchema]
// returns early on an event or an idp_group source precisely because it is not
// the plane that would answer it. So a plane missing from this list is not a
// weaker check, it is no check at all for its kind, and a schema could name a
// source that nothing in the process can resolve and still load. Which is why a
// deployment that configures no velocity sources still contributes a gate here:
// refusing every event source is the correct answer for it, and silence is not.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// schemaGate is one plane's answer to "can this deployment serve this schema".
//
// Every implementation reports its refusals wrapping [fact.ErrLoad], so a
// caller can tell "this deployment refuses this policy set" from a runtime
// failure without caring which plane refused.
type schemaGate interface {
	VerifySchema(*policy.Schema) error
}

// unconfiguredKind refuses every schema source of a kind this process runs no
// plane for.
//
// It is the gate a deployment gets in place of a plane it did not configure,
// and it exists so that "configured nothing" and "configured something" refuse
// the same schema. The alternative — leaving the kind ungated when no plane
// owns it — is a policy that names an event source, loads, and denies at call
// time with a resolver error, which is a load-time misconfiguration discovered
// during the request it breaks.
type unconfiguredKind struct {
	kind policy.SourceKind
	why  string
}

func (u unconfiguredKind) VerifySchema(s *policy.Schema) error {
	if s == nil {
		return nil
	}
	var errs []error
	for i := range s.Sources {
		if s.Sources[i].Kind != u.kind {
			continue
		}
		errs = append(errs, fmt.Errorf("%w: source %q: declared by the schema as %s, but %s",
			fact.ErrLoad, s.Sources[i].Name, u.kind, u.why))
	}
	return errors.Join(errs...)
}

// emptySchemaVersion names the snapshot a fresh installation holds: no schema
// has been authored, so there is nothing to version. It is not the empty string
// because [engine.NewSnapshot] requires an identifier, and it is a fixed string
// because every fresh instance must agree that they hold the same nothing.
const emptySchemaVersion = "empty"

// snapshotSource loads the effective tenant policy set.
type snapshotSource struct {
	store *store.Store
	// gates is every source plane this deployment runs, in the order an
	// operator reads them. A schema has to satisfy all of them.
	gates []schemaGate
}

var _ engine.SnapshotLoader = (*snapshotSource)(nil)

// LoadSnapshot implements [engine.SnapshotLoader].
//
// A fresh installation with no schema is a successful load of an empty set, not
// an error. Every request against it denies with no_matching_policy, which is
// R53's fail-closed direction — whereas failing the load would make an instance
// refuse to start until somebody authored a policy.
func (s *snapshotSource) LoadSnapshot(ctx context.Context) (*engine.Snapshot, engine.Revision, error) {
	schema, schemaVersion, err := s.schema(ctx)
	if err != nil {
		return nil, "", err
	}
	// The refusals are collected rather than reported one at a time: an
	// operator fixing a deployment should see every source the schema names
	// that this process cannot serve, not the first one.
	var gateErrs []error
	for _, gate := range s.gates {
		if gate == nil {
			continue
		}
		gateErrs = append(gateErrs, gate.VerifySchema(schema))
	}
	if err := errors.Join(gateErrs...); err != nil {
		return nil, "", fmt.Errorf("runtime: the stored schema names sources this deployment does not serve: %w", err)
	}

	records, err := store.EffectivePolicies(ctx, s.store.Pool())
	if err != nil {
		return nil, "", err
	}
	versions := make([]engine.PolicyVersion, 0, len(records))
	digest := sha256.New()
	_, _ = fmt.Fprintf(digest, "schema:%s\n", schemaVersion)
	for _, rec := range records {
		if revision.IsReserved(rec.ID) {
			continue
		}
		p, perr := rec.Policy()
		if perr != nil {
			return nil, "", perr
		}
		version := rec.ID + "@" + strconv.FormatInt(rec.Version, 10)
		_, _ = fmt.Fprintf(digest, "policy:%s\n", version)
		versions = append(versions, engine.PolicyVersion{Version: version, Policy: *p})
	}

	snap, err := engine.NewSnapshot(schemaVersion, *schema, versions)
	if err != nil {
		return nil, "", fmt.Errorf("runtime: build the effective snapshot: %w", err)
	}
	return snap, engine.Revision(hex.EncodeToString(digest.Sum(nil))[:32]), nil
}

// schema reads the schema the tenant policies are written against.
func (s *snapshotSource) schema(ctx context.Context) (*policy.Schema, string, error) {
	rec, err := store.LatestSchema(ctx, s.store.Pool())
	if errors.Is(err, store.ErrNotFound) {
		return &policy.Schema{}, emptySchemaVersion, nil
	}
	if err != nil {
		return nil, "", err
	}
	decoded, err := revision.DecodeSchema(rec.Document)
	if err != nil {
		return nil, "", fmt.Errorf("runtime: decode stored schema v%d: %w", rec.Version, err)
	}
	return decoded, strconv.FormatInt(rec.Version, 10), nil
}
