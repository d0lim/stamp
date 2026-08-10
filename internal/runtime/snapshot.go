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
// A schema is verified against the deployment's configured fact sources on every
// load. A policy set that names a source this process cannot serve is refused
// here, before it becomes the set an instance judges with.

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

// emptySchemaVersion names the snapshot a fresh installation holds: no schema
// has been authored, so there is nothing to version. It is not the empty string
// because [engine.NewSnapshot] requires an identifier, and it is a fixed string
// because every fresh instance must agree that they hold the same nothing.
const emptySchemaVersion = "empty"

// snapshotSource loads the effective tenant policy set.
type snapshotSource struct {
	store *store.Store
	facts *fact.Registry
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
	if s.facts != nil {
		if err := s.facts.VerifySchema(schema); err != nil {
			return nil, "", fmt.Errorf("runtime: the stored schema names fact sources this deployment does not serve: %w", err)
		}
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
