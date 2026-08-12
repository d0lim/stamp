package runtime

// readiness.go answers one question for every listener this process binds: may a
// request sent here be served?
//
// The only thing that can currently answer "no" is the schema, and the reason is
// the rollout's shape. Exactly one tier migrates — the chart gives `database
// .migrate` to the `api` role and to no other — while `helm upgrade` rolls every
// Deployment at once with nothing sequencing them: no hooks, no Job, no
// initContainer. So a decide pod running the new image can come up against a
// database still on the old schema, and every statement it issues names a column
// that is not there yet. Postgres answers 42703, the decide surface answers 500,
// and the pod is in its Service the whole time because the probe in front of it
// only asked whether the process was alive.
//
// The gate turns that into a wait. A pod whose binary is ahead of the database
// reports itself unready, Kubernetes keeps it out of the Service, the old pods
// keep serving on the old schema, and the rollout resumes on its own the moment
// the migrating tier lands the migration. The failure mode becomes a rollout
// that takes longer, and in the worst case one that stalls with a message saying
// which schema it is waiting for — instead of a fleet of pods answering errors.
//
// The alternative was a `pre-upgrade` hook Job that migrates before anything
// rolls. It is not obviously wrong, and a deployment that wants it can still add
// one, but it was rejected here: a hook Job puts the migration on the critical
// path of every upgrade including the ones that change nothing about the schema,
// it needs its own image, RBAC and failure semantics (a failed hook fails the
// release, leaving an operator to decide what "release" now means), and it does
// nothing at all for the case where the schema is behind for a reason other than
// this upgrade. The readiness gate is one query and holds in every one of those
// cases.

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/d0lim/stamp/internal/store"
)

// schemaVersionGate reports whether the database has reached the schema this binary's
// queries are written against.
type schemaVersionGate struct {
	store *store.Store
	// want is the version this binary's embedded migrations reach, read once at
	// assembly. It cannot change while the process runs.
	want uint
	// open latches. See [schemaVersionGate.ready].
	open   atomic.Bool
	logger *slog.Logger
	// logged keeps the "waiting for schema" line to one per process. A probe
	// every few seconds against a stalled rollout would otherwise write the
	// same sentence into the log until someone noticed it, which is how the
	// line that says what is wrong gets scrolled away by itself.
	logged atomic.Bool
}

func newSchemaVersionGate(s *store.Store, logger *slog.Logger) (*schemaVersionGate, error) {
	want, err := store.LatestSchemaVersion()
	if err != nil {
		return nil, fmt.Errorf("runtime: readiness gate: %w", err)
	}
	return &schemaVersionGate{store: s, want: want, logger: logger}, nil
}

// ready answers [api.Config.Ready].
//
// It latches: once the schema has arrived the gate stops asking, and every later
// probe is answered without touching the database. The question it exists to ask
// — "has this rollout's migration landed yet?" — is answered once and stays
// answered, and a probe every few seconds per pod per surface is not something
// to spend a query on for the rest of the process's life.
//
// The cost of latching is that a schema rolled *backwards* under a running pod
// leaves the pod ready and failing. That is deliberate. A down migration is a
// manual act that already requires putting the old image back, and a gate that
// reopened on it would pull every pod in the fleet out of service during exactly
// the incident where an operator is trying to work — trading a subset of
// requests failing for all of them failing.
//
// A database that cannot be reached is reported unready rather than ready. It is
// the same answer for the same reason: a request routed to this pod would fail,
// and that is the only thing readiness means.
//
// That last paragraph holds exactly once — before the gate has opened — and it
// is worth being blunt about, because it reads like a general statement and is
// not one. The latch above means an unreachable database is reported unready
// only by a process that has never yet been found ready. The chart probes
// readiness every five seconds from two seconds after start, so a deployed pod
// has an open gate within seconds of boot and answers 200 for the rest of its
// life, including with no database at all. Both answers are measured in
// TestTheSurfacesAnswerWhenTheDatabaseIsGone's readiness subtest, and the
// operational consequence — do not use /readyz as a database health signal — is
// written down in docs/operations/failure-modes.md. Nothing about the behaviour
// changed when that was found; what changed is that it is now stated.
func (g *schemaVersionGate) ready(ctx context.Context) error {
	if g.open.Load() {
		return nil
	}
	version, dirty, ok, err := g.store.SchemaBehind(ctx, g.want)
	switch {
	case err != nil:
		return fmt.Errorf("database schema version is unreadable: %w", err)
	case dirty:
		// A dirty schema is a migration that failed part-way, and which part
		// landed is the thing nobody can tell from the version number. Serving
		// on it is guessing.
		return fmt.Errorf("database schema is dirty at version %d: a migration failed part-way "+
			"and no tier may serve on it until an operator resolves it; this build needs %d",
			version, g.want)
	case !ok:
		if g.logger != nil && g.logged.CompareAndSwap(false, true) {
			g.logger.Warn("holding this process out of service until the database schema catches up",
				slog.Uint64("schema_version", uint64(version)),
				slog.Uint64("required_version", uint64(g.want)))
		}
		return fmt.Errorf("database schema is at version %d and this build needs %d: "+
			"the migrating tier has not applied it yet", version, g.want)
	}
	g.open.Store(true)
	return nil
}
