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
//
// The second question this file answers arrived later and by measurement. The
// gate above latches, and a latched gate answered `200 ready` from a pod that
// had lost its database entirely — so the pod stayed in its Service and every
// request routed to it failed. The gate now closes again on that, and the
// evidence it closes on is described at [databaseReachability]. The rule the
// whole file follows is that readiness is about *this pod*: it reports what
// this process has already found out, and it never goes looking.

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/d0lim/stamp/internal/store"
)

// unreachableStreak is how many statements must fail to reach Postgres, with
// none succeeding in between, before this process calls its database gone and
// takes itself out of the Service.
//
// It is not one, and the reason is that one failure is a connection rather than
// a database. Each statement is issued over a pooled connection, and a single
// one can be reset by an idle timeout, a proxy recycling it, a failover that
// moved the primary, or the server closing it at a restart; pgxpool discards it
// and the next statement gets a fresh one, so a healthy process sees isolated
// transport failures as ordinary weather. Pulling a pod out of its Service for
// one of those would flap, and it would flap in the worst possible way: every
// replica shares the database, so they all observe the same blip at the same
// instant and the Service empties rather than shedding onto a healthy peer.
//
// It is also not large, and not a rate over a window. Three consecutive
// failures with nothing succeeding in between is not one connection — it is the
// pool failing to produce a working one — and a partial failure, where some
// statements still get answers, keeps resetting the streak and keeps the pod
// serving the requests it can still serve. That is the property worth having:
// the gate closes on a database that is *gone*, not on one that is *slow* or
// *erroring*, because a server that answers 42703 or a statement timeout has
// answered, and a readiness gate that reacted to those would empty the Service
// over a bad query.
//
// The cost of a threshold is that up to two requests can fail on a pod that is
// about to be removed. That is already true of any readiness signal — the probe
// period is five seconds and the failures happen in microseconds — and it is the
// side to be wrong on, because the alternative errs toward removing pods that
// were fine.
const unreachableStreak = 3

// databaseReachability is what this process has learned about its database from
// the work it was already doing.
//
// It is fed by [store.Config.OnReachability], which reports the outcome of
// every statement the process issues without issuing any of its own. That is
// the whole design: the readiness gate needs to know whether the database is
// there, and the two ways to find out are to ask it or to notice. Asking — a
// query per probe per pod — puts load on the database at the moment it is least
// able to take it, which is how a database incident becomes a database incident
// plus a probe storm. Noticing costs nothing, and a process serving traffic
// already has the answer.
//
// What noticing cannot do is tell a pod the database came back, because a pod
// that has been removed from its Service is no longer issuing the statements it
// would notice with. That half is handled by the gate: a closed gate reads the
// schema on each probe, exactly as it did before it first opened. See
// [schemaVersionGate.ready].
//
// The counters are atomics rather than a mutex because this is called from the
// path of every query. A success storing zero concurrently with a failure
// adding one can land in either order, and that is acceptable for a threshold
// whose whole purpose is to ignore isolated failures: the next observation
// corrects it, and observations are not scarce.
type databaseReachability struct {
	// failures is the current streak of statements that never reached a
	// server. Any statement that did reach one resets it.
	failures atomic.Int64
	// lastErr is the most recent transport failure, kept so the probe's body
	// can say what happened. A pod stuck out of its Service with no reason in
	// `kubectl describe` is an outage an operator has to guess at.
	lastErr atomic.Pointer[string]
}

// observe records one outcome. It must not block: see [store.Reachability].
func (r *databaseReachability) observe(o store.Reachability) {
	if o.Reached {
		r.failures.Store(0)
		return
	}
	r.failures.Add(1)
	if o.Err != nil {
		msg := o.Err.Error()
		r.lastErr.Store(&msg)
	}
}

// reached records that the database answered. It is what the readiness probe's
// own successful read reports, so a gate that reopens does not leave a stale
// streak behind it.
func (r *databaseReachability) reached() { r.failures.Store(0) }

// lost reports whether the streak has crossed [unreachableStreak], and what the
// last transport failure said.
func (r *databaseReachability) lost() (bool, string) {
	if r.failures.Load() < unreachableStreak {
		return false, ""
	}
	if msg := r.lastErr.Load(); msg != nil {
		return true, *msg
	}
	return true, "no error recorded"
}

// schemaVersionGate reports whether the database has reached the schema this binary's
// queries are written against.
type schemaVersionGate struct {
	store *store.Store
	// want is the version this binary's embedded migrations reach, read once at
	// assembly. It cannot change while the process runs.
	want uint
	// open latches, and closes again only on observed unreachability. See
	// [schemaVersionGate.ready].
	open atomic.Bool
	// reach is what the process has noticed about the database while serving.
	// It is never nil in an assembled process; a gate built without one — the
	// unit tests that are only about the schema — behaves exactly as the
	// latching gate did.
	reach  *databaseReachability
	logger *slog.Logger
	// logged keeps the "waiting for schema" line to one per process. A probe
	// every few seconds against a stalled rollout would otherwise write the
	// same sentence into the log until someone noticed it, which is how the
	// line that says what is wrong gets scrolled away by itself.
	logged atomic.Bool
	// reclosed records that this gate has been open and closed again, so the
	// return to service is logged once rather than on every probe. An operator
	// reading an incident back wants both edges and neither repeated.
	reclosed atomic.Bool
}

func newSchemaVersionGate(
	s *store.Store, reach *databaseReachability, logger *slog.Logger,
) (*schemaVersionGate, error) {
	want, err := store.LatestSchemaVersion()
	if err != nil {
		return nil, fmt.Errorf("runtime: readiness gate: %w", err)
	}
	if reach == nil {
		reach = &databaseReachability{}
	}
	return &schemaVersionGate{store: s, want: want, reach: reach, logger: logger}, nil
}

// ready answers [api.Config.Ready].
//
// It latches on the schema: once the schema has arrived the gate stops asking,
// and a later probe on a healthy process is answered without touching the
// database. The question it exists to ask — "has this rollout's migration
// landed yet?" — is answered once and stays answered, and a probe every few
// seconds per pod per surface is not something to spend a query on for the rest
// of the process's life.
//
// The cost of latching on the schema is that a schema rolled *backwards* under
// a running pod leaves the pod ready and failing. That is deliberate. A down
// migration is a manual act that already requires putting the old image back,
// and a gate that reopened on it would pull every pod in the fleet out of
// service during exactly the incident where an operator is trying to work —
// trading a subset of requests failing for all of them failing.
//
// The latch is not a latch on *reachability*, and that distinction is the
// correction this file carries. A gate that latched on both answered `200
// ready` from a pod whose database was entirely gone, which meant Kubernetes
// kept routing to a pod that could not serve anything. So an open gate closes
// again when this process has observed [unreachableStreak] statements failing
// to reach the server with none succeeding in between — the failures it saw
// while serving requests, not failures it went looking for. See
// [databaseReachability] for why that evidence and no polling.
//
// Once closed, the gate reads the schema on each probe, exactly as it does
// before it has ever opened. That is deliberate and it is the only query this
// change adds: a pod out of its Service receives no traffic, so there is
// nothing left for it to notice the database's return *with*, and a gate that
// went unready and never came back would be an outage of its own rather than a
// fix for one. The query is bounded by the state it happens in — a closed gate
// is either a pod that has never served or one that has already watched its
// database fail, and in both cases the probe is the only thing that can tell
// it otherwise. A healthy process still issues nothing, which is the property
// that kept the latch worth having; that is pinned by
// TestTheSchemaGateStopsAskingOnceTheSchemaHasArrived.
//
// So: a database that cannot be reached is reported unready rather than ready,
// and — the part that was not true before — it stays that way for as long as
// this process keeps failing to reach it, and stops the probe after the one
// that reaches it again. Both directions are measured in
// TestTheSurfacesAnswerWhenTheDatabaseIsGone's readiness and recovery subtests.
// /healthz is deliberately untouched by all of this: liveness asks whether the
// process is wedged, and restarting a pod because its database went away turns
// one outage into two.
//
// What this still does not do is notice a database that is reachable and
// answering errors — a wrong schema after a manual down migration, a disk that
// has filled, a role whose grants were revoked. Those are server answers, the
// gate stays open through them, and the surfaces report them as failures rather
// than the pod removing itself. That is a judgment about which failures are
// worth emptying a Service over and not an oversight; the reasoning is at
// [unreachableStreak] and the consequence is written down in
// docs/operations/failure-modes.md.
func (g *schemaVersionGate) ready(ctx context.Context) error {
	if g.open.Load() {
		lost, why := g.reach.lost()
		if !lost {
			return nil
		}
		if g.open.CompareAndSwap(true, false) && g.logger != nil {
			// Logged on the transition rather than on every probe: the
			// interesting fact is that this pod left its Service, and the same
			// sentence every five seconds for the length of an outage is how
			// the one that says when it started gets scrolled away.
			g.reclosed.Store(true)
			g.logger.Warn("taking this process out of service: the database has stopped answering",
				slog.Int64("consecutive_transport_failures", g.reach.failures.Load()),
				slog.String("last_error", why))
		}
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
	// This read reached the server and got an answer, which is the same
	// evidence the tracer feeds back through [databaseReachability.observe].
	// Clearing the streak here says so directly, so that reopening does not
	// depend on the order two independent observations happened to land in.
	g.reach.reached()
	g.open.Store(true)
	if g.reclosed.CompareAndSwap(true, false) && g.logger != nil {
		g.logger.Info("returning this process to service: the database is answering again",
			slog.Uint64("schema_version", uint64(version)))
	}
	return nil
}
