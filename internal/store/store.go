// Package store is STAMP's Postgres persistence layer: the schema, the storage
// API for policies, decisions, challenge progress, approvals, aggregation
// buckets and the dedup index, and the tamper-evident audit log those writes
// are recorded in.
//
// Postgres is the only operational dependency, so everything that would
// otherwise want a second system lives here — expiry timers are a column plus a
// SKIP LOCKED sweeper rather than a job queue, and velocity aggregation is
// fixed-width bucket rows rather than a stream processor.
//
// Three shapes in this package are load-bearing and are not free to change
// without changing what the system guarantees.
//
// The audit log is a set of per-writer hash chains, not one global chain. Each
// row carries (writer_id, seq, prev_hash) and an append only ever reads and
// extends its own segment, so appends from different instances never contend.
// Periodic checkpoints name every writer's head at a moment and are signed with
// a key the database does not hold, which is what cross-links the segments and
// what makes a wholesale re-chaining of the table detectable. The price of the
// split is that a writer_id must be owned by exactly one process: two claimants
// collide on the primary key, and that is a correctness failure, so acquisition
// is an exclusive claim at startup that fails the boot rather than retrying.
//
// A decision has two deadline columns. expires_at is the decision's own
// deadline and the only one an entry-time check reads. next_deadline is the
// scheduler's column, holding min(expires_at, unmet challenge timers) with a
// next_deadline_kind discriminator. Collapsing them would make a decision read
// as expired the moment a delay timer landed in the column.
//
// The dedup index is keyed on (caller_id, event_id, metric). The caller has to
// be in the key or one caller can burn another's identifiers by claiming them
// first.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Errors the storage API returns as sentinels, so callers can branch on the
// condition rather than on message text.
var (
	// ErrNotFound is returned when a lookup by identifier matches no row.
	ErrNotFound = errors.New("store: not found")

	// ErrConflict is returned when a write loses a uniqueness race that the
	// caller is expected to handle — a duplicate approval, a second live
	// version of the same policy.
	ErrConflict = errors.New("store: conflict")

	// ErrWriterTaken is returned when an audit writer identifier is already
	// held by a live process. It is deliberately not retryable: see
	// ClaimWriter.
	ErrWriterTaken = errors.New("store: audit writer id already claimed")

	// ErrChainBroken reports that the audit chain failed verification.
	ErrChainBroken = errors.New("store: audit chain verification failed")
)

// Config configures a Store.
type Config struct {
	// DSN is the Postgres connection string.
	DSN string

	// MaxConns bounds the pool. Zero uses pgxpool's default.
	MaxConns int32

	// Roles names the database roles the grants file provisions. The zero
	// value uses DefaultRoleNames.
	Roles RoleNames

	// Now is the clock, injectable so that deadline behaviour is testable
	// without sleeping. Nil means time.Now.
	Now func() time.Time

	// OnReachability, if set, is told the outcome of every statement this
	// process issues and every connection it opens. See [Reachability]. Nil —
	// which is every caller that has no use for it — installs no tracer at
	// all, so the pool is exactly the pool it was.
	OnReachability func(Reachability)
}

// Reachability is what one attempted statement said about whether Postgres is
// there at all. It is deliberately not "did the statement succeed": a server
// that answers 42703, 23505 or a statement timeout is a reachable server, and a
// caller that treated those as an outage would report one every time a
// constraint did its job.
//
// It exists so that a process can learn its database is gone from the work it
// was already doing. The alternative — a health check on a timer — issues
// queries at exactly the moment the database is least able to answer them, and
// a probe that adds load to a struggling database trades one outage for
// another. Nothing here issues a query; it reports on the ones that were going
// to happen anyway.
type Reachability struct {
	// Reached is true when Postgres answered — with rows, with a command tag,
	// or with an error of its own. It is false only when the statement never
	// got to a server: a connection that could not be made, one that was reset
	// mid-statement, a read that hit EOF.
	Reached bool

	// Err is the transport failure, when Reached is false. It is carried so a
	// reader of the resulting state can say what happened rather than only
	// that something did.
	Err error
}

// reachabilityTracer reports [Reachability] from pgx's own tracing hooks.
//
// Tracing is the only place in this package that sees every statement without
// wrapping every call site. The pool's accessors are spread over eight files
// and a dozen types, several of which take a [Querier] that may be a
// transaction the caller owns; instrumenting them one at a time would be a
// change with no natural end and a new way to be wrong every time a query is
// added.
//
// The hooks are on the path of every query, so the reporting side of this must
// be cheap and non-blocking. That contract is stated on [Config.OnReachability]
// rather than enforced here, for the same reason a mutex is not taken here:
// this is the check path.
type reachabilityTracer struct {
	report func(Reachability)
}

func (t reachabilityTracer) TraceQueryStart(
	ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData,
) context.Context {
	return ctx
}

func (t reachabilityTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	t.observe(ctx, data.Err)
}

func (t reachabilityTracer) TraceConnectStart(
	ctx context.Context, _ pgx.TraceConnectStartData,
) context.Context {
	return ctx
}

func (t reachabilityTracer) TraceConnectEnd(ctx context.Context, data pgx.TraceConnectEndData) {
	t.observe(ctx, data.Err)
}

// observe classifies one outcome. The classification is the whole of this
// type's judgment, so the cases are spelled out rather than folded together.
func (t reachabilityTracer) observe(ctx context.Context, err error) {
	var pgErr *pgconn.PgError
	switch {
	case err == nil:
		t.report(Reachability{Reached: true})
	case errors.As(err, &pgErr):
		// The server composed an error message and sent it. Whatever else is
		// wrong, the database is there.
		t.report(Reachability{Reached: true})
	case ctx.Err() != nil:
		// The caller's own deadline or cancellation ended this, and what the
		// server would have done is unknown. Saying nothing is the honest
		// answer, and it is also the safe one: a request budget that expires
		// under load must not read as an unreachable database.
	default:
		t.report(Reachability{Err: err})
	}
}

var (
	_ pgx.QueryTracer   = reachabilityTracer{}
	_ pgx.ConnectTracer = reachabilityTracer{}
)

// RoleNames are the database role names the per-role grants are written
// against. They are configurable because roles are cluster-global: a cluster
// that already has a role named stamp_check must not have it quietly co-opted.
type RoleNames struct {
	Check    string
	Decide   string
	Consumer string
	Admin    string
}

// DefaultRoleNames returns the role names a deployment gets when it configures
// none.
func DefaultRoleNames() RoleNames {
	return RoleNames{
		Check:    "stamp_check",
		Decide:   "stamp_decide",
		Consumer: "stamp_consumer",
		Admin:    "stamp_admin",
	}
}

func (r RoleNames) withDefaults() RoleNames {
	d := DefaultRoleNames()
	if r.Check == "" {
		r.Check = d.Check
	}
	if r.Decide == "" {
		r.Decide = d.Decide
	}
	if r.Consumer == "" {
		r.Consumer = d.Consumer
	}
	if r.Admin == "" {
		r.Admin = d.Admin
	}
	return r
}

// Store is the handle on the database. It owns a connection pool and hands out
// the per-concern accessors the rest of the system uses.
type Store struct {
	pool  *pgxpool.Pool
	roles RoleNames
	now   func() time.Time
}

// Open connects to Postgres and verifies the connection. It does not migrate;
// call Migrate for that.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	if cfg.MaxConns > 0 {
		poolCfg.MaxConns = cfg.MaxConns
	}
	if cfg.OnReachability != nil {
		// The tracer is installed on the connection config, so it covers every
		// connection the pool makes and every statement issued over one —
		// including the statements a caller's own transaction issues, which is
		// the half a wrapper around this package's accessors would miss.
		poolCfg.ConnConfig.Tracer = reachabilityTracer{report: cfg.OnReachability}
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, roles: cfg.Roles.withDefaults(), now: now}, nil
}

// Close releases the pool.
func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// Pool exposes the underlying pool. Units that need a query this package does
// not wrap use it; it is not an invitation to bypass the storage API for writes
// that must be audited.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Now reports the store's clock.
func (s *Store) Now() time.Time { return s.now().UTC() }

// InTx runs fn inside a transaction, committing on success and rolling back on
// error or panic.
func (s *Store) InTx(ctx context.Context, fn func(ctx context.Context, tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	committed = true
	return nil
}

// Querier is the subset of pgx both a pool and a transaction satisfy, so every
// read in this package can be called either standalone or inside a caller's
// transaction. Storing a decision has to put the policy version, the fact
// snapshot and the audit row in one transaction, and that is only expressible
// if the individual writes accept a transaction.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}
