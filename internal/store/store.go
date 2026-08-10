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
}

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
