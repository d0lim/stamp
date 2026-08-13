package store

// export_test.go opens the migration driver's construction to the external test
// package.
//
// The boot race lives inside newPgxMigrationDriver, and the two things worth
// proving about it — that the create waits on the advisory lock, and that a
// peer's create is tolerated rather than turned into a failed boot — cannot be
// reached through Store.Migrate deterministically: Migrate serialises every
// caller on the migration lock afterwards, so a test driving it observes
// queueing, not the create.
//
// These hooks compile only into the test binary. The alternative was a
// concurrency test that watches Migrate from the outside and infers the race
// from wall-clock overlap, which is what the first attempt at this round did —
// and that assertion turned out to be satisfied on every run, including every
// run of the unfixed code. Reaching the real seam is what makes the guards
// deterministic instead of hopeful.

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// VersionTableLockKeyForTest is the advisory key the version-table create takes.
var VersionTableLockKeyForTest = versionTableLockKey

// EnsureVersionTableForTest runs exactly what a booting process runs before
// golang-migrate sees the driver, and reports whether a peer's create was
// tolerated on the way.
func EnsureVersionTableForTest(ctx context.Context, pool *pgxpool.Pool) (toleratedDuplicate bool, err error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()

	d := &pgxMigrationDriver{conn: conn, ctx: ctx, lockKey: advisoryKey("stamp:migrations")}
	return d.ensureVersionTable()
}
