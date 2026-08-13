package store_test

// bootrace_test.go guards the boot-race fix deterministically.
//
// The first attempt at this round guarded it with the concurrent-boot test and a
// peak-concurrency assertion, and code review showed that guard was empty: every
// boot that loses the migration lock sits inside Migrate polling for up to 90
// seconds, so "more than one boot was inside Migrate at once" is true on
// essentially every run — including all 143 green runs of the *unfixed* code.
// The assertion could not fail for the reason it was written for.
//
// Worse, the mutation audit had already said so without the implication being
// drawn: removing the advisory lock on its own left the whole suite green,
// because the widened isDuplicateObject absorbed the error the missing lock let
// through. Only a paired mutation went red, at one run in a hundred and thirty.
// A refactor deleting the lock as redundant would have landed green.
//
// The two tests here replace luck with sequencing. Neither races: one holds the
// key and observes that the create waits, the other holds an uncommitted create
// and observes that the wait ends in tolerance. Both fail immediately and every
// time on the mutations they exist to catch.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/d0lim/stamp/internal/store"
)

// TestVersionTableCreateWaitsForTheAdvisoryLock is the guard the advisory lock
// did not have.
//
// A second session holds the key; the create must not proceed. Deleting the
// `SELECT pg_advisory_xact_lock(...)` line makes this fail on the first run,
// with no scheduling luck involved — which is the whole point, because the
// mutation audit measured the concurrent-boot test detecting that same deletion
// roughly once in a hundred and thirty runs.
func TestVersionTableCreateWaitsForTheAdvisoryLock(t *testing.T) {
	ctx := context.Background()
	dsn := freshDB(t)

	holder, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect holder: %v", err)
	}
	t.Cleanup(holder.Close)
	// A session-scoped lock on a dedicated connection: it is released by
	// Unlock below, not by any transaction boundary.
	held, err := holder.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire holder connection: %v", err)
	}
	defer held.Release()
	if _, err := held.Exec(ctx, `SELECT pg_advisory_lock($1)`, store.VersionTableLockKeyForTest); err != nil {
		t.Fatalf("hold the version-table key: %v", err)
	}

	booting, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect booter: %v", err)
	}
	t.Cleanup(booting.Close)

	// Short next to the lock_timeout the create sets, so this deadline is what
	// ends the wait and the failure is unambiguous.
	blocked, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = store.EnsureVersionTableForTest(blocked, booting)
	if err == nil {
		t.Fatal("the create completed while another session held the version-table lock: " +
			"the advisory lock is not being taken, so two booting replicas can race on the create again")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked create = %v, want a deadline while waiting for the lock", err)
	}

	// And it is genuinely the lock: released, the same call succeeds.
	if _, err := held.Exec(ctx, `SELECT pg_advisory_unlock($1)`, store.VersionTableLockKeyForTest); err != nil {
		t.Fatalf("release the version-table key: %v", err)
	}
	if _, err := store.EnsureVersionTableForTest(ctx, booting); err != nil {
		t.Fatalf("create after the lock was released: %v", err)
	}
}

// TestVersionTableToleratesAPeerThatDidNotTakeTheLock drives the branch the head
// commit exists for.
//
// It reproduces the rolling upgrade: a process on the previous build creates the
// table without taking the lock. This one takes the lock, finds its create
// blocked behind that uncommitted peer, and must come back reporting success
// once the peer commits — not the ErrTxCommitRollback that committing an aborted
// transaction would produce.
//
// The ordering is enforced, not hoped for: the peer's create is held open until
// this test observes the booting session waiting on it.
func TestVersionTableToleratesAPeerThatDidNotTakeTheLock(t *testing.T) {
	ctx := context.Background()
	dsn := freshDB(t)

	peer, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect peer: %v", err)
	}
	t.Cleanup(peer.Close)
	peerTx, err := peer.Begin(ctx)
	if err != nil {
		t.Fatalf("peer begin: %v", err)
	}
	defer func() { _ = peerTx.Rollback(ctx) }()
	// Deliberately no advisory lock — this is what the previous build does.
	if _, err := peerTx.Exec(ctx, `CREATE TABLE schema_migrations (
		version bigint NOT NULL PRIMARY KEY,
		dirty   boolean NOT NULL
	)`); err != nil {
		t.Fatalf("peer create: %v", err)
	}

	booting, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect booter: %v", err)
	}
	t.Cleanup(booting.Close)

	type result struct {
		tolerated bool
		err       error
	}
	done := make(chan result, 1)
	go func() {
		tolerated, err := store.EnsureVersionTableForTest(ctx, booting)
		done <- result{tolerated, err}
	}()

	waitUntilBlockedOnALock(t, peer, ctx)

	if err := peerTx.Commit(ctx); err != nil {
		t.Fatalf("peer commit: %v", err)
	}

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("a boot that lost the create to an unlocked peer failed: %v", got.err)
		}
		if !got.tolerated {
			t.Error("the peer's create was not observed as a tolerated duplicate: " +
				"this test no longer exercises the branch it exists for")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the booting session never returned after the peer committed")
	}
}

// waitUntilBlockedOnALock blocks until some backend on this database is waiting
// on a lock, so the peer commits only once the booting session is actually
// behind it. Polling the catalogue is what makes the ordering observed rather
// than assumed — a sleep here would make the test pass on the wrong interleaving
// without saying so.
func waitUntilBlockedOnALock(t *testing.T, pool *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var waiting int
		err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting)
		if err != nil {
			t.Fatalf("read pg_stat_activity: %v", err)
		}
		if waiting > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no session ever blocked on a lock: the booting create did not queue behind the peer")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
