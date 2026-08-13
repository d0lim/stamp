package store

// duplicateobject_test.go is the deterministic half of the boot-race guard.
//
// The concurrent-boot test in store_test.go is the end-to-end proof, and it is
// probabilistic: measured against the unfixed code it failed twice in 145 runs,
// so a green run of it was silent about 98.6% of the time. Two earlier rounds
// read that silence as proof and shipped on it.
//
// So the part that can be deterministic is deterministic. Which SQLSTATEs
// isDuplicateObject tolerates is a property of one function and three constants;
// it does not need a race to answer, and answering it by feeding the real
// function real *pgconn.PgError values leaves nothing to luck.
//
// The false cases carry more weight here than the true ones. Widening this
// predicate to the whole 42 class is a one-character-looking change that would
// make a least-privilege deployment read "permission denied" as "it is already
// there" — see isDuplicateObject's comment. TestIsDuplicateObjectRefusesCodes
// exists to fail on that change.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func pgErr(code string) error {
	return &pgconn.PgError{Code: code, Message: "synthetic " + code}
}

// TestIsDuplicateObjectAcceptsEveryConcurrentCreateCode pins the closed set a
// concurrent CREATE TABLE IF NOT EXISTS can raise. Each has a distinct mechanism
// — two pre-checks and one unique index — and which one fires is scheduling
// luck, so all three have to be tolerated or the boot dies on the unlucky one.
func TestIsDuplicateObjectAcceptsEveryConcurrentCreateCode(t *testing.T) {
	for _, tc := range []struct{ code, mechanism string }{
		{"42P07", "duplicate_table: the pg_class pre-check saw a committed peer"},
		{"42710", "duplicate_object: the pg_type pre-check saw one, on the implicit row type"},
		{"23505", "unique_violation: both pre-checks passed and the catalogue index caught the insert"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			if !isDuplicateObject(pgErr(tc.code)) {
				t.Errorf("isDuplicateObject(%s) = false, want true — %s", tc.code, tc.mechanism)
			}
		})
	}
}

// TestIsDuplicateObjectRefusesCodes is the half that guards the guard.
//
// 42501 is the one that matters: it sits in the same SQLSTATE class as two of
// the codes above, so any attempt to simplify this predicate into a class match
// silently converts a privilege denial into "the object already exists" and
// boots a pod that never confirmed it may create anything. grants.sql promises
// the opposite for the sibling role-creation race.
func TestIsDuplicateObjectRefusesCodes(t *testing.T) {
	for _, tc := range []struct{ code, why string }{
		{"42501", "insufficient_privilege — class 42, but a permissions failure must fail the boot loudly"},
		{"42601", "syntax_error — class 42, and a broken statement is not a duplicate"},
		{"42P01", "undefined_table — class 42, and a missing relation is not a duplicate"},
		{"23503", "foreign_key_violation — class 23, a real defect that must not be retried"},
		{"23514", "check_violation — class 23, likewise"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			if isDuplicateObject(pgErr(tc.code)) {
				t.Errorf("isDuplicateObject(%s) = true, want false — %s", tc.code, tc.why)
			}
		})
	}
}

func TestIsDuplicateObjectRefusesNonPostgresErrors(t *testing.T) {
	if isDuplicateObject(errors.New("connection reset")) {
		t.Error("isDuplicateObject reported a plain error as a duplicate")
	}
	if isDuplicateObject(nil) {
		t.Error("isDuplicateObject reported nil as a duplicate")
	}
}

// TestIsDuplicateObjectSeesThroughWrapping is separate from the refusal test
// because it is a positive case: bundling it there made a failed unwrap report
// itself as "refuses non-Postgres errors", which names the wrong defect.
//
// It matters because nothing guarantees the error arrives bare — ensureVersionTable
// passes on what pgx returns, and any layer between here and the wire may wrap it.
func TestIsDuplicateObjectSeesThroughWrapping(t *testing.T) {
	if !isDuplicateObject(fmt.Errorf("exec create: %w", pgErr("42710"))) {
		t.Error("isDuplicateObject did not unwrap a wrapped PgError")
	}
}

// TestVersionTableLockIsNotTheMigrationLock pins the separation the two keys
// depend on. Collapsing them would make every boot wait out a peer's entire
// migration run to execute a create that finds the table already there, and
// would put two acquisitions of one key on a single boot path.
func TestVersionTableLockIsNotTheMigrationLock(t *testing.T) {
	if versionTableLockKey == advisoryKey("stamp:migrations") {
		t.Error("the version-table lock and the migration lock share a key")
	}
	if versionTableLockKey == grantsLockKey {
		t.Error("the version-table lock and the grants lock share a key")
	}
}
