package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

//go:embed grants.sql
var grantsTemplate string

// migrationsTableName is where golang-migrate keeps the applied version. It is
// named explicitly rather than left to the driver default so that a future
// driver swap cannot quietly start a new history.
const migrationsTableName = "schema_migrations"

// Migrate brings the database up to the latest schema version and then applies
// the per-role grants.
//
// Grants are applied after every migration rather than as a numbered migration
// of their own. Roles are cluster-global while migrations are per-database, and
// the role names are deployment configuration, so the grants have to be
// templated at apply time — which a static migration file cannot be. Applying
// them on every Migrate also means a privilege added to a new table is never
// one release behind the table.
func (s *Store) Migrate(ctx context.Context) error {
	m, err := s.migrator(ctx)
	if err != nil {
		return err
	}
	defer closeMigrator(m)

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("store: migrate up: %w", err)
	}
	return s.ApplyGrants(ctx)
}

// MigrateDown rolls back n migration steps. n must be positive.
func (s *Store) MigrateDown(ctx context.Context, n int) error {
	if n <= 0 {
		return fmt.Errorf("store: migrate down: steps must be positive, got %d", n)
	}
	m, err := s.migrator(ctx)
	if err != nil {
		return err
	}
	defer closeMigrator(m)

	if err := m.Steps(-n); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("store: migrate down %d: %w", n, err)
	}
	return nil
}

// SchemaVersion reports the applied migration version and whether a previous
// migration left the schema dirty. ok is false when nothing has been applied.
func (s *Store) SchemaVersion(ctx context.Context) (version uint, dirty bool, ok bool, err error) {
	m, merr := s.migrator(ctx)
	if merr != nil {
		return 0, false, false, merr
	}
	defer closeMigrator(m)

	v, d, verr := m.Version()
	if errors.Is(verr, migrate.ErrNilVersion) {
		return 0, false, false, nil
	}
	if verr != nil {
		return 0, false, false, fmt.Errorf("store: schema version: %w", verr)
	}
	return v, d, true, nil
}

// LatestSchemaVersion is the version this binary's embedded migrations reach —
// the schema every query in this package is written against.
//
// It is derived from the embedded files rather than written down as a constant,
// because a constant is a second place to update and the one nobody updates. A
// migration added to the directory moves this number by existing, which is what
// makes [Store.SchemaBehind] a claim about *this* binary rather than about
// whatever number someone last remembered to bump.
//
// The error is a build-time mistake surfacing at run time: the embedded
// directory is compile-time content, so a file whose name does not start with a
// version means the migration set itself is malformed. Callers treat it as fatal
// rather than degrading, because a process that cannot say which schema it needs
// cannot decide whether it may serve traffic.
func LatestSchemaVersion() (uint, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return 0, fmt.Errorf("store: read embedded migrations: %w", err)
	}
	var latest uint
	var found bool
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		digits := name
		if i := strings.IndexFunc(name, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
			digits = name[:i]
		}
		if digits == "" {
			return 0, fmt.Errorf("store: migration %q does not begin with a version", name)
		}
		var v uint64
		if _, err := fmt.Sscanf(digits, "%d", &v); err != nil {
			return 0, fmt.Errorf("store: migration %q has an unreadable version: %w", name, err)
		}
		found = true
		if uint(v) > latest {
			latest = uint(v)
		}
	}
	if !found {
		return 0, errors.New("store: no embedded migrations found")
	}
	return latest, nil
}

// SchemaBehind reports how far the database is behind what this binary needs: it
// returns the version the database is actually at, and whether that version is
// good enough to serve on.
//
// This is the question a process that does *not* migrate has to answer before it
// takes traffic. Only one tier migrates (the chart's `api` role), and `helm
// upgrade` rolls every Deployment at once with nothing sequencing them, so a
// decide pod on the new image can reach a database still on the old schema and
// answer every request with `42703 column ... does not exist`. Asked here and
// wired into readiness, that outage becomes a pod that stays out of its Service
// until the migrating tier catches up — a slower rollout instead of a broken one.
//
// A dirty schema is never good enough, whatever the version says. golang-migrate
// records the version it was attempting when a migration failed, so a dirty 9 is
// not "at 9", it is "9 did not finish" — and which half of 9 landed is exactly
// what nobody can tell from the number.
//
// Ahead is fine and deliberate: a database migrated past this binary is the
// normal state during the first half of a rollout, when the new api pods have
// already migrated and old-image pods are still serving. Those old pods'
// statements are a subset of the new columns, so they keep working; refusing to
// serve on a schema newer than expected would take the fleet down on precisely
// the upgrade this gate exists to make safe.
func (s *Store) SchemaBehind(ctx context.Context, want uint) (version uint, dirty bool, ready bool, err error) {
	version, dirty, ok, err := s.AppliedSchemaVersion(ctx)
	if err != nil {
		return 0, false, false, err
	}
	if !ok || dirty {
		return version, dirty, false, nil
	}
	return version, false, version >= want, nil
}

// AppliedSchemaVersion reads the applied version straight out of the version
// table. ok is false when no migration has ever been applied — including when
// the table does not exist yet.
//
// [Store.SchemaVersion] answers the same question and cannot be used here.
// Building a migrator acquires a dedicated pooled connection for the life of the
// call and runs `CREATE TABLE IF NOT EXISTS schema_migrations` — inside a
// transaction holding an advisory lock every other booting replica contends for
// — before it reads anything, which is both far more than a readiness probe
// every few seconds should cost and more privilege than a non-migrating tier's
// login is given: R39's grants hand the decide role SELECT and nothing that
// creates objects. A probe that needed DDL rights to answer "may I serve?"
// would fail closed on exactly the least-privilege deployments this project
// asks operators to run.
//
// A missing table is reported as "nothing applied" rather than as an error for
// the same reason SchemaVersion reports a missing row that way: a database
// nobody has migrated is a state a readiness gate must be able to describe, not
// one it should crash on.
func (s *Store) AppliedSchemaVersion(ctx context.Context) (version uint, dirty bool, ok bool, err error) {
	var v int64
	var d bool
	err = s.pool.QueryRow(ctx,
		`SELECT version, dirty FROM `+migrationsTableName+` LIMIT 1`).Scan(&v, &d)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, false, false, nil
	case isUndefinedTable(err):
		return 0, false, false, nil
	case err != nil:
		return 0, false, false, fmt.Errorf("store: read applied schema version: %w", err)
	}
	if v < 0 {
		// golang-migrate's NilVersion never reaches the table — SetVersion
		// deletes the row instead — but a hand-edited table could hold one, and
		// a negative version widened into uint would read as astronomically
		// ahead of the binary and open the gate.
		return 0, d, false, nil
	}
	return uint(v), d, true, nil
}

// isUndefinedTable reports whether err is Postgres saying the relation is not
// there (42P01).
func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}

// How long a booting process waits for another process's migration before it
// gives up, and how often it asks.
//
// The budget is generous on purpose. What it is waiting for is one peer's
// migrations to finish, and a boot that waits a minute is a slower rollout,
// while a boot that gives up early is a crashloop. The poll interval is short
// because the common case is a peer that is already nearly done.
const (
	migrationLockWait = 90 * time.Second
	migrationLockPoll = 100 * time.Millisecond
)

// migrationLockTimeout is golang-migrate's own ceiling on a Driver.Lock call. It
// is set above migrationLockWait deliberately, and the ordering is load-bearing
// rather than cosmetic: the library abandons a Lock that outruns this timeout
// and lets the caller close the migrator, which releases the pooled connection
// the abandoned call is still using. Keeping the driver's own deadline strictly
// shorter means that never happens. The library's default is 15s, which is
// under our wait and would have made this the normal path.
const migrationLockTimeout = migrationLockWait + 30*time.Second

func (s *Store) migrator(ctx context.Context) (*migrate.Migrate, error) {
	src, err := iofs.New(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: read embedded migrations: %w", err)
	}
	drv, err := newPgxMigrationDriver(ctx, s.pool)
	if err != nil {
		return nil, err
	}
	m, err := migrate.NewWithInstance("iofs", src, "pgx", drv)
	if err != nil {
		return nil, fmt.Errorf("store: build migrator: %w", err)
	}
	m.LockTimeout = migrationLockTimeout
	return m, nil
}

func closeMigrator(m *migrate.Migrate) {
	// Close returns the source and database close errors. The database side is
	// the pooled connection this package owns and releases anyway, and there is
	// nothing a caller could do about a failure to release it, so it is not
	// propagated.
	_, _ = m.Close()
}

// roleNamePattern is the syntax a configurable role name must match. Role names
// are substituted into SQL text, so this is the injection guard rather than a
// style rule: a name that does not match is rejected instead of quoted, because
// there is no legitimate role name that needs quoting.
var roleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// grantsLockKey serialises concurrent applies of the grants file. It is a
// different key from the migration lock on purpose: the two are taken by the
// same process one after the other, and sharing a key would make Migrate's own
// call to ApplyGrants wait on a lock it had just released for no reason.
var grantsLockKey = advisoryKey("stamp:grants")

// ApplyGrants provisions the per-role database roles and their privileges.
//
// The roles are created without LOGIN and without a password: they are
// privilege templates that a deployment grants to the login roles it already
// manages. Credentials never ship in a file embedded in the binary.
//
// This is safe to run concurrently with an identical apply, which it has to be:
// it runs at pod boot (see internal/runtime/wiring.go), Kubernetes rolls a
// Deployment's replicas together, and `helm upgrade` rolls every tier at once
// with nothing sequencing them. Two boots landing in the same millisecond is the
// normal case on a rollout, not a pathological one. It is also run twice by one
// process whenever both migrate and applyGrants are enabled, since Migrate ends
// by calling it, so it has to be repeatable as well as concurrent.
//
// The apply is wrapped in a transaction holding a transaction-scoped advisory
// lock. Three reasons for that shape:
//
// The file is not just role creation. It REVOKEs everything from the four roles
// and re-GRANTs the current set, so two uncoordinated applies interleave
// catalogue updates on the same pg_class rows — which Postgres answers with
// `tuple concurrently updated` rather than by merging. Serialising the whole
// file is the fix; serialising only the CREATE ROLE would leave that.
//
// The lock is transaction-scoped rather than session-scoped, unlike
// pgxMigrationDriver.Lock. That driver has no choice: golang-migrate's interface
// hands it Lock and Unlock as separate calls spanning many statements, so it has
// to hold the lock across them and carry the risk that a pooled connection is
// returned still holding it. Here the entire apply is one transaction, so
// pg_advisory_xact_lock releases at commit or rollback with no bookkeeping and
// no way to leak a held lock back into the pool.
//
// It is the blocking pg_advisory_xact_lock and not pg_try_advisory_xact_lock,
// because the desired outcome is that both boots succeed. A try-lock would make
// the loser choose between failing (the bug this fixes) and skipping the apply
// (worse: a pod would proceed believing privileges it never confirmed). Waiting
// costs one apply's duration and is bounded by the caller's context.
//
// What the lock cannot cover is role creation itself — advisory locks are
// per-database and roles are cluster-global — so grants.sql tolerates the
// duplicate-role error separately. See the comment there.
func (s *Store) ApplyGrants(ctx context.Context) error {
	roles := s.roles.withDefaults()
	seen := map[string]struct{}{}
	for label, name := range map[string]string{
		"check": roles.Check, "decide": roles.Decide,
		"consumer": roles.Consumer, "admin": roles.Admin,
	} {
		if !roleNamePattern.MatchString(name) {
			return fmt.Errorf("store: %s role name %q is not a plain lowercase SQL identifier", label, name)
		}
		if _, dup := seen[name]; dup {
			return fmt.Errorf("store: role name %q is used for more than one role: the roles would share privileges", name)
		}
		seen[name] = struct{}{}
	}

	tmpl, err := template.New("grants").Parse(grantsTemplate)
	if err != nil {
		return fmt.Errorf("store: parse grants template: %w", err)
	}
	var sql strings.Builder
	if err := tmpl.Execute(&sql, roles); err != nil {
		return fmt.Errorf("store: render grants: %w", err)
	}
	return s.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, grantsLockKey); err != nil {
			return fmt.Errorf("store: lock grants: %w", err)
		}
		// One Exec for the whole file. pgx sends a statement without arguments
		// over the simple protocol, which is what allows the multi-statement
		// body at all — and the grants have to arrive together, or a REVOKE
		// could commit without the GRANT that restores what it took away.
		if _, err := tx.Exec(ctx, sql.String()); err != nil {
			return fmt.Errorf("store: apply grants: %w", err)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// golang-migrate driver over pgx
// ---------------------------------------------------------------------------

// pgxMigrationDriver implements golang-migrate's database.Driver on top of the
// pgx pool this package already owns.
//
// golang-migrate ships a pgx/v5 driver, but it pulls a module that is not in
// this repository's pinned manifest, and the landing strategy fixes every M1
// dependency in the scaffold unit so sibling branches never edit go.sum. The
// engine — version bookkeeping, step direction, the dirty flag — still comes
// from the library; only the four database operations are local.
type pgxMigrationDriver struct {
	conn     *pgxpool.Conn
	ctx      context.Context //nolint:containedctx // database.Driver's methods take no context
	lockKey  int64
	isLocked bool
}

var _ database.Driver = (*pgxMigrationDriver)(nil)

func newPgxMigrationDriver(ctx context.Context, pool *pgxpool.Pool) (*pgxMigrationDriver, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: acquire migration connection: %w", err)
	}
	d := &pgxMigrationDriver{conn: conn, ctx: ctx, lockKey: advisoryKey("stamp:migrations")}
	if _, err := d.ensureVersionTable(); err != nil {
		conn.Release()
		return nil, err
	}
	return d, nil
}

// versionTableLockKey serialises the version-table create against a peer's.
//
// It is deliberately not lockKey. Reusing the migration lock would make every
// boot wait out a peer's entire migration run before executing a create that
// finds the table already there, and then wait again in Lock. This key is held
// only for the create, so boots serialise against each other's create and
// nothing else.
//
// Nothing ever holds both this and lockKey at once — this one is taken and
// released inside newPgxMigrationDriver, before the driver is handed to
// golang-migrate and long before Lock runs — so the two cannot deadlock.
var versionTableLockKey = advisoryKey("stamp:migrations:version-table")

// ensureVersionTable creates the version table if it is not there.
//
// This runs before the migration lock is taken and it has to. The reason is
// narrower than "golang-migrate calls Lock then Version": Migrate.Version calls
// the driver's Version with no lock at all (golang-migrate v4.19.1
// migrate.go:384 — it and Close are the only two driver calls that bypass
// m.lock), and Store.SchemaVersion goes through exactly that path. A create
// moved inside Lock would leave an unmigrated database answering 42P01 to
// SchemaVersion instead of "nothing applied yet".
//
// So the create stays here, and the lock comes to it. `CREATE TABLE IF NOT
// EXISTS` is not atomic against a concurrent identical create — the existence
// check and the catalogue insert are separate steps, and which of them notices
// the peer decides which error Postgres raises:
//
//	42P07  the pg_class pre-check in heap_create_with_catalog saw a committed peer
//	42710  the pg_type pre-check saw one — every table has an implicit row type
//	23505  both pre-checks passed and pg_type_typname_nsp_index caught the insert
//
// That set is closed for this statement: two pre-checks and one unique index,
// with no fourth place to lose. Which one fires is pure scheduling luck, which
// is why this was fixed twice before and stayed broken — each fix recorded the
// code that incident produced rather than the mechanisms that can produce one.
//
// Under the lock none of them can fire. isDuplicateObject stays as a belt for
// the one window the lock cannot cover: the rolling upgrade that deploys this
// code, where pods still running the previous build create without taking it.
//
// The transaction is opened on d.conn rather than through Store.InTx, which is
// how the rest of this package writes one. InTx is a method on *Store and begins
// on any pooled connection; this driver holds its own connection and has no
// Store to reach, so going through it would mean plumbing one in to acquire a
// second connection for work the driver's own can already do.
//
// The lock is transaction-scoped and blocking for the reasons ApplyGrants gives
// at length above — it releases at commit with no bookkeeping and no way to leak
// a held lock back into the pool, and both boots are meant to succeed. The
// polling try-lock in Lock is not the pattern to copy here: that shape exists
// because golang-migrate abandons an over-budget Driver.Lock goroutine while the
// caller releases the pooled connection underneath it. Nothing abandons this
// call — it is our own code, synchronous, inside the constructor.
// The wait is bounded by lock_timeout rather than left to the boot context,
// which carries no deadline of its own. Advisory locks need no privilege, so any
// session that can connect can hold this key — and an unbounded wait would turn
// that into every replica hanging before it binds a listener, with nothing
// logged. Bounded, the same situation ends in 55P03 wrapped by the message
// below, which is the shape Lock already chose for the migration key. (The
// chart's liveness probe kills a pre-Listen container well before this fires;
// the timeout is what makes the failure nameable when a probe is not watching.)
//
// The lock is transaction-scoped and blocking for the reasons ApplyGrants gives
// at length above — it releases at commit with no bookkeeping and no way to leak
// a held lock back into the pool, and both boots are meant to succeed. The
// polling try-lock in Lock is not the pattern to copy here: that shape exists
// because golang-migrate abandons an over-budget Driver.Lock goroutine while the
// caller releases the pooled connection underneath it. Nothing abandons this
// call — it is our own code, synchronous, inside the constructor.
//
// The bool reports whether a peer's create was tolerated. Only tests read it;
// the constructor discards it. It exists because that branch is otherwise
// unobservable, and a branch nothing can observe is a branch nothing can test —
// which is how this defect survived two rounds.
func (d *pgxMigrationDriver) ensureVersionTable() (toleratedDuplicate bool, err error) {
	const stmt = `CREATE TABLE IF NOT EXISTS ` + migrationsTableName + ` (
		version bigint NOT NULL PRIMARY KEY,
		dirty   boolean NOT NULL
	)`
	tx, err := d.conn.Begin(d.ctx)
	if err != nil {
		return false, fmt.Errorf("store: begin %s create: %w", migrationsTableName, err)
	}
	defer func() { _ = tx.Rollback(d.ctx) }()

	if _, err := tx.Exec(d.ctx, `SET LOCAL lock_timeout = `+quoteLockTimeout(migrationLockWait)); err != nil {
		return false, fmt.Errorf("store: bound %s create wait: %w", migrationsTableName, err)
	}
	if _, err := tx.Exec(d.ctx, `SELECT pg_advisory_xact_lock($1)`, versionTableLockKey); err != nil {
		return false, fmt.Errorf("store: lock %s create: %w", migrationsTableName, err)
	}
	if _, err := tx.Exec(d.ctx, stmt); err != nil {
		if !isDuplicateObject(err) {
			return false, fmt.Errorf("store: create %s: %w", migrationsTableName, err)
		}
		// A peer committed the table between this transaction's lock and its
		// create. Under the lock that cannot happen between two processes
		// running this code, so what is left is the rollout that introduces the
		// lock: pods still on the previous build create without taking it.
		//
		// This branch must never reach Commit. The failed statement put the
		// transaction in an aborted state, and an aborted transaction cannot be
		// committed: Postgres answers COMMIT with a ROLLBACK tag, which pgx
		// surfaces as ErrTxCommitRollback (pgx/v5 tx.go, dbTx.Commit; pinned by
		// TestCommitAfterAFailedStatementReportsRollback). Committing would turn
		// "a peer already made the table" into a failed boot, on exactly the
		// deploy this tolerance exists for.
		// TestVersionTableToleratesAPeerThatDidNotTakeTheLock drives this branch
		// and fails if a Commit is reintroduced anywhere below.
		//
		// The rollback is explicit rather than left to the defer because the
		// next statement has to run on a transaction that is no longer aborted.
		// That statement is the point: a duplicate error is not by itself proof
		// that the relation exists. 42710 comes from the pg_type pre-check, and
		// pg_type holds enums, domains and composites too — a leftover object of
		// this name would satisfy the tolerance forever while no table existed.
		// The code this replaced re-ran the create for exactly this reason
		// ("it verifies rather than assumes"); dropping that check would have
		// traded a named failure here for a confusing 42P01 from Version later.
		_ = tx.Rollback(d.ctx)
		var exists bool
		if verr := d.conn.QueryRow(d.ctx,
			`SELECT to_regclass($1) IS NOT NULL`, migrationsTableName).Scan(&exists); verr != nil {
			return true, fmt.Errorf("store: verify %s after a tolerated duplicate: %w", migrationsTableName, verr)
		}
		if !exists {
			return true, fmt.Errorf(
				"store: %s was reported as already existing but no such relation is present — "+
					"an object of that name that is not a table? (original error: %w)", migrationsTableName, err)
		}
		return true, nil
	}
	if err := tx.Commit(d.ctx); err != nil {
		return false, fmt.Errorf("store: commit %s create: %w", migrationsTableName, err)
	}
	return false, nil
}

// quoteLockTimeout renders d as a SQL string literal for SET LOCAL, which does
// not accept a bind parameter. The value is derived from a constant in this
// file, never from input, and milliseconds are the unit lock_timeout reads when
// given a bare number — the explicit unit here is for the reader.
func quoteLockTimeout(d time.Duration) string {
	return fmt.Sprintf("'%dms'", d.Milliseconds())
}

// isDuplicateObject reports whether err is Postgres refusing to create something
// that is already there.
//
// The three codes are the ones a concurrent `CREATE TABLE IF NOT EXISTS` can
// raise, enumerated by the mechanism that raises each rather than by the ones
// this project has met — ensureVersionTable's comment has the table.
//
// Matching the whole 42 class would be wrong, and dangerously so. Class 42 is
// `syntax_error_or_access_rule_violation`: it holds 42501 insufficient_privilege
// alongside the duplicate codes. A predicate named isDuplicateObject that
// answered true for 42501 would let a least-privilege deployment read "you may
// not create this" as "it is already there" and boot anyway — the exact opposite
// of what grants.sql promises for the sibling role-creation race, where a
// permissions failure still aborts the apply and fails the boot loudly.
func isDuplicateObject(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	switch pgErr.Code {
	case "42P07", // duplicate_table — the pg_class pre-check
		"42710", // duplicate_object — the pg_type pre-check on the row type
		"23505": // unique_violation — pg_type_typname_nsp_index on the insert
		return true
	default:
		return false
	}
}

// Open is part of database.Driver but is only used by the URL-registered path.
// This driver is always constructed with an existing pool.
func (d *pgxMigrationDriver) Open(string) (database.Driver, error) {
	return nil, errors.New("store: migration driver is constructed from an existing pool, not a URL")
}

func (d *pgxMigrationDriver) Close() error {
	if d.conn != nil {
		d.conn.Release()
		d.conn = nil
	}
	return nil
}

// Lock takes a session advisory lock so two processes starting at once do not
// both run the same migration. The lock is session-scoped on a dedicated
// connection, so a process that dies mid-migration releases it when Postgres
// notices the connection is gone — a lock row in a table would not.
//
// It waits for the lock rather than failing on it. A bare pg_try_advisory_lock
// serialises the two boots by killing one of them: golang-migrate calls
// Driver.Lock exactly once and returns whatever it gets, so the loser's Up
// failed with `can't acquire lock` and the process exited. That is the same
// concurrent-boot defect as the grants race, only with a politer error message —
// and it fires on any rollout that starts two replicas together, which is every
// rollout.
//
// The wait is bounded and polled rather than a blocking pg_advisory_lock, for
// one reason that is not stylistic: golang-migrate runs Driver.Lock in its own
// goroutine and abandons it when its LockTimeout fires, while the caller goes on
// to close the migrator and release this pooled connection. A blocked
// pg_advisory_lock would still be holding that connection when it was released
// underneath it. Polling with a deadline this driver owns — kept under the
// library's ceiling by migrationLockTimeout — means Lock always returns before
// anything can be pulled out from under it, and lets d.ctx cancel the wait so a
// boot that is being shut down does not sit here.
func (d *pgxMigrationDriver) Lock() error {
	if d.isLocked {
		return database.ErrLocked
	}
	deadline := time.Now().Add(migrationLockWait)
	for {
		var got bool
		if err := d.conn.QueryRow(d.ctx, `SELECT pg_try_advisory_lock($1)`, d.lockKey).Scan(&got); err != nil {
			return fmt.Errorf("store: migration lock: %w", err)
		}
		if got {
			d.isLocked = true
			return nil
		}
		if time.Now().After(deadline) {
			// Reported as ErrLocked and not as a timeout because that is what it
			// is: something else has held the migration lock for longer than a
			// migration should take, and this process cannot tell a slow peer
			// from a stuck one. Failing the boot is right — proceeding would mean
			// serving on a schema nobody confirmed.
			return database.ErrLocked
		}
		select {
		case <-d.ctx.Done():
			return fmt.Errorf("store: migration lock: %w", d.ctx.Err())
		case <-time.After(migrationLockPoll):
		}
	}
}

func (d *pgxMigrationDriver) Unlock() error {
	if !d.isLocked {
		return database.ErrNotLocked
	}
	if _, err := d.conn.Exec(d.ctx, `SELECT pg_advisory_unlock($1)`, d.lockKey); err != nil {
		return fmt.Errorf("store: migration unlock: %w", err)
	}
	d.isLocked = false
	return nil
}

// Run applies one migration file. The whole file goes in one Exec, which
// Postgres runs as a single implicit transaction, so a migration that fails
// halfway does not leave half its tables behind.
func (d *pgxMigrationDriver) Run(migration io.Reader) error {
	body, err := io.ReadAll(migration)
	if err != nil {
		return fmt.Errorf("store: read migration: %w", err)
	}
	if strings.TrimSpace(string(body)) == "" {
		return nil
	}
	if _, err := d.conn.Exec(d.ctx, string(body)); err != nil {
		return fmt.Errorf("store: run migration: %w", err)
	}
	return nil
}

func (d *pgxMigrationDriver) SetVersion(version int, dirty bool) error {
	return pgx.BeginFunc(d.ctx, d.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(d.ctx, `DELETE FROM `+migrationsTableName); err != nil {
			return fmt.Errorf("store: clear %s: %w", migrationsTableName, err)
		}
		// A negative version is golang-migrate's NilVersion, meaning "nothing
		// applied". It is represented by the absence of a row.
		if version < 0 {
			return nil
		}
		_, err := tx.Exec(d.ctx,
			`INSERT INTO `+migrationsTableName+` (version, dirty) VALUES ($1, $2)`, version, dirty)
		if err != nil {
			return fmt.Errorf("store: set version: %w", err)
		}
		return nil
	})
}

func (d *pgxMigrationDriver) Version() (int, bool, error) {
	var version int
	var dirty bool
	err := d.conn.QueryRow(d.ctx,
		`SELECT version, dirty FROM `+migrationsTableName+` LIMIT 1`).Scan(&version, &dirty)
	if errors.Is(err, pgx.ErrNoRows) {
		return database.NilVersion, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("store: read version: %w", err)
	}
	return version, dirty, nil
}

// Drop removes every table in the current schema. golang-migrate calls it only
// for an explicit drop request.
func (d *pgxMigrationDriver) Drop() error {
	rows, err := d.conn.Query(d.ctx,
		`SELECT tablename FROM pg_tables WHERE schemaname = current_schema()`)
	if err != nil {
		return fmt.Errorf("store: list tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("store: scan table name: %w", err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: list tables: %w", err)
	}
	for _, name := range tables {
		quoted := pgx.Identifier{name}.Sanitize()
		if _, err := d.conn.Exec(d.ctx, `DROP TABLE IF EXISTS `+quoted+` CASCADE`); err != nil {
			return fmt.Errorf("store: drop %s: %w", name, err)
		}
	}
	return nil
}

// advisoryKey derives a stable 64-bit advisory lock key from a name. Postgres
// advisory locks are namespaced only by the integer, so the derivation has to
// be deterministic across processes and versions.
func advisoryKey(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return int64(h.Sum64()) //nolint:gosec // the full 64-bit space is the key space
}
