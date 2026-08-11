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
// call and runs `CREATE TABLE IF NOT EXISTS schema_migrations` before it reads
// anything, which is both more than a readiness probe every few seconds should
// cost and more privilege than a non-migrating tier's login is given: R39's
// grants hand the decide role SELECT and nothing that creates objects. A probe
// that needed DDL rights to answer "may I serve?" would fail closed on exactly
// the least-privilege deployments this project asks operators to run.
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

// ApplyGrants provisions the per-role database roles and their privileges.
//
// The roles are created without LOGIN and without a password: they are
// privilege templates that a deployment grants to the login roles it already
// manages. Credentials never ship in a file embedded in the binary.
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
	if _, err := s.pool.Exec(ctx, sql.String()); err != nil {
		return fmt.Errorf("store: apply grants: %w", err)
	}
	return nil
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
	if err := d.ensureVersionTable(); err != nil {
		conn.Release()
		return nil, err
	}
	return d, nil
}

func (d *pgxMigrationDriver) ensureVersionTable() error {
	const stmt = `CREATE TABLE IF NOT EXISTS ` + migrationsTableName + ` (
		version bigint NOT NULL PRIMARY KEY,
		dirty   boolean NOT NULL
	)`
	if _, err := d.conn.Exec(d.ctx, stmt); err != nil {
		return fmt.Errorf("store: create %s: %w", migrationsTableName, err)
	}
	return nil
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
func (d *pgxMigrationDriver) Lock() error {
	if d.isLocked {
		return database.ErrLocked
	}
	var got bool
	if err := d.conn.QueryRow(d.ctx, `SELECT pg_try_advisory_lock($1)`, d.lockKey).Scan(&got); err != nil {
		return fmt.Errorf("store: migration lock: %w", err)
	}
	if !got {
		return database.ErrLocked
	}
	d.isLocked = true
	return nil
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
