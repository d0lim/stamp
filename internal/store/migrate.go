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
