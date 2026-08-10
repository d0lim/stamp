package store_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// The tests in this package run against a real Postgres. The schema is most of
// what this unit delivers — constraints, grants, a unique index that is the
// only thing standing between two writers and a forked audit chain — and none
// of that is exercised by a fake.

const postgresImage = "postgres:17-alpine"

var (
	adminDSN string
	dbSerial atomic.Int64
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	container, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase("stamp"),
		tcpostgres.WithUsername("stamp"),
		tcpostgres.WithPassword("stamp"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store tests need a working Docker daemon: %v\n", err)
		os.Exit(1)
	}
	adminDSN, err = container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection string: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	if err := testcontainers.TerminateContainer(container); err != nil {
		fmt.Fprintf(os.Stderr, "terminate container: %v\n", err)
	}
	os.Exit(code)
}

// freshDB creates an empty database in the shared container and returns its
// DSN. Each test gets its own so that a test which tampers with the audit log
// cannot make an unrelated test fail.
func freshDB(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("t%d_%d", time.Now().UnixNano()%1e9, dbSerial.Add(1))

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect to admin database: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}
	return replaceDBName(adminDSN, name)
}

func replaceDBName(dsn, name string) string {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.ConnConfig.User, cfg.ConnConfig.Password, cfg.ConnConfig.Host, cfg.ConnConfig.Port, name)
}

// testMaxConns sizes the pool for tests that claim several audit writers at
// once. Each claim holds a connection for the writer's lifetime, so the pool
// has to cover the writers plus the connections their appends and the test's
// own queries need. Leaving it to the pgxpool default makes the concurrency
// tests pass or hang depending on the core count of the machine.
const testMaxConns = 24

// openStore opens a store on a fresh database without migrating it.
func openStore(t *testing.T, dsn string) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), store.Config{DSN: dsn, MaxConns: testMaxConns})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// migratedStore is the common fixture: a fresh database at the latest schema.
func migratedStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dsn := freshDB(t)
	s := openStore(t, dsn)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s, dsn
}

func claimWriter(t *testing.T, s *store.Store, id string) *store.AuditWriter {
	t.Helper()
	w, err := s.ClaimWriter(context.Background(), id, "test")
	if err != nil {
		t.Fatalf("claim writer %s: %v", id, err)
	}
	t.Cleanup(func() { _ = w.Close(context.Background()) })
	return w
}

func testSigner(t *testing.T) *store.CheckpointSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := store.NewCheckpointSigner("test-key", priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer
}

func fileSink(t *testing.T) *store.FileSink {
	t.Helper()
	sink, err := store.NewFileSink(filepath.Join(t.TempDir(), "checkpoints.jsonl"))
	if err != nil {
		t.Fatalf("new file sink: %v", err)
	}
	return sink
}

// seedPolicy stores a schema and one policy so that decision rows have a
// foreign key to point at.
func seedPolicy(t *testing.T, s *store.Store, id string, challenges ...policy.Challenge) store.PolicyRecord {
	t.Helper()
	ctx := context.Background()
	schema := &policy.Schema{
		Entities: []policy.EntityType{
			{Name: "user", Attributes: []policy.Attribute{{Name: "role", Type: policy.TypeString}}},
			{Name: "account", Attributes: []policy.Attribute{{Name: "tier", Type: policy.TypeString}}},
		},
		Actions: []policy.Action{{Name: "transfer"}},
	}
	if _, err := store.LatestSchema(ctx, s.Pool()); errors.Is(err, store.ErrNotFound) {
		if _, err := store.PutSchema(ctx, s.Pool(), schema, store.OriginForm, "tester"); err != nil {
			t.Fatalf("put schema: %v", err)
		}
	}
	latest, err := store.LatestSchema(ctx, s.Pool())
	if err != nil {
		t.Fatalf("latest schema: %v", err)
	}

	p := &policy.Policy{
		ID:         id,
		Subject:    "user",
		Resource:   "account",
		Actions:    []string{"transfer"},
		Condition:  policy.Compare{Op: policy.OpEq, Left: policy.Field(policy.RoleSubject, "role"), Right: policy.String("admin")},
		Challenges: challenges,
	}
	rec, err := store.PutPolicy(ctx, s.Pool(), store.PolicyInput{
		Policy: p, SchemaVersion: latest.Version, Origin: store.OriginForm, Author: "tester",
	})
	if err != nil {
		t.Fatalf("put policy: %v", err)
	}
	return rec
}

// ---------------------------------------------------------------------------
// migrations
// ---------------------------------------------------------------------------

func TestMigrateUpFromEmptyAndRollbackOneStep(t *testing.T) {
	ctx := context.Background()
	dsn := freshDB(t)
	s := openStore(t, dsn)

	if _, _, ok, err := s.SchemaVersion(ctx); err != nil || ok {
		t.Fatalf("empty database reported version ok=%v err=%v, want no version", ok, err)
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	version, dirty, ok, err := s.SchemaVersion(ctx)
	if err != nil || !ok {
		t.Fatalf("schema version after migrate: ok=%v err=%v", ok, err)
	}
	if dirty {
		t.Fatal("schema is dirty after a clean migrate")
	}
	if version != 6 {
		t.Fatalf("schema version = %d, want 6", version)
	}

	for _, table := range []string{
		"policy_schemas", "policies", "decisions", "challenge_progress", "approvals",
		"audit_writers", "audit_log", "audit_checkpoints", "velocity_buckets", "processed_events",
		"policy_revisions", "governance_bootstrap",
	} {
		if !tableExists(t, s, table) {
			t.Errorf("table %q is missing after migrate", table)
		}
	}

	if err := s.MigrateDown(ctx, 1); err != nil {
		t.Fatalf("migrate down 1: %v", err)
	}
	version, dirty, ok, err = s.SchemaVersion(ctx)
	if err != nil || !ok {
		t.Fatalf("schema version after rollback: ok=%v err=%v", ok, err)
	}
	if dirty {
		t.Fatal("schema is dirty after a clean rollback")
	}
	if version != 5 {
		t.Fatalf("schema version after one rollback = %d, want 5", version)
	}
	// The newest migration only adds columns to policy_revisions, so rolling it
	// back leaves the table and takes the column.
	if !tableExists(t, s, "policy_revisions") {
		t.Error("policy_revisions was dropped by a rollback of a migration that only altered it")
	}
	if columnExists(t, s, "policy_revisions", "origin") {
		t.Error("policy_revisions.origin survived the rollback of its own migration")
	}

	if err := s.MigrateDown(ctx, 1); err != nil {
		t.Fatalf("migrate down 1: %v", err)
	}
	if tableExists(t, s, "policy_revisions") {
		t.Error("policy_revisions survived the rollback of its own migration")
	}
	if tableExists(t, s, "governance_bootstrap") {
		t.Error("governance_bootstrap survived the rollback of its own migration")
	}
	if !tableExists(t, s, "processed_events") {
		t.Error("processed_events was dropped by a rollback that should not have touched it")
	}
	if !tableExists(t, s, "audit_log") {
		t.Error("audit_log was dropped by a rollback that should not have touched it")
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("re-migrate after rollback: %v", err)
	}
	if !tableExists(t, s, "policy_revisions") {
		t.Error("policy_revisions did not come back after re-migrating")
	}
	if !columnExists(t, s, "policy_revisions", "origin") {
		t.Error("policy_revisions.origin did not come back after re-migrating")
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func tableExists(t *testing.T, s *store.Store, name string) bool {
	t.Helper()
	var exists bool
	err := s.Pool().QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = current_schema() AND tablename = $1)`,
		name).Scan(&exists)
	if err != nil {
		t.Fatalf("check table %q: %v", name, err)
	}
	return exists
}

func columnExists(t *testing.T, s *store.Store, table, column string) bool {
	t.Helper()
	var exists bool
	err := s.Pool().QueryRow(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2)`,
		table, column).Scan(&exists)
	if err != nil {
		t.Fatalf("check column %q.%q: %v", table, column, err)
	}
	return exists
}

// ---------------------------------------------------------------------------
// role grants
// ---------------------------------------------------------------------------

// loginAs gives a provisioned role a password and connects as it. The grants
// file deliberately creates NOLOGIN roles, so a test that wants to connect has
// to do what a deployment does: attach the privilege template to a login role.
func loginAs(t *testing.T, s *store.Store, dsn, role string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	login := role + "_login"
	stmts := []string{
		fmt.Sprintf(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%s') THEN CREATE ROLE %s LOGIN PASSWORD 'pw'; END IF; END $$`, login, login),
		fmt.Sprintf(`ALTER ROLE %s WITH LOGIN PASSWORD 'pw'`, login),
		fmt.Sprintf(`GRANT %s TO %s`, role, login),
	}
	for _, stmt := range stmts {
		if _, err := s.Pool().Exec(ctx, stmt); err != nil {
			t.Fatalf("provision login role %s: %v", login, err)
		}
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	roleDSN := fmt.Sprintf("postgres://%s:pw@%s:%d/%s?sslmode=disable",
		login, cfg.ConnConfig.Host, cfg.ConnConfig.Port, cfg.ConnConfig.Database)
	pool, err := pgxpool.New(ctx, roleDSN)
	if err != nil {
		t.Fatalf("connect as %s: %v", login, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestCheckRoleCannotWritePolicies(t *testing.T) {
	ctx := context.Background()
	s, dsn := migratedStore(t)
	seedPolicy(t, s, "p1")

	check := loginAs(t, s, dsn, "stamp_check")

	var id string
	if err := check.QueryRow(ctx, `SELECT id FROM policies LIMIT 1`).Scan(&id); err != nil {
		t.Fatalf("check role cannot read policies, but it must: %v", err)
	}

	_, err := check.Exec(ctx, `UPDATE policies SET document = 'tampered' WHERE id = $1`, id)
	if err == nil {
		t.Fatal("check role updated the policy table")
	}
	if !isInsufficientPrivilege(err) {
		t.Fatalf("check role policy update failed with %v, want insufficient_privilege", err)
	}

	_, err = check.Exec(ctx, `
		INSERT INTO policies (id, version, schema_version, origin, document, content_hash, requires_decision, created_by)
		VALUES ('injected', 1, 1, 'form', 'x', '\x00', false, 'attacker')`)
	if err == nil {
		t.Fatal("check role inserted into the policy table")
	}
	if !isInsufficientPrivilege(err) {
		t.Fatalf("check role policy insert failed with %v, want insufficient_privilege", err)
	}

	// The check role does have to be able to append audit rows, or the check
	// path cannot record anything at all.
	_, err = check.Exec(ctx, `
		INSERT INTO audit_log (writer_id, seq, prev_hash, hash, kind, subject, payload, recorded_at)
		VALUES ('checker', 1, decode(repeat('00', 32), 'hex'), decode(repeat('11', 32), 'hex'),
		        'check.batch', '', '{}'::jsonb, now())`)
	if err != nil {
		t.Fatalf("check role cannot append to the audit log, but it must: %v", err)
	}
}

func TestConsumerRoleCannotWriteOutsideBuckets(t *testing.T) {
	ctx := context.Background()
	s, dsn := migratedStore(t)
	seedPolicy(t, s, "p1")

	consumer := loginAs(t, s, dsn, "stamp_consumer")

	if _, err := consumer.Exec(ctx, `
		INSERT INTO velocity_buckets (subject_id, metric, width_seconds, bucket_start, event_count, value_sum)
		VALUES ('u1', 'transfers', 60, now(), 1, 1.0)`); err != nil {
		t.Fatalf("consumer role cannot upsert a bucket, but it must: %v", err)
	}
	if _, err := consumer.Exec(ctx, `
		INSERT INTO processed_events (caller_id, event_id, metric) VALUES ('c1', 'e1', 'transfers')`); err != nil {
		t.Fatalf("consumer role cannot write the dedup index, but it must: %v", err)
	}

	forbidden := []struct {
		what string
		sql  string
	}{
		{"audit_log", `INSERT INTO audit_log (writer_id, seq, prev_hash, hash, kind, subject, payload, recorded_at)
			VALUES ('c', 1, decode(repeat('00',32),'hex'), decode(repeat('11',32),'hex'), 'x', '', '{}'::jsonb, now())`},
		{"policies", `UPDATE policies SET document = 'tampered'`},
		{"decisions", `INSERT INTO decisions (id, caller_id, policy_id, policy_version, subject_id, resource_id, action,
			request, fact_snapshot, state, expires_at)
			VALUES (gen_random_uuid(), 'c', 'p1', 1, 's', 'r', 'transfer', '{}'::jsonb, '{}'::jsonb, 'pending', now())`},
		{"approvals", `DELETE FROM approvals`},
		{"audit_checkpoints", `DELETE FROM audit_checkpoints`},
	}
	for _, tc := range forbidden {
		_, err := consumer.Exec(ctx, tc.sql)
		if err == nil {
			t.Errorf("consumer role wrote to %s", tc.what)
			continue
		}
		if !isInsufficientPrivilege(err) {
			t.Errorf("consumer write to %s failed with %v, want insufficient_privilege", tc.what, err)
		}
	}
}

func TestGrantsRejectUnsafeRoleNames(t *testing.T) {
	ctx := context.Background()
	dsn := freshDB(t)
	s, err := store.Open(ctx, store.Config{
		DSN:      dsn,
		MaxConns: testMaxConns,
		Roles:    store.RoleNames{Check: `check"; DROP TABLE policies; --`},
	})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)

	err = s.Migrate(ctx)
	if err == nil {
		t.Fatal("a role name carrying SQL was accepted")
	}
	if !strings.Contains(err.Error(), "not a plain lowercase SQL identifier") {
		t.Fatalf("error = %v, want a rejection of the role name", err)
	}
}

func isInsufficientPrivilege(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "42501"
	}
	return false
}
