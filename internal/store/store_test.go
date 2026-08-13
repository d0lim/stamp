package store_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	if version != 9 {
		t.Fatalf("schema version = %d, want 9", version)
	}

	// 000008 is the idempotency key and its length check; 000009 is the unique
	// index that backstops the key, split off so it can be built CONCURRENTLY
	// instead of holding ACCESS EXCLUSIVE on `decisions` for a full heap scan.
	// The index is named here rather than counted, because its name is what the
	// store reads off a 23505 to tell a repeated key from a collided identifier:
	// an index that exists under another name is a conflict reported as the wrong
	// thing.
	//
	// That the index exists at all after a plain Migrate is the assertion that
	// CREATE INDEX CONCURRENTLY is legal through this driver at all. The driver
	// sends a migration file in one argument-less Exec, which pgx routes through
	// the simple query protocol; a multi-statement simple query is an implicit
	// transaction block and CONCURRENTLY would fail there with 25001. 000009
	// holds exactly one statement so that it does not. If someone adds a second
	// statement to that file, Migrate above fails and this test is where it says
	// so.
	if !columnExists(t, s, "decisions", "idempotency_key") {
		t.Error("decisions.idempotency_key is missing after migrate")
	}
	// The fingerprint rides in the same migration as the key, because a key
	// without one is the substitution the two columns together prevent: the
	// decide path's lookup is fail-closed on a row that holds a key and no
	// digest, so a schema with only the first column is a schema where every
	// keyed retry is refused.
	if !columnExists(t, s, "decisions", "idempotency_fingerprint") {
		t.Error("decisions.idempotency_fingerprint is missing after migrate")
	}
	if !indexExists(t, s, "decisions_unique_idempotency_key") {
		t.Error("index \"decisions_unique_idempotency_key\" is missing after migrate")
	}
	// CONCURRENTLY's failure mode is an index that exists and enforces nothing,
	// so existence is not enough: an INVALID index is exactly what a build that
	// died half-way leaves behind, and it would satisfy the check above while
	// letting a second decision through on a key another one already holds.
	if !indexIsValid(t, s, "decisions_unique_idempotency_key") {
		t.Error("decisions_unique_idempotency_key exists but is INVALID: a concurrent build " +
			"did not finish, and the index enforces nothing")
	}

	// 000007 is index-only. Its indexes are the audit console's query axes, so
	// their absence is a silently slow console rather than a failure, which is
	// exactly the kind of regression a count assertion alone would not catch.
	for _, index := range []string{
		"decisions_history_idx", "decisions_policy_history_idx",
		"decisions_subject_history_idx", "decisions_state_history_idx",
		"challenge_progress_open_quorum_idx",
	} {
		if !indexExists(t, s, index) {
			t.Errorf("index %q is missing after migrate", index)
		}
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
	if version != 8 {
		t.Fatalf("schema version after one rollback = %d, want 8", version)
	}
	// Rolling back the index migration takes the index and leaves the column and
	// its check, because the two are separate migrations now: a deployment that
	// has to undo a stuck concurrent build should not have to give up the column
	// the decide path already reads.
	if indexExists(t, s, "decisions_unique_idempotency_key") {
		t.Error("decisions_unique_idempotency_key survived the rollback of its own migration")
	}
	if !columnExists(t, s, "decisions", "idempotency_key") {
		t.Error("decisions.idempotency_key was dropped by a rollback that only owns the index")
	}
	if !columnExists(t, s, "decisions", "idempotency_fingerprint") {
		t.Error("decisions.idempotency_fingerprint was dropped by a rollback that only owns the index")
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
	if version != 7 {
		t.Fatalf("schema version after two rollbacks = %d, want 7", version)
	}
	// Rolling back a column takes the column and its check, and leaves every
	// decision row where it was. A rollback that dropped rows to drop a column
	// would be a rollback nobody could run on a live deployment.
	if columnExists(t, s, "decisions", "idempotency_key") {
		t.Error("decisions.idempotency_key survived the rollback of its own migration")
	}
	if columnExists(t, s, "decisions", "idempotency_fingerprint") {
		t.Error("decisions.idempotency_fingerprint survived the rollback of its own migration")
	}
	if !tableExists(t, s, "decisions") {
		t.Error("decisions was dropped by a rollback that only added a column to it")
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
	if version != 6 {
		t.Fatalf("schema version after three rollbacks = %d, want 6", version)
	}
	// Rolling back an index-only migration takes the indexes and leaves every
	// row where it was.
	if indexExists(t, s, "decisions_history_idx") {
		t.Error("decisions_history_idx survived the rollback of its own migration")
	}
	if !tableExists(t, s, "decisions") {
		t.Error("decisions was dropped by a rollback that only created indexes on it")
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
		t.Fatalf("schema version after four rollbacks = %d, want 5", version)
	}
	// 000006 only adds columns to policy_revisions, so rolling it back leaves
	// the table and takes the column.
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

// TestDecisionReadsFailAgainstTheSchemaBeforeTheirOwn pins the hazard the
// readiness gate exists for.
//
// decisionColumns names idempotency_key, and it backs every decision read and
// the create insert. That column arrives in 000008. Only one tier migrates — the
// chart hands `database.migrate` to the `api` role alone — and `helm upgrade`
// rolls every Deployment at once with no hook, no Job and no initContainer
// sequencing them. So there is a window in every upgrade where a decide pod is
// running this binary against schema 7, and this test is what that window looks
// like from inside the process: not a slow query, not a missing field, but every
// read failing outright with 42703.
//
// It asserts the failure rather than fixing it, because it cannot be fixed here:
// the query has to name the column it selects. What the failure buys is the
// argument for [Store.SchemaBehind] and the /readyz gate in front of it — the
// pod must not be in its Service while this is the answer. If someone later
// makes decision reads tolerate a missing column, this test fails and the gate's
// justification has to be rewritten rather than quietly outlived.
func TestDecisionReadsFailAgainstTheSchemaBeforeTheirOwn(t *testing.T) {
	ctx := context.Background()
	s := openStore(t, freshDB(t))
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	// Down to 7: 000009's index and 000008's column, in that order.
	if err := s.MigrateDown(ctx, 2); err != nil {
		t.Fatalf("migrate down 2: %v", err)
	}
	version, _, _, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if version != 7 {
		t.Fatalf("schema version = %d, want 7 (the version a pod can be ahead of)", version)
	}

	_, err = store.GetDecision(ctx, s.Pool(), "any-decision-id")
	if err == nil {
		t.Fatal("GetDecision succeeded against schema 7, which does not have decisions.idempotency_key: " +
			"either the column moved out of decisionColumns or this test stopped rolling back far enough")
	}
	if errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetDecision reported ErrNotFound against schema 7: the read is supposed to fail on the "+
			"schema, not on the row, and a not-found here would mean the mismatch is invisible: %v", err)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42703" {
		t.Fatalf("GetDecision against schema 7 failed with %v, want SQLSTATE 42703 (undefined_column)", err)
	}
	if !strings.Contains(pgErr.Message, "idempotency_key") {
		t.Errorf("42703 does not name idempotency_key: %q", pgErr.Message)
	}

	// And the gate above the surface says so, which is the whole remedy: the
	// same database state that breaks the read is one this process can see and
	// refuse traffic on before a caller finds out the hard way.
	latest, err := store.LatestSchemaVersion()
	if err != nil {
		t.Fatalf("latest schema version: %v", err)
	}
	at, dirty, ready, err := s.SchemaBehind(ctx, latest)
	if err != nil {
		t.Fatalf("schema behind: %v", err)
	}
	if dirty {
		t.Error("a clean rollback left the schema dirty")
	}
	if ready {
		t.Errorf("SchemaBehind reported ready at version %d against a binary needing %d, "+
			"on a database where the decision read above just failed", at, latest)
	}
	if at != 7 {
		t.Errorf("SchemaBehind reported version %d, want 7", at)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func indexExists(t *testing.T, s *store.Store, name string) bool {
	t.Helper()
	var exists bool
	err := s.Pool().QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1)`,
		name).Scan(&exists)
	if err != nil {
		t.Fatalf("check index %q: %v", name, err)
	}
	return exists
}

// indexIsValid reports whether an index is one Postgres will enforce and plan
// against. A CREATE INDEX CONCURRENTLY that is interrupted leaves the index in
// pg_indexes with indisvalid = false: present, maintained on every write, and
// enforcing nothing. Existence and validity are therefore different questions,
// and only the second one is the one the unique backstop needs answered.
func indexIsValid(t *testing.T, s *store.Store, name string) bool {
	t.Helper()
	var valid bool
	err := s.Pool().QueryRow(context.Background(), `
		SELECT i.indisvalid AND i.indisready
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relname = $1`, name).Scan(&valid)
	if err != nil {
		t.Fatalf("check index validity %q: %v", name, err)
	}
	return valid
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

// ---------------------------------------------------------------------------
// concurrent grant application
// ---------------------------------------------------------------------------

// uniqueRoleNames returns a role name set no other test has provisioned.
//
// Roles are cluster-global and every test in this package shares one container,
// so a fixed name set would make the concurrency tests below depend on whether
// some earlier test had already created the roles. "The roles do not exist yet"
// is exactly the state the race needs, and it is the state a real cluster is in
// the first time a release rolls.
func uniqueRoleNames(t *testing.T) store.RoleNames {
	t.Helper()
	prefix := fmt.Sprintf("r%d_%d", time.Now().UnixNano()%1e9, dbSerial.Add(1))
	return store.RoleNames{
		Check:    prefix + "_check",
		Decide:   prefix + "_decide",
		Consumer: prefix + "_consumer",
		Admin:    prefix + "_admin",
	}
}

// openStoreWithRoles opens a store on an existing database with a chosen role
// name set, standing in for one pod's boot.
func openStoreWithRoles(t *testing.T, dsn string, roles store.RoleNames) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), store.Config{DSN: dsn, MaxConns: testMaxConns, Roles: roles})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// applyGrantsConcurrently runs ApplyGrants on every store at once and fails the
// test for any boot that did not survive.
//
// The start channel matters: without it the goroutines are staggered by their
// own scheduling and the first one is usually finished before the second looks
// at pg_roles, which is why this race reproduced on CI and not on a laptop.
func applyGrantsConcurrently(t *testing.T, stores []*store.Store) {
	t.Helper()
	ctx := context.Background()

	errs := make([]error, len(stores))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, s := range stores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = s.ApplyGrants(ctx)
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("boot %d: apply grants: %v", i, err)
		}
	}
}

// concurrentBoots is how many processes race. Kubernetes rolls a Deployment's
// replicas together and `helm upgrade` rolls every tier at once, so more than
// two is the normal case rather than the pathological one; four keeps the window
// wide enough that a regression fails on the first run instead of the tenth.
const concurrentBoots = 4

// TestApplyGrantsSurvivesConcurrentBoot is the defect CI found: two containers
// started against one database at the same instant and the api tier died at boot
// with 23505 on pg_authid_rolname_index. Grants are applied at pod boot, so a
// process that cannot survive a peer doing the same thing at the same moment is
// a process that crashloops on a normal rollout.
func TestApplyGrantsSurvivesConcurrentBoot(t *testing.T) {
	base, dsn := migratedStore(t)
	roles := uniqueRoleNames(t)

	stores := make([]*store.Store, concurrentBoots)
	for i := range stores {
		stores[i] = openStoreWithRoles(t, dsn, roles)
	}
	applyGrantsConcurrently(t, stores)

	// Surviving the race is only half of it. An apply that became idempotent by
	// becoming permissive would pass the assertion above and hand a compromised
	// tier privileges R42 says it must never have, so the privilege matrix is
	// checked on the roles the concurrent applies actually produced.
	assertGrantsAreRestrictive(t, base, roles)
}

// TestApplyGrantsSurvivesConcurrentBootAcrossDatabases covers the scope the
// roles actually live in. Roles are cluster-global while tables are per-database,
// so two STAMP deployments sharing a cluster race on role creation even though
// they share nothing else — and no per-database lock can serialise them, because
// Postgres has no cluster-wide advisory lock.
func TestApplyGrantsSurvivesConcurrentBootAcrossDatabases(t *testing.T) {
	roles := uniqueRoleNames(t)

	stores := make([]*store.Store, concurrentBoots)
	bases := make([]*store.Store, concurrentBoots)
	for i := range stores {
		base, dsn := migratedStore(t)
		bases[i] = base
		stores[i] = openStoreWithRoles(t, dsn, roles)
	}
	applyGrantsConcurrently(t, stores)

	for _, base := range bases {
		assertGrantsAreRestrictive(t, base, roles)
	}
}

// TestMigrateSurvivesConcurrentBoot is the same question one line earlier on the
// boot path. STAMP_DB_MIGRATE defaults to true, so every replica that boots also
// migrates, and Migrate ends by calling ApplyGrants — a Migrate that cannot
// survive a peer leaves the process dying on exactly the rollout the grants fix
// was meant to make survivable.
func TestMigrateSurvivesConcurrentBoot(t *testing.T) {
	ctx := context.Background()
	dsn := freshDB(t)

	stores := make([]*store.Store, concurrentBoots)
	for i := range stores {
		stores[i] = openStore(t, dsn)
	}

	errs := make([]error, len(stores))
	start := make(chan struct{})
	// inFlight counts boots currently inside Migrate; peak remembers the most
	// that were ever there at once. Without this the test passes on a run that
	// happened to serialize, which is the failure mode that let this defect
	// survive two rounds: measured against the unfixed code it failed twice in
	// 145 runs, so a green run said nothing about 98.6% of the time. The limiter
	// tests in internal/stream and internal/api already count entrants this way;
	// this is that idiom reaching internal/store.
	var inFlight, peak atomic.Int64
	var wg sync.WaitGroup
	for i, s := range stores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			n := inFlight.Add(1)
			for {
				seen := peak.Load()
				if n <= seen || peak.CompareAndSwap(seen, n) {
					break
				}
			}
			errs[i] = s.Migrate(ctx)
			inFlight.Add(-1)
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("boot %d: migrate: %v", i, err)
		}
	}

	// A run where no two boots overlapped exercised nothing this test exists to
	// exercise, so it is reported rather than counted as a pass. It is not a
	// product defect — hence Errorf on the observation, not Fatalf — but a green
	// tick against a serialized run is exactly the false assurance being removed.
	if got := peak.Load(); got < 2 {
		t.Errorf("at most %d boot was inside Migrate at a time: the run serialized and proved nothing about the race", got)
	}

	// Every boot must also agree the schema arrived. A migrate that returned nil
	// without the schema being at the latest version would be the quiet failure
	// this is guarding against, and readiness reads exactly this number.
	want, err := store.LatestSchemaVersion()
	if err != nil {
		t.Fatalf("latest schema version: %v", err)
	}
	for i, s := range stores {
		version, dirty, ok, err := s.AppliedSchemaVersion(ctx)
		if err != nil {
			t.Fatalf("boot %d: applied schema version: %v", i, err)
		}
		if !ok || dirty || version != want {
			t.Errorf("boot %d: applied version = %d (dirty=%v, ok=%v), want %d clean", i, version, dirty, ok, want)
		}
	}
}

// TestCommitAfterAFailedStatementReportsRollback pins the driver behaviour
// ensureVersionTable's duplicate branch is shaped around.
//
// A statement that errors inside an explicit transaction leaves it aborted, so
// Postgres answers COMMIT with a ROLLBACK tag rather than an error — and pgx
// turns that tag into ErrTxCommitRollback. Code that tolerates an error and then
// commits anyway therefore fails at the commit, not at the statement it chose to
// tolerate.
//
// That is not a hypothetical here: it is the rolling upgrade that introduces the
// version-table lock, where a pod on the previous build can commit the table
// between this transaction's lock and its create. Tolerating the duplicate and
// committing would turn that into a failed boot on the one deploy the tolerance
// exists for.
//
// This test is a claim about pgx and Postgres, not about this package, which is
// exactly why it is worth having: the reason ensureVersionTable returns early
// instead of falling through lives outside our code, so nothing else would go
// red if the assumption stopped holding.
func TestCommitAfterAFailedStatementReportsRollback(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, freshDB(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Any error will do; a duplicate is the one this mirrors.
	if _, err := tx.Exec(ctx, `CREATE TABLE pinned (id int)`); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err = tx.Exec(ctx, `CREATE TABLE pinned (id int)`)
	if err == nil {
		t.Fatal("a second CREATE TABLE of the same name succeeded")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42P07" {
		t.Fatalf("second create = %v, want 42P07 duplicate_table", err)
	}

	if cerr := tx.Commit(ctx); !errors.Is(cerr, pgx.ErrTxCommitRollback) {
		t.Fatalf("commit after a failed statement = %v, want pgx.ErrTxCommitRollback; "+
			"if this driver behaviour changed, ensureVersionTable's duplicate branch can be simplified", cerr)
	}
}

// assertGrantsAreRestrictive checks a sample of the privilege matrix R39 and R42
// pin down: every role can read what it has to read, and none of them gained a
// write the grants file does not hand out.
func assertGrantsAreRestrictive(t *testing.T, s *store.Store, roles store.RoleNames) {
	t.Helper()
	cases := []struct {
		role  string
		table string
		priv  string
		want  bool
	}{
		// Every role reads the applied schema version for its readiness probe,
		// and none of them may claim one.
		{roles.Check, "schema_migrations", "SELECT", true},
		{roles.Decide, "schema_migrations", "SELECT", true},
		{roles.Consumer, "schema_migrations", "SELECT", true},
		{roles.Admin, "schema_migrations", "SELECT", true},
		{roles.Check, "schema_migrations", "UPDATE", false},
		{roles.Consumer, "schema_migrations", "INSERT", false},

		// check reads policies and appends audit rows; it never authors a rule.
		{roles.Check, "policies", "SELECT", true},
		{roles.Check, "policies", "INSERT", false},
		{roles.Check, "policies", "UPDATE", false},
		{roles.Check, "audit_log", "INSERT", true},
		{roles.Check, "audit_log", "UPDATE", false},
		{roles.Check, "audit_log", "DELETE", false},

		// decide owns the decision lifecycle and stays read-only on policies.
		{roles.Decide, "decisions", "UPDATE", true},
		{roles.Decide, "policies", "UPDATE", false},
		{roles.Decide, "approvals", "DELETE", false},
		{roles.Decide, "policy_revisions", "SELECT", true},
		{roles.Decide, "policy_revisions", "INSERT", false},

		// consumer is the least trusted writer: buckets and the dedup index only.
		{roles.Consumer, "velocity_buckets", "UPDATE", true},
		{roles.Consumer, "processed_events", "DELETE", true},
		{roles.Consumer, "audit_log", "INSERT", false},
		{roles.Consumer, "policies", "SELECT", false},
		{roles.Consumer, "decisions", "SELECT", false},

		// admin authors policy and governs, and still cannot rewrite the log.
		{roles.Admin, "policies", "UPDATE", true},
		{roles.Admin, "approvals", "DELETE", true},
		{roles.Admin, "audit_log", "INSERT", true},
		{roles.Admin, "audit_log", "UPDATE", false},
		{roles.Admin, "audit_log", "DELETE", false},
		{roles.Admin, "audit_checkpoints", "UPDATE", false},
	}
	for _, tc := range cases {
		var got bool
		err := s.Pool().QueryRow(context.Background(),
			`SELECT has_table_privilege($1, $2, $3)`, tc.role, tc.table, tc.priv).Scan(&got)
		if err != nil {
			t.Fatalf("has_table_privilege(%s, %s, %s): %v", tc.role, tc.table, tc.priv, err)
		}
		if got != tc.want {
			t.Errorf("has_table_privilege(%s, %s, %s) = %v, want %v", tc.role, tc.table, tc.priv, got, tc.want)
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

// TestReachabilityDistinguishesAnUnreachableServerFromAnAngryOne pins the one
// judgment [store.Reachability] makes.
//
// The readiness gate in internal/runtime takes a pod out of its Service on the
// strength of these reports, so the classification is load-bearing in the
// direction that matters most: a server that answers with an error has
// answered, and a deployment whose pods left their Service every time a query
// hit a constraint or a missing column would be a worse failure than the
// fail-open this signal was introduced to close.
func TestReachabilityDistinguishesAnUnreachableServerFromAnAngryOne(t *testing.T) {
	ctx := context.Background()

	type observation struct {
		reached bool
		err     error
	}
	var mu sync.Mutex
	var seen []observation
	record := func(o store.Reachability) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, observation{reached: o.Reached, err: o.Err})
	}
	drain := func() []observation {
		mu.Lock()
		defer mu.Unlock()
		out := seen
		seen = nil
		return out
	}

	s, err := store.Open(ctx, store.Config{
		DSN: freshDB(t), MaxConns: testMaxConns, OnReachability: record,
	})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)

	// A statement that works.
	var one int
	if err := s.Pool().QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		t.Fatalf("select 1: %v", err)
	}
	for _, o := range drain() {
		if !o.reached {
			t.Errorf("a successful statement was reported unreachable: %v", o.err)
		}
	}

	// A statement the server refuses. 42P01 is the shape a tier running ahead
	// of its schema produces, and it is exactly the case that must not read as
	// an outage.
	if err := s.Pool().QueryRow(ctx, `SELECT * FROM a_table_that_is_not_there`).Scan(&one); err == nil {
		t.Fatal("selecting from a missing table succeeded")
	}
	angry := drain()
	if len(angry) == 0 {
		t.Fatal("a refused statement produced no observation at all")
	}
	for _, o := range angry {
		if !o.reached {
			t.Errorf("a server error was reported as an unreachable database: %v", o.err)
		}
	}

	// A server that is not there. The port is closed, so this never gets past
	// the dial — which is the only condition this type reports as unreachable.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := closed.Addr().String()
	if err := closed.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	drain()
	_, err = store.Open(ctx, store.Config{
		DSN:            "postgres://stamp:stamp@" + addr + "/stamp?sslmode=disable",
		OnReachability: record,
	})
	if err == nil {
		t.Fatal("opening a store against a closed port succeeded")
	}
	unreachable := drain()
	if len(unreachable) == 0 {
		t.Fatal("a connection to a closed port produced no observation at all")
	}
	for _, o := range unreachable {
		if o.reached {
			t.Error("a dial to a closed port was reported as a reachable database")
		}
		if o.err == nil {
			t.Error("an unreachable report carried no error to show an operator")
		}
	}
}

func isInsufficientPrivilege(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "42501"
	}
	return false
}
