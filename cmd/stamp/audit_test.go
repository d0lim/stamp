package main

// audit_test.go drives `stamp audit verify` against a real audit chain.
//
// The store package proves that the four defects — an in-place edit, a
// wholesale re-chaining, a missing checkpoint, a forged signature — are
// detectable. What is proved here is the thing a pipeline actually consumes:
// that the command catches them, and that each outcome arrives as a distinct
// exit code. A verification that detects everything and exits 0 detects nothing
// as far as CI is concerned.
//
// The cases that matter most are the two that produce no faults and must still
// not pass: a sink with nothing in it, and a checkpoint signed under a key
// nobody kept. Both are what a control that quietly stopped working looks like.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/d0lim/stamp/internal/runtime"
	"github.com/d0lim/stamp/internal/store"
)

const postgresImage = "postgres:17-alpine"

// postgresDSN starts the container on first use, so the stub-driven policy
// tests in this package still run without a Docker daemon.
var postgresDSN = sync.OnceValues(func() (string, error) {
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase("stamp"),
		tcpostgres.WithUsername("stamp"),
		tcpostgres.WithPassword("stamp"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		return "", fmt.Errorf("the audit verification tests need a working Docker daemon: %w", err)
	}
	setContainer(c)
	return c.ConnectionString(ctx, "sslmode=disable")
})

var (
	containerMu sync.Mutex
	container   testcontainers.Container
	dbSerial    atomic.Int64
)

func setContainer(c testcontainers.Container) {
	containerMu.Lock()
	defer containerMu.Unlock()
	container = c
}

func TestMain(m *testing.M) {
	code := m.Run()
	containerMu.Lock()
	running := container
	containerMu.Unlock()
	if running != nil {
		if err := testcontainers.TerminateContainer(running); err != nil {
			fmt.Fprintf(os.Stderr, "terminate container: %v\n", err)
		}
	}
	os.Exit(code)
}

func freshDB(t *testing.T) string {
	t.Helper()
	adminDSN, err := postgresDSN()
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	name := fmt.Sprintf("a%d_%d", time.Now().UnixNano()%1e9, dbSerial.Add(1))

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect to admin database: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}
	cfg, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.ConnConfig.User, cfg.ConnConfig.Password, cfg.ConnConfig.Host, cfg.ConnConfig.Port, name)
}

// ---------------------------------------------------------------------------
// the fixture: a deployment that has been recording an audit chain
// ---------------------------------------------------------------------------

const fixtureKeyID = "audit-2026-08"

type auditFixture struct {
	t        *testing.T
	dsn      string
	store    *store.Store
	writer   *store.AuditWriter
	signer   *store.CheckpointSigner
	sink     *store.FileSink
	sinkPath string
}

// newAuditFixture builds a database with an audit chain, a checkpoint sink, and
// the operator configuration the verification command reads: the sink path and
// the public half of the signing key. The private half stays in this process
// and is never configured, because that is how an auditor's host is set up.
func newAuditFixture(t *testing.T) *auditFixture {
	t.Helper()
	ctx := context.Background()
	dsn := freshDB(t)
	s, err := store.Open(ctx, store.Config{DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	w, err := s.ClaimWriter(ctx, "w0", "audit-test")
	if err != nil {
		t.Fatalf("claim writer: %v", err)
	}
	t.Cleanup(func() { _ = w.Close(context.Background()) })

	f := &auditFixture{
		t: t, dsn: dsn, store: s, writer: w,
		signer:   newSigner(t, fixtureKeyID),
		sinkPath: filepath.Join(t.TempDir(), "checkpoints.jsonl"),
	}
	f.sink, err = store.NewFileSink(f.sinkPath)
	if err != nil {
		t.Fatalf("open sink: %v", err)
	}

	t.Setenv(runtime.EnvCheckpointSinkFile, f.sinkPath)
	t.Setenv(runtime.EnvCheckpointVerifyKeys,
		fixtureKeyID+"="+writePublicKey(t, f.signer.Public()))
	t.Setenv(runtime.EnvCheckpointKeyFile, "")
	t.Setenv(runtime.EnvCheckpointKeyID, "")
	_ = os.Unsetenv(runtime.EnvCheckpointKeyFile)
	_ = os.Unsetenv(runtime.EnvCheckpointKeyID)
	return f
}

func newSigner(t *testing.T, keyID string) *store.CheckpointSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := store.NewCheckpointSigner(keyID, priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer
}

func writePublicKey(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "checkpoint.pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return path
}

func (f *auditFixture) appendN(n int) {
	f.t.Helper()
	for i := range n {
		if _, err := f.writer.Append(context.Background(), store.AuditEntry{
			Kind:    "test.event",
			Subject: fmt.Sprintf("subject-%d", i),
			Payload: map[string]any{"i": i},
		}); err != nil {
			f.t.Fatalf("append: %v", err)
		}
	}
}

// checkpoint records one under the fixture's own key.
func (f *auditFixture) checkpoint() {
	f.t.Helper()
	if _, err := f.store.Checkpointer(f.signer, f.sink).Checkpoint(context.Background()); err != nil {
		f.t.Fatalf("checkpoint: %v", err)
	}
}

// checkpointUnder records one under some other key, which is what an attacker
// holding database access and a key of their own can produce.
func (f *auditFixture) checkpointUnder(signer *store.CheckpointSigner) {
	f.t.Helper()
	if _, err := f.store.Checkpointer(signer, f.sink).Checkpoint(context.Background()); err != nil {
		f.t.Fatalf("checkpoint under %s: %v", signer.KeyID(), err)
	}
}

func (f *auditFixture) exec(sql string) {
	f.t.Helper()
	if _, err := f.store.Pool().Exec(context.Background(), sql); err != nil {
		f.t.Fatalf("exec %q: %v", sql, err)
	}
}

// verify runs the command the way a pipeline does and reports what a pipeline
// sees: the output and the exit code.
func (f *auditFixture) verify(args ...string) (string, int) {
	f.t.Helper()
	var out strings.Builder
	err := runAudit(context.Background(), append([]string{"verify", "--dsn", f.dsn}, args...), &out)
	if err == nil {
		return out.String(), 0
	}
	out.WriteString("\n" + err.Error() + "\n")
	return out.String(), exitCodeOf(err)
}

func requireCode(t *testing.T, got, want int, output string) {
	t.Helper()
	if got != want {
		t.Fatalf("exit code = %d, want %d\n%s", got, want, output)
	}
}

func requireMentions(t *testing.T, output string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(output, want) {
			t.Errorf("the output does not mention %q:\n%s", want, output)
		}
	}
}

// ---------------------------------------------------------------------------
// the verdicts
// ---------------------------------------------------------------------------

func TestAuditVerifyPassesOnACleanChain(t *testing.T) {
	f := newAuditFixture(t)
	f.appendN(6)
	f.checkpoint()
	f.appendN(3)
	f.checkpoint()

	out, code := f.verify()
	requireCode(t, code, 0, out)
	requireMentions(t, out, "no faults", "2 checkpoint(s)", fixtureKeyID)
}

// TestAuditVerifyCatchesARechainedLog is the attack the segmented chain cannot
// survive on its own: whoever can write the database can rebuild every hash, so
// the rewritten log re-chains perfectly and only the signed head disagrees.
func TestAuditVerifyCatchesARechainedLog(t *testing.T) {
	f := newAuditFixture(t)
	f.appendN(6)
	f.checkpoint()

	f.exec(`DELETE FROM audit_log`)
	if err := f.writer.ReloadHead(context.Background()); err != nil {
		t.Fatalf("reload head: %v", err)
	}
	f.appendN(6)

	out, code := f.verify()
	requireCode(t, code, exitChainBroken, out)
	requireMentions(t, out, string(store.FaultHeadMismatch), "does not agree with what was signed")
	// The re-chaining is only visible against the checkpoint: the log itself is
	// internally consistent, which is the whole reason the checkpoint exists.
	if strings.Contains(out, "chain fault(s):") {
		t.Errorf("the rewritten log reported chain faults; it should re-chain cleanly:\n%s", out)
	}
}

// TestAuditVerifyCatchesAForgedCheckpoint is the same attacker one step
// further: they hold database access and a signing key of their own, and they
// stamp their rewrite with a checkpoint under the identifier the deployment
// uses. They cannot produce the operator's signature.
func TestAuditVerifyCatchesAForgedCheckpoint(t *testing.T) {
	f := newAuditFixture(t)
	f.appendN(4)
	f.checkpointUnder(newSigner(t, fixtureKeyID))

	out, code := f.verify()
	requireCode(t, code, exitChainBroken, out)
	requireMentions(t, out, string(store.FaultCheckpointSignature))
}

// TestAuditVerifyCatchesAnEditedRow is the other half of the contract row:
// chain integrity, checked by re-chaining rather than against a checkpoint.
func TestAuditVerifyCatchesAnEditedRow(t *testing.T) {
	f := newAuditFixture(t)
	f.appendN(4)
	f.checkpoint()
	f.exec(`UPDATE audit_log SET subject = 'rewritten' WHERE seq = 2`)

	out, code := f.verify()
	requireCode(t, code, exitChainBroken, out)
	requireMentions(t, out, string(store.FaultHashMismatch))
}

// TestAuditVerifyCatchesAMissingCheckpoint covers the sink someone pruned.
func TestAuditVerifyCatchesAMissingCheckpoint(t *testing.T) {
	f := newAuditFixture(t)
	for range 3 {
		f.appendN(2)
		f.checkpoint()
	}
	raw, err := os.ReadFile(f.sinkPath)
	if err != nil {
		t.Fatalf("read sink: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("sink holds %d checkpoints, want 3", len(lines))
	}
	if err := os.WriteFile(f.sinkPath, []byte(lines[0]+"\n"+lines[2]+"\n"), 0o600); err != nil {
		t.Fatalf("rewrite sink: %v", err)
	}

	out, code := f.verify()
	requireCode(t, code, exitChainBroken, out)
	requireMentions(t, out, string(store.FaultCheckpointGap))
}

// ---------------------------------------------------------------------------
// the non-verdicts
// ---------------------------------------------------------------------------

// TestAuditVerifyWithNothingToVerifyDoesNotPass is the trap. Zero checkpoints
// produce zero faults, and a command that exits 0 there reports a deployment
// that has never anchored its audit log as a verified one.
func TestAuditVerifyWithNothingToVerifyDoesNotPass(t *testing.T) {
	f := newAuditFixture(t)
	f.appendN(5)

	out, code := f.verify()
	requireCode(t, code, exitUnverifiable, out)
	requireMentions(t, out, "nothing was verified", "not a clean audit trail")
}

// TestAuditVerifyWithAnUnknownKeyIsNotAFailure separates "I cannot check this"
// from "this is wrong". A checkpoint signed under a retired key whose public
// half nobody kept is unverifiable, and reporting it as tampering is how the
// alarm that means tampering gets ignored.
func TestAuditVerifyWithAnUnknownKeyIsNotAFailure(t *testing.T) {
	f := newAuditFixture(t)
	f.appendN(4)
	f.checkpointUnder(newSigner(t, "rotated-out-2025"))

	out, code := f.verify()
	requireCode(t, code, exitUnverifiable, out)
	requireMentions(t, out, "rotated-out-2025", runtime.EnvCheckpointVerifyKeys)
}

// TestAuditVerifyReportsFaultsEvenWhenPartOfTheSeriesIsUnverifiable: evidence
// that stands on its own is still evidence. A head that does not match what was
// signed is a fault whatever else could not be checked.
func TestAuditVerifyReportsFaultsEvenWhenPartOfTheSeriesIsUnverifiable(t *testing.T) {
	f := newAuditFixture(t)
	f.appendN(4)
	f.checkpoint()
	f.checkpointUnder(newSigner(t, "rotated-out-2025"))
	f.exec(`DELETE FROM audit_log`)
	if err := f.writer.ReloadHead(context.Background()); err != nil {
		t.Fatalf("reload head: %v", err)
	}
	f.appendN(4)

	out, code := f.verify()
	requireCode(t, code, exitChainBroken, out)
	requireMentions(t, out, string(store.FaultHeadMismatch), "rotated-out-2025")
}

func TestAuditVerifyWithoutAKeyCannotVerify(t *testing.T) {
	f := newAuditFixture(t)
	f.appendN(4)
	f.checkpoint()
	t.Setenv(runtime.EnvCheckpointVerifyKeys, "")
	_ = os.Unsetenv(runtime.EnvCheckpointVerifyKeys)

	out, code := f.verify()
	requireCode(t, code, exitUnverifiable, out)
	requireMentions(t, out, "no checkpoint verification key")
}

func TestAuditVerifyWithoutASinkCannotVerify(t *testing.T) {
	f := newAuditFixture(t)
	f.appendN(4)
	f.checkpoint()
	t.Setenv(runtime.EnvCheckpointSinkFile, "")
	_ = os.Unsetenv(runtime.EnvCheckpointSinkFile)

	out, code := f.verify()
	requireCode(t, code, exitUnverifiable, out)
	requireMentions(t, out, "no readable checkpoint sink", "agrees with itself")
}

// TestAuditVerifyWithAMissingSinkFileNamesIt keeps a mistyped path from
// reading as an empty sink, which would be a true statement about a file the
// operator never meant.
func TestAuditVerifyWithAMissingSinkFileNamesIt(t *testing.T) {
	f := newAuditFixture(t)
	f.appendN(4)
	f.checkpoint()
	absent := filepath.Join(t.TempDir(), "not-here.jsonl")

	out, code := f.verify("--sink", absent)
	requireCode(t, code, exitUnverifiable, out)
	requireMentions(t, out, "cannot be read")
	if _, err := os.Stat(absent); err == nil {
		t.Error("verification created the sink file it was pointed at")
	}
}

// ---------------------------------------------------------------------------
// usage
// ---------------------------------------------------------------------------

func TestAuditUsageIsAPlainFailure(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{nil, {"bogus"}} {
		var out strings.Builder
		err := runAudit(context.Background(), args, &out)
		if err == nil {
			t.Fatalf("stamp audit %v was accepted", args)
		}
		if code := exitCodeOf(err); code != exitFailure {
			t.Errorf("stamp audit %v exits %d, want %d: a usage error is not a verdict about the log",
				args, code, exitFailure)
		}
	}
}

func TestAuditVerifyWithoutADSNIsAUsageError(t *testing.T) {
	t.Setenv(runtime.EnvDSN, "")
	_ = os.Unsetenv(runtime.EnvDSN)
	var out strings.Builder
	err := runAudit(context.Background(), []string{"verify"}, &out)
	if err == nil {
		t.Fatal("verification without a DSN was accepted")
	}
	if code := exitCodeOf(err); code != exitFailure {
		t.Errorf("exit code = %d, want %d", code, exitFailure)
	}
}

// TestAuditExitCodesAreDistinct is the contract itself. Every outcome a
// pipeline branches on has to be a different number, and none of them may be 0.
func TestAuditExitCodesAreDistinct(t *testing.T) {
	t.Parallel()
	codes := map[int]string{
		exitFailure:      "usage",
		exitRejected:     "revision rejected",
		exitReleased:     "revision released",
		exitTimeout:      "revision timed out",
		exitChainBroken:  "chain broken",
		exitUnverifiable: "unverifiable",
	}
	if len(codes) != 6 {
		t.Fatalf("two outcomes share an exit code: %v", codes)
	}
	for code := range codes {
		if code == 0 {
			t.Errorf("%s exits 0, which is the code for a verified audit trail", codes[code])
		}
	}
}
