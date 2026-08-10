package runtime

// checkpoint_test.go covers the three things this wiring has to get right: that
// a signing key can only arrive as a file (R42), that exactly one role records
// checkpoints, and that a deployment which configured none is told so in terms
// that cannot be read as a setting.
//
// The library behaviour underneath — what a re-chained log, a truncated one, a
// missing checkpoint and a forged signature each produce — is store's, and is
// tested there against a real database. What is tested here is the wiring.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/store"
)

// ---------------------------------------------------------------------------
// key material fixtures
// ---------------------------------------------------------------------------

// writeSigningKey writes a PEM PKCS#8 Ed25519 key and returns its path and its
// private half, so a test can assert that the half it wrote never comes back
// out anywhere else.
func writeSigningKey(t *testing.T) (path string, priv ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	path = filepath.Join(t.TempDir(), "checkpoint.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path, priv
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

// ---------------------------------------------------------------------------
// R42: the key is a file, and only a file
// ---------------------------------------------------------------------------

// TestCheckpointConfigHasNowhereToPutAKey is the structural half of R42. The
// requirement is not "we happen to read the key from a file"; it is that there
// is no other way in. A field of any byte-shaped type would be one, because the
// next reader of this struct would fill it from the environment.
func TestCheckpointConfigHasNowhereToPutAKey(t *testing.T) {
	typ := reflect.TypeOf(CheckpointConfig{})
	allowed := map[reflect.Type]bool{
		reflect.TypeOf(""):                     true,
		reflect.TypeOf(map[string]string(nil)): true,
		reflect.TypeOf(time.Duration(0)):       true,
	}
	for i := range typ.NumField() {
		field := typ.Field(i)
		if !allowed[field.Type] {
			t.Errorf("CheckpointConfig.%s is a %s: a signing key could be written into it, and R42 says "+
				"the key arrives as a mounted file and never as a value", field.Name, field.Type)
		}
	}
	// The names an operator can set. None of them takes key material, and the
	// list is asserted rather than described so that adding one is a decision
	// somebody makes on purpose.
	for _, name := range []string{
		EnvCheckpointKeyFile, EnvCheckpointKeyID, EnvCheckpointVerifyKeys,
		EnvCheckpointSinkFile, EnvCheckpointSinkWebhook, EnvCheckpointInterval,
	} {
		if !strings.HasPrefix(name, "STAMP_AUDIT_CHECKPOINT_") {
			t.Errorf("%q is not on the audit checkpoint surface", name)
		}
	}
	if EnvCheckpointKeyFile != "STAMP_AUDIT_CHECKPOINT_KEY_FILE" {
		t.Errorf("the signing key variable is %q: it names a file, and renaming it to something that "+
			"reads like a value is how a key ends up in a manifest", EnvCheckpointKeyFile)
	}
}

func TestCheckpointConfigFromEnvReadsTheCheckpointSurfaceAlone(t *testing.T) {
	clearCheckpointEnv(t)
	keyPath, _ := writeSigningKey(t)
	t.Setenv(EnvCheckpointKeyFile, keyPath)
	t.Setenv(EnvCheckpointKeyID, "audit-2026-08")
	t.Setenv(EnvCheckpointSinkFile, "/var/lib/stamp/checkpoints.jsonl")
	t.Setenv(EnvCheckpointVerifyKeys, "audit-2025-01=/keys/old.pub, audit-2025-07=/keys/older.pub")
	t.Setenv(EnvCheckpointInterval, "90s")

	cfg, err := CheckpointConfigFromEnv()
	if err != nil {
		t.Fatalf("CheckpointConfigFromEnv: %v", err)
	}
	if cfg.KeyFile != keyPath || cfg.KeyID != "audit-2026-08" {
		t.Errorf("key = %q/%q, want %q/audit-2026-08", cfg.KeyFile, cfg.KeyID, keyPath)
	}
	if cfg.Interval != 90*time.Second {
		t.Errorf("interval = %s, want 90s", cfg.Interval)
	}
	if len(cfg.VerifyKeys) != 2 || cfg.VerifyKeys["audit-2025-01"] != "/keys/old.pub" {
		t.Errorf("verify keys = %v", cfg.VerifyKeys)
	}
	// No DSN, no issuer, no audience: an auditor with a public key and a
	// read-only replica has to be able to run the verification command.
	if _, err := CheckpointConfigFromEnv(); err != nil {
		t.Errorf("reading the checkpoint surface required the rest of the deployment surface: %v", err)
	}
}

func TestCheckpointVerifyKeysRefuseAnUnreadableList(t *testing.T) {
	clearCheckpointEnv(t)
	for _, spec := range []string{"just-an-id", "=/keys/one.pub", "id=", "a=/one.pub,a=/two.pub"} {
		if _, err := checkpointVerifyKeysFrom(spec); err == nil {
			t.Errorf("%q was accepted, want a refusal", spec)
		}
	}
}

// TestCheckpointSignerComesFromTheFileAndTheErrorsCarryNoKey covers the other
// half of R42: the loader's failures name the path and never the contents,
// because the place those failures are read is a container log.
func TestCheckpointSignerComesFromTheFileAndTheErrorsCarryNoKey(t *testing.T) {
	keyPath, priv := writeSigningKey(t)
	signer, err := LoadCheckpointSigner(CheckpointConfig{KeyFile: keyPath, KeyID: "k1"})
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}
	if signer.KeyID() != "k1" {
		t.Errorf("key id = %q, want k1", signer.KeyID())
	}
	if !signer.Public().Equal(priv.Public()) {
		t.Error("the loaded signer does not hold the key that was written")
	}
	// A rendered signer is an identifier and nothing else. Without this, one
	// `%v` in a log line prints the seed.
	if rendered := fmt.Sprintf("%v", signer); rendered != `store.CheckpointSigner{key_id="k1"}` {
		t.Errorf("a rendered signer is %q, want it to carry the identifier and nothing else", rendered)
	}

	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.key")
	if err := os.WriteFile(garbage, priv, 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal rsa key: %v", err)
	}
	wrongKind := filepath.Join(dir, "rsa.key")
	if err := os.WriteFile(wrongKind, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}), 0o600); err != nil {
		t.Fatalf("write rsa key: %v", err)
	}

	for _, tc := range []struct{ name, path, want string }{
		{"raw bytes are not a key file", garbage, "is not PEM"},
		{"the wrong algorithm is refused", wrongKind, "Ed25519"},
		{"a missing file names itself", filepath.Join(dir, "absent.key"), "no such file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadCheckpointSigner(CheckpointConfig{KeyFile: tc.path, KeyID: "k1"})
			if err == nil {
				t.Fatalf("%s was accepted as a signing key", tc.path)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
			assertNoKeyMaterial(t, err.Error(), priv)
		})
	}

	if _, err := LoadCheckpointSigner(CheckpointConfig{KeyFile: keyPath}); err == nil {
		t.Error("a signing key with no identifier was accepted; rotation needs one")
	}
}

func TestCheckpointVerificationDerivesTheActiveKeyAndKeepsRetiredOnes(t *testing.T) {
	keyPath, priv := writeSigningKey(t)
	retiredPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate retired key: %v", err)
	}
	retiredPath := writePublicKey(t, retiredPub)

	cfg := CheckpointConfig{
		KeyFile:    keyPath,
		KeyID:      "audit-2026-08",
		VerifyKeys: map[string]string{"audit-2025-01": retiredPath},
	}
	keys, err := LoadCheckpointVerification(cfg)
	if err != nil {
		t.Fatalf("load verification: %v", err)
	}
	// A rotation is a new key file plus the retired public half: the old
	// checkpoints stay verifiable and nothing is re-signed.
	for _, id := range []string{"audit-2025-01", "audit-2026-08"} {
		if !keys.Covers(id) {
			t.Errorf("key id %q is not covered; keys = %v", id, keys.KeyIDs)
		}
	}
	if keys.Covers("never-configured") {
		t.Error("an unconfigured key id is reported as covered")
	}

	// An auditor with no signing key at all verifies from public halves alone.
	activePub := writePublicKey(t, priv.Public().(ed25519.PublicKey))
	auditor, err := LoadCheckpointVerification(CheckpointConfig{
		VerifyKeys: map[string]string{"audit-2026-08": activePub},
	})
	if err != nil {
		t.Fatalf("load auditor verification: %v", err)
	}
	if !auditor.Covers("audit-2026-08") || len(auditor.KeyIDs) != 1 {
		t.Errorf("an auditor's key set = %v, want the one public key", auditor.KeyIDs)
	}

	// Two answers for the active identifier is a rotation nobody can read.
	cfg.VerifyKeys = map[string]string{"audit-2026-08": activePub}
	if _, err := LoadCheckpointVerification(cfg); err == nil {
		t.Error("a public key declared for the active signing key's identifier was accepted")
	}
}

func TestCheckpointConfigRefusesAHalfConfiguredSubsystem(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  CheckpointConfig
		want string
	}{
		{
			name: "a sink with no key receives nothing",
			cfg:  CheckpointConfig{SinkFile: "/var/lib/stamp/checkpoints.jsonl"},
			want: EnvCheckpointKeyFile,
		},
		{
			name: "a key with no sink never leaves the database",
			cfg:  CheckpointConfig{KeyFile: "/keys/checkpoint.key", KeyID: "k1"},
			want: EnvCheckpointSinkFile,
		},
		{
			name: "a key with no identifier cannot be rotated",
			cfg:  CheckpointConfig{KeyFile: "/keys/checkpoint.key", SinkFile: "/var/lib/stamp/c.jsonl"},
			want: EnvCheckpointKeyID,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := tc.cfg.validate()
			if len(errs) == 0 {
				t.Fatalf("%+v started, want a boot failure", tc.cfg)
			}
			if !strings.Contains(errors.Join(errs...).Error(), tc.want) {
				t.Errorf("the refusal does not name %s: %v", tc.want, errors.Join(errs...))
			}
		})
	}
	// Configuring nothing is not half-configured: it is the unconfigured
	// deployment, which warns and starts.
	if errs := (CheckpointConfig{}).validate(); len(errs) != 0 {
		t.Errorf("an unconfigured deployment was refused: %v", errors.Join(errs...))
	}
}

// ---------------------------------------------------------------------------
// the wiring, against a real database
// ---------------------------------------------------------------------------

// checkpointApp assembles a process with the given roles and checkpoint
// configuration, and returns it with whatever it logged on the way up.
func checkpointApp(t *testing.T, roleSpec string, cp CheckpointConfig,
	mutators ...func(*Config),
) (*App, *bytes.Buffer, context.CancelFunc) {
	t.Helper()
	idp := newMockIdP(t)
	cfg := Config{
		DSN:             freshDB(t),
		MaxConns:        8,
		Migrate:         true,
		InstanceID:      "checkpoint-test",
		WriterID:        "checkpoint-test",
		Addresses:       map[api.Surface]string{api.SurfacePEP: "127.0.0.1:0"},
		Checkpoint:      cp,
		AuditFailClosed: true,
		OIDC: OIDCConfig{
			Issuers:                []IssuerConfig{{Issuer: idp.server.URL, JWKSURL: idp.server.URL + "/jwks"}},
			Audience:               testAudience,
			Algorithms:             []string{"RS256"},
			AllowInsecureTransport: true,
		},
	}
	for _, mutate := range mutators {
		mutate(&cfg)
	}
	roles, err := ParseRoles(roleSpec)
	if err != nil {
		t.Fatalf("parse roles %q: %v", roleSpec, err)
	}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))

	ctx, cancel := context.WithCancel(context.Background())
	app, err := Assemble(ctx, cfg, roles, logger)
	if err != nil {
		cancel()
		t.Fatalf("assemble with --roles=%s: %v", roleSpec, err)
	}
	t.Cleanup(func() { cancel(); app.Close() })
	return app, logs, cancel
}

// TestCheckpointsAreRecordedByTheAPIRoleAlone pins the role decision. One
// checkpoint binds every writer's head, so the series wants one producer and
// not one per replica of the tier that scales.
func TestCheckpointsAreRecordedByTheAPIRoleAlone(t *testing.T) {
	keyPath, _ := writeSigningKey(t)
	sinkPath := filepath.Join(t.TempDir(), "checkpoints.jsonl")
	cp := CheckpointConfig{KeyFile: keyPath, KeyID: "k1", SinkFile: sinkPath, Interval: time.Hour}

	for _, tc := range []struct {
		roles string
		want  bool
	}{
		{roles: "api", want: true},
		{roles: "all", want: true},
		{roles: "check", want: false},
		{roles: "decide", want: false},
		{roles: "consumer", want: false},
		{roles: "console", want: false},
		{roles: "check,decide,consumer,console", want: false},
	} {
		t.Run(tc.roles, func(t *testing.T) {
			app, logs, _ := checkpointApp(t, tc.roles, cp)
			if got := hasComponent(app, "audit-checkpointer"); got != tc.want {
				t.Errorf("--roles=%s runs the checkpointer = %v, want %v (components: %v)",
					tc.roles, got, tc.want, app.Components())
			}
			// A process that does not record them says so once, so that its log
			// cannot be read as "this deployment takes none".
			said := strings.Contains(logs.String(), "recorded by the api role")
			if said == tc.want {
				t.Errorf("--roles=%s: the note about which role records checkpoints was %v", tc.roles, said)
			}
		})
	}
}

// TestUnconfiguredCheckpointsWarnAndCannotBeReadAsASetting is U18's scenario,
// and the wording is half of it: a deployment with no checkpoints has to be
// told it is missing a control, not told about a knob it left at a default.
func TestUnconfiguredCheckpointsWarnAndCannotBeReadAsASetting(t *testing.T) {
	app, logs, _ := checkpointApp(t, "all", CheckpointConfig{})
	if hasComponent(app, "audit-checkpointer") {
		t.Error("a deployment with no checkpoint configuration registered the checkpointer")
	}

	warning := findLogLine(t, logs, slog.LevelWarn, "audit checkpoints are not configured")
	if warning == nil {
		t.Fatalf("no warning about the missing checkpoint sink:\n%s", logs.String())
	}
	// It says what is lost, not merely that a variable is unset.
	for _, want := range []string{"rewrite", "stamp audit verify"} {
		if !strings.Contains(fmt.Sprint(warning["effect"]), want) {
			t.Errorf("the warning does not say %q is affected: %v", want, warning)
		}
	}
	// And it forecloses the reading that this is a relaxed setting.
	statement := fmt.Sprint(warning["this_is_not_a_setting"])
	for _, want := range []string{"absent rather than relaxed", "no other", "compensates"} {
		if !strings.Contains(statement, want) {
			t.Errorf("the warning can be read as a permissive setting; it says %q", statement)
		}
	}
	if !strings.Contains(fmt.Sprint(warning["configure"]), EnvCheckpointSinkFile) {
		t.Errorf("the warning does not name the variable to set: %v", warning)
	}
}

// TestConfiguredCheckpointsAreSignedIntoTheSink is the other half of U18's
// scenario, end to end through the composition root: a configured deployment
// writes signed checkpoints to its sink, and its logs name the key and never
// carry it.
func TestConfiguredCheckpointsAreSignedIntoTheSink(t *testing.T) {
	keyPath, priv := writeSigningKey(t)
	sinkPath := filepath.Join(t.TempDir(), "checkpoints.jsonl")
	app, logs, cancel := checkpointApp(t, "api", CheckpointConfig{
		KeyFile: keyPath, KeyID: "audit-2026-08", SinkFile: sinkPath, Interval: 50 * time.Millisecond,
	})

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan error, 1)
	if err := app.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { done <- app.Serve(ctx) }()

	sink, err := store.NewFileSink(sinkPath)
	if err != nil {
		t.Fatalf("open sink: %v", err)
	}
	var held []store.Checkpoint
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		held, err = sink.Checkpoints(context.Background())
		if err != nil {
			t.Fatalf("read sink: %v", err)
		}
		if len(held) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(held) == 0 {
		t.Fatalf("no checkpoint reached %s within the deadline:\n%s", sinkPath, logs.String())
	}

	verifier := store.NewCheckpointVerifier(map[string]ed25519.PublicKey{
		"audit-2026-08": priv.Public().(ed25519.PublicKey),
	})
	if err := verifier.Verify(held[0]); err != nil {
		t.Fatalf("the checkpoint in the sink does not verify under the configured key: %v", err)
	}
	if held[0].KeyID != "audit-2026-08" {
		t.Errorf("checkpoint key id = %q, want the configured identifier", held[0].KeyID)
	}

	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve returned %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the process did not stop within 20s of cancellation")
	}
	cancel()

	// R42's log half, against everything this process wrote on the way up and
	// while running.
	if !strings.Contains(logs.String(), "audit-2026-08") {
		t.Errorf("the logs never name the signing key's identifier:\n%s", logs.String())
	}
	assertNoKeyMaterial(t, logs.String(), priv)
}

// TestWebhookSinkDeliversAlongsideTheFile covers the optional half of R32's
// sink: an additional destination, reached through the same egress gate as
// every other outbound call, and never instead of the file.
func TestWebhookSinkDeliversAlongsideTheFile(t *testing.T) {
	delivered := make(chan store.Checkpoint, 4)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var cp store.Checkpoint
		if err := json.NewDecoder(r.Body).Decode(&cp); err != nil {
			t.Errorf("decode the delivered checkpoint: %v", err)
		}
		select {
		case delivered <- cp:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(receiver.Close)

	keyPath, priv := writeSigningKey(t)
	sinkPath := filepath.Join(t.TempDir(), "checkpoints.jsonl")
	app, logs, _ := checkpointApp(t, "api", CheckpointConfig{
		KeyFile: keyPath, KeyID: "k1", SinkFile: sinkPath,
		SinkWebhook: receiver.URL, Interval: 50 * time.Millisecond,
	}, func(cfg *Config) {
		cfg.Egress = fact.EgressConfig{Allow: []string{receiver.URL}, AllowLoopback: true}
	})

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	if err := app.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx) }()

	select {
	case cp := <-delivered:
		if err := store.NewCheckpointVerifier(map[string]ed25519.PublicKey{
			"k1": priv.Public().(ed25519.PublicKey),
		}).Verify(cp); err != nil {
			t.Errorf("the delivered checkpoint does not verify: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("no checkpoint was delivered to the webhook:\n%s", logs.String())
	}
	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve returned %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the process did not stop within 20s of cancellation")
	}

	// The file still holds it: a webhook is an addition, and the readable copy
	// is the one verification exists for.
	sink, err := store.NewFileSink(sinkPath)
	if err != nil {
		t.Fatalf("open sink: %v", err)
	}
	held, err := sink.Checkpoints(context.Background())
	if err != nil {
		t.Fatalf("read sink: %v", err)
	}
	if len(held) == 0 {
		t.Error("the file sink holds nothing while the webhook was delivered to")
	}
}

// TestWebhookOnlySinkSaysItCannotBeVerifiedAgainst: delivery is not
// verification. A deployment whose only sink is write-only has checkpoints and
// no way to run `stamp audit verify` against them.
func TestWebhookOnlySinkSaysItCannotBeVerifiedAgainst(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(receiver.Close)

	keyPath, _ := writeSigningKey(t)
	app, logs, _ := checkpointApp(t, "api", CheckpointConfig{
		KeyFile: keyPath, KeyID: "k1", SinkWebhook: receiver.URL, Interval: time.Hour,
	}, func(cfg *Config) {
		cfg.Egress = fact.EgressConfig{Allow: []string{receiver.URL}, AllowLoopback: true}
	})
	if !hasComponent(app, "audit-checkpointer") {
		t.Error("a webhook-only deployment does not record checkpoints at all")
	}
	warning := findLogLine(t, logs, slog.LevelWarn, "the only audit checkpoint sink is a webhook")
	if warning == nil {
		t.Fatalf("no warning that the sink cannot be read back:\n%s", logs.String())
	}
	if !strings.Contains(fmt.Sprint(warning["effect"]), "cannot verify") {
		t.Errorf("the warning does not say what is lost: %v", warning)
	}
}

// TestAnUnreachableWebhookIsRefusedAtStartup keeps the checkpoint destination
// inside the same egress rules as every other outbound call.
func TestAnUnreachableWebhookIsRefusedAtStartup(t *testing.T) {
	keyPath, _ := writeSigningKey(t)
	idp := newMockIdP(t)
	roles, err := ParseRoles("api")
	if err != nil {
		t.Fatalf("parse roles: %v", err)
	}
	_, err = Assemble(context.Background(), Config{
		DSN: freshDB(t), MaxConns: 8, Migrate: true,
		InstanceID: "checkpoint-egress", WriterID: "checkpoint-egress",
		Addresses: map[api.Surface]string{api.SurfacePEP: "127.0.0.1:0"},
		Checkpoint: CheckpointConfig{
			KeyFile: keyPath, KeyID: "k1", SinkWebhook: "https://sink.invalid/checkpoints",
		},
		OIDC: OIDCConfig{
			Issuers:                []IssuerConfig{{Issuer: idp.server.URL, JWKSURL: idp.server.URL + "/jwks"}},
			Audience:               testAudience,
			Algorithms:             []string{"RS256"},
			AllowInsecureTransport: true,
		},
	}, roles, nil)
	if err == nil {
		t.Fatal("a checkpoint webhook outside the egress allowlist was accepted")
	}
	if !strings.Contains(err.Error(), EnvCheckpointSinkWebhook) {
		t.Errorf("the refusal does not name the variable: %v", err)
	}
}

// assertNoKeyMaterial fails if any encoding of the private key appears in text.
func assertNoKeyMaterial(t *testing.T, text string, priv ed25519.PrivateKey) {
	t.Helper()
	raw, seed := []byte(priv), priv.Seed()
	for _, encoded := range []string{
		hex.EncodeToString(raw),
		hex.EncodeToString(seed),
		base64.StdEncoding.EncodeToString(raw),
		base64.StdEncoding.EncodeToString(seed),
		string(raw),
		string(seed),
		// The rendering a stray `%v` over the key would produce.
		fmt.Sprintf("%v", raw),
		fmt.Sprintf("%v", seed),
	} {
		if strings.Contains(text, encoded) {
			t.Fatalf("key material appears in %d bytes of output", len(text))
		}
	}
}

func hasComponent(app *App, name string) bool {
	for _, c := range app.Components() {
		if c == name {
			return true
		}
	}
	return false
}

// findLogLine returns the first JSON log record at the given level whose
// message starts with prefix.
func findLogLine(t *testing.T, logs *bytes.Buffer, level slog.Level, prefix string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		msg, _ := record["msg"].(string)
		if record["level"] == level.String() && strings.HasPrefix(msg, prefix) {
			return record
		}
	}
	return nil
}

// clearCheckpointEnv unsets the checkpoint surface so a test starts from a
// known environment rather than from the developer's shell.
func clearCheckpointEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		EnvCheckpointKeyFile, EnvCheckpointKeyID, EnvCheckpointVerifyKeys,
		EnvCheckpointSinkFile, EnvCheckpointSinkWebhook, EnvCheckpointInterval,
	} {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}
}
