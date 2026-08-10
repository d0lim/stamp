package challenge_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// The quorum tests run against a real Postgres and against real tokens.
//
// The database is not a detail here: "a duplicate approval counts once" is a
// unique constraint, and a fake store asserting it would be asserting that the
// fake behaves. The tokens are not a detail either: claim-based target
// resolution reads the verified claims of an identity.Subject, and a Subject
// carries them only when a verifier put them there.

const postgresImage = "postgres:17-alpine"

// postgresDSN starts the container on first use, so the tests in this package
// that need no database — the contract tests, and the hash tests — still run
// without a Docker daemon.
var postgresDSN = sync.OnceValues(func() (string, error) {
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase("stamp"),
		tcpostgres.WithUsername("stamp"),
		tcpostgres.WithPassword("stamp"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		return "", fmt.Errorf("the quorum tests need a working Docker daemon: %w", err)
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

// testMaxConns sizes every pool. A claimed audit writer pins one connection for
// its whole life, so leaving this to the pgxpool default makes a multi-writer
// test pass or hang depending on the machine's core count.
const testMaxConns = 24

func freshDB(t *testing.T) string {
	t.Helper()
	adminDSN, err := postgresDSN()
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	name := fmt.Sprintf("d%d_%d", time.Now().UnixNano()%1e9, dbSerial.Add(1))

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

// openStore returns a migrated store on a database of its own.
func openStore(t *testing.T, now func() time.Time) *store.Store {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, store.Config{DSN: freshDB(t), MaxConns: testMaxConns, Now: now})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
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

// seedPolicy writes a schema and one policy so that a decision row has the
// (policy_id, version) pair its foreign key demands. The policy's own content
// is not what these tests are about — the challenge specification under test is
// handed to Issue directly, exactly as the evaluator hands one over.
func seedPolicy(t *testing.T, s *store.Store, id string) int64 {
	t.Helper()
	ctx := context.Background()
	schema := &policy.Schema{
		Entities: []policy.EntityType{
			{Name: "user", Attributes: []policy.Attribute{{Name: "role", Type: policy.TypeString}}},
			{Name: "account", Attributes: []policy.Attribute{{Name: "tier", Type: policy.TypeString}}},
		},
		Actions: []policy.Action{{Name: "transfer"}},
	}
	schemaRec, err := store.PutSchema(ctx, s.Pool(), schema, store.OriginForm, "tester")
	if err != nil {
		t.Fatalf("put schema: %v", err)
	}
	rec, err := store.PutPolicy(ctx, s.Pool(), store.PolicyInput{
		Policy: &policy.Policy{
			ID:       id,
			Subject:  "user",
			Resource: "account",
			Actions:  []string{"transfer"},
			Condition: policy.Compare{
				Op:    policy.OpEq,
				Left:  policy.Field(policy.RoleSubject, "role"),
				Right: policy.String("admin"),
			},
			Challenges: []policy.Challenge{
				policy.Quorum{Threshold: 1, Approvers: policy.ApproverSet{Members: []string{"bob"}}},
			},
		},
		SchemaVersion: schemaRec.Version,
		Origin:        store.OriginForm,
		Author:        "tester",
	})
	if err != nil {
		t.Fatalf("put policy %s: %v", id, err)
	}
	return rec.Version
}

// ---------------------------------------------------------------------------
// identities
// ---------------------------------------------------------------------------

const (
	testAudience    = "stamp"
	testKeyID       = "test-key"
	testConsoleApp  = "console"
	testWorkloadApp = "pep-1"
)

// testKey is generated once: RSA key generation would otherwise dominate this
// package's test time.
var testKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

// mockIdP publishes one signing key and mints tokens for it. It exists so that
// the approver identities these tests use are the ones a verifier produced, not
// structs a test filled in — the claims a Subject carries are unexported, and
// that is the point.
type mockIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey

	once   sync.Once
	cached *identity.Verifier
}

func newMockIdP(t *testing.T) *mockIdP {
	t.Helper()
	m := &mockIdP{key: testKey()}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"kid": testKeyID,
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(m.key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(m.key.E)).Bytes()),
		}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockIdP) token(t *testing.T, subject, clientID string, extra map[string]any) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": m.server.URL,
		"sub": subject,
		"aud": testAudience,
		"azp": clientID,
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	header := map[string]string{"alg": "RS256", "kid": testKeyID, "typ": "JWT"}
	encode := func(v any) string {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal token part: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	signing := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (m *mockIdP) verifier(t *testing.T) *identity.Verifier {
	t.Helper()
	v, err := identity.New(t.Context(), identity.Config{
		Issuers: []identity.IssuerConfig{{
			Issuer:          m.server.URL,
			JWKSURL:         m.server.URL + "/jwks",
			WorkloadClients: []string{testWorkloadApp},
		}},
		Audience:               testAudience,
		Algorithms:             []string{"RS256"},
		AllowInsecureTransport: true,
	})
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}
	return v
}

// user mints and verifies an end-user token, returning the Subject a request
// would have carried.
// issuer is the `iss` this mock signs under. A handler that has to be told
// which IdP its approvers live in is told this.
func (m *mockIdP) issuer() string { return m.server.URL }

// testApproverIssuer designates an approver issuer for the tests that never
// present a credential, where any non-empty designation does.
const testApproverIssuer = "https://idp.test"

func (m *mockIdP) user(t *testing.T, subject string, extra map[string]any) *identity.Subject {
	t.Helper()
	return m.subject(t, subject, testConsoleApp, extra)
}

// workload is the same for a machine credential: a client the operator declared
// as a workload client.
func (m *mockIdP) workload(t *testing.T, subject string) *identity.Subject {
	t.Helper()
	return m.subject(t, subject, testWorkloadApp, nil)
}

func (m *mockIdP) subject(t *testing.T, subject, clientID string, extra map[string]any) *identity.Subject {
	t.Helper()
	v := m.verifierOnce(t)
	s, err := v.Verify(t.Context(), m.token(t, subject, clientID, extra))
	if err != nil {
		t.Fatalf("verify token for %s: %v", subject, err)
	}
	return s
}

// verifierOnce keeps one verifier per IdP so that the key set is fetched once.
func (m *mockIdP) verifierOnce(t *testing.T) *identity.Verifier {
	t.Helper()
	m.once.Do(func() { m.cached = m.verifier(t) })
	return m.cached
}
