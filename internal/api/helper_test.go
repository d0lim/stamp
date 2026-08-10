package api_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// These tests never reach the network and never reach a database. The identity
// boundary is exercised against a mock IdP because R40 is about a real
// credential check running before evaluation, and the audit chain is exercised
// against a recording writer because what this unit owns is what reaches the
// chain, not how the chain is stored.

const (
	testAudience = "stamp"
	testClientID = "pep-1"
	testKeyID    = "test-key"
)

// testKey is generated once. RSA key generation otherwise dominates this
// package's test time.
var testKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

// mockIdP publishes one signing key and mints tokens for it.
type mockIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
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

// token mints a signed token. clientID decides whether the middleware sees a
// workload or an end user, because that split is operator configuration rather
// than anything inside the token.
func (m *mockIdP) token(t *testing.T, subject, clientID string) string {
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

// spySink records every authentication attempt and forwards it to the buffer,
// so a test can read the caller identifier that reached the audit path without
// the buffer having to expose its queue.
type spySink struct {
	inner identity.AuditSink

	mu      sync.Mutex
	records []identity.AuthRecord
}

func (s *spySink) RecordAuth(ctx context.Context, rec identity.AuthRecord) {
	s.mu.Lock()
	s.records = append(s.records, rec)
	s.mu.Unlock()
	s.inner.RecordAuth(ctx, rec)
}

func (s *spySink) all() []identity.AuthRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]identity.AuthRecord(nil), s.records...)
}

func (m *mockIdP) middleware(t *testing.T, sink identity.AuditSink, now func() time.Time) *identity.Middleware {
	t.Helper()
	verifier, err := identity.New(t.Context(), identity.Config{
		Issuers: []identity.IssuerConfig{{
			Issuer:          m.server.URL,
			JWKSURL:         m.server.URL + "/jwks",
			WorkloadClients: []string{testClientID},
		}},
		Audience:               testAudience,
		Algorithms:             []string{"RS256"},
		AllowInsecureTransport: true,
	})
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}
	mw, err := identity.NewMiddleware(identity.MiddlewareConfig{Verifier: verifier, Audit: sink, Now: now})
	if err != nil {
		t.Fatalf("build middleware: %v", err)
	}
	return mw
}

// recordingWriter is the audit chain, reduced to what this unit writes into it.
type recordingWriter struct {
	mu       sync.Mutex
	batches  []store.CheckBatch
	gaps     []store.CheckGap
	failNext atomic.Bool
}

func (w *recordingWriter) AppendCheckBatch(_ context.Context, b store.CheckBatch) (store.AuditRecord, error) {
	if w.failNext.Load() {
		return store.AuditRecord{}, io.ErrClosedPipe
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.batches = append(w.batches, b)
	return store.AuditRecord{Kind: store.AuditKindCheckBatch, Seq: int64(len(w.batches))}, nil
}

func (w *recordingWriter) AppendCheckGap(_ context.Context, g store.CheckGap) (store.AuditRecord, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.gaps = append(w.gaps, g)
	return store.AuditRecord{Kind: store.AuditKindCheckGap, Seq: int64(len(w.gaps))}, nil
}

func (w *recordingWriter) snapshot() ([]store.CheckBatch, []store.CheckGap) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]store.CheckBatch(nil), w.batches...), append([]store.CheckGap(nil), w.gaps...)
}

// loadSet parses a policy set from the exchange format, failing the test on any
// diagnostic. Each call parses its own copy: normalization rewrites the
// condition tree in place, so two sets must never share one.
func loadSet(t *testing.T, documents string) *policy.Set {
	t.Helper()
	set, err := policy.Load(strings.NewReader(documents))
	if err != nil {
		t.Fatalf("load policy set: %v", err)
	}
	return set
}

// snapshotOf builds an evaluable snapshot, versioning every policy with the
// given revision so a test can swap versions by swapping the string.
//
// The version identifier carries the policy identifier as well as the revision.
// The compile cache is keyed by (schema version, policy version) and nothing
// else, so two policies sharing one revision string would share one compiled
// program — a wrong decision rather than a slow one. Whatever the store's
// revision numbering is, it has to be made unique per policy here.
func snapshotOf(t *testing.T, set *policy.Set, revision string) *engine.Snapshot {
	t.Helper()
	versions := make([]engine.PolicyVersion, len(set.Policies))
	for i := range set.Policies {
		versions[i] = engine.PolicyVersion{
			Version: set.Policies[i].ID + "@" + revision,
			Policy:  set.Policies[i],
		}
	}
	snap, err := engine.NewSnapshot(revision, set.Schema, versions)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	return snap
}

// staticLoader serves one snapshot forever.
func staticLoader(snap *engine.Snapshot, revision string) engine.SnapshotLoader {
	return engine.SnapshotLoaderFunc(func(context.Context) (*engine.Snapshot, engine.Revision, error) {
		return snap, engine.Revision(revision), nil
	})
}

// fixture is a fully wired PEP and console surface over an in-memory policy
// set.
type fixture struct {
	server  *api.Server
	service *engine.CheckService
	buffer  *api.AuditBuffer
	writer  *recordingWriter
	auth    *spySink
	idp     *mockIdP
	now     time.Time
}

type fixtureOptions struct {
	documents  string
	loader     engine.SnapshotLoader
	resolver   engine.SourceResolver
	aliases    map[string]string
	failClosed bool
	capacity   int
	batchSize  int
	revision   string
}

// fixedNow is the instant every fixture's clock reports. A fixed clock is what
// lets a test recompute an audit leaf exactly rather than assert on a count.
var fixedNow = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

func newFixture(t *testing.T, opts fixtureOptions) *fixture {
	t.Helper()
	if opts.revision == "" {
		opts.revision = "rev-1"
	}
	loader := opts.loader
	if loader == nil {
		loader = staticLoader(snapshotOf(t, loadSet(t, opts.documents), opts.revision), opts.revision)
	}
	service, err := engine.NewCheckService(t.Context(), engine.CheckConfig{
		Loader:   loader,
		Resolver: opts.resolver,
	})
	if err != nil {
		t.Fatalf("build check service: %v", err)
	}

	now := func() time.Time { return fixedNow }
	writer := &recordingWriter{}
	buffer, err := api.NewAuditBuffer(api.AuditConfig{
		Writer:     writer,
		Capacity:   opts.capacity,
		BatchSize:  opts.batchSize,
		FailClosed: opts.failClosed,
		Now:        now,
	})
	if err != nil {
		t.Fatalf("build audit buffer: %v", err)
	}

	auth := &spySink{inner: buffer}
	idp := newMockIdP(t)
	server, err := api.New(api.Config{
		Identity: idp.middleware(t, auth, now),
		// Two surfaces are bound and the third is not, so a test can assert
		// both that a bound surface refuses another's paths and that an
		// unconfigured surface is not reachable at all.
		Addresses: map[api.Surface]string{
			api.SurfacePEP:     "127.0.0.1:0",
			api.SurfaceConsole: "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	checkAPI, err := api.NewCheckAPI(api.CheckAPIConfig{
		Service:         service,
		Audit:           buffer,
		PropertyAliases: opts.aliases,
		Now:             now,
	})
	if err != nil {
		t.Fatalf("build check api: %v", err)
	}
	dryRunAPI, err := api.NewDryRunAPI(api.DryRunAPIConfig{Service: service})
	if err != nil {
		t.Fatalf("build dry run api: %v", err)
	}
	if err := server.Mount(checkAPI, dryRunAPI); err != nil {
		t.Fatalf("mount: %v", err)
	}
	return &fixture{
		server:  server,
		service: service,
		buffer:  buffer,
		writer:  writer,
		auth:    auth,
		idp:     idp,
		now:     fixedNow,
	}
}

// evaluate posts an AuthZEN request to the PEP surface as an authenticated
// workload.
func (f *fixture) evaluate(t *testing.T, body string) (int, api.EvaluationResponse) {
	t.Helper()
	return f.evaluateAs(t, body, f.idp.token(t, "svc-a", testClientID))
}

func (f *fixture) evaluateAs(t *testing.T, body, token string) (int, api.EvaluationResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, api.EvaluationPath, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.server.Handler(api.SurfacePEP).ServeHTTP(rec, req)

	var resp api.EvaluationResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, resp
}

func (f *fixture) reasonOf(t *testing.T, resp api.EvaluationResponse) string {
	t.Helper()
	reason, ok := resp.Context[api.ContextKeyReason].(string)
	if !ok {
		t.Fatalf("response context carries no %s: %#v", api.ContextKeyReason, resp.Context)
	}
	return reason
}
