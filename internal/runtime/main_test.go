package runtime

// main_test.go is the end-to-end harness: a real Postgres, a real OIDC issuer,
// a real fact source over a real socket, and the assembled process serving its
// real listeners.
//
// Nothing here is a double. The exit condition of this milestone is that the
// eleven units run together, and every fake in this file would be a place where
// they did not have to.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/challenge/mfa"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

const postgresImage = "postgres:17-alpine"

// postgresDSN starts the container on first use, so the registry tests in this
// package still run without a Docker daemon.
var postgresDSN = sync.OnceValues(func() (string, error) {
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase("stamp"),
		tcpostgres.WithUsername("stamp"),
		tcpostgres.WithPassword("stamp"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		return "", fmt.Errorf("the end-to-end tests need a working Docker daemon: %w", err)
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

// ---------------------------------------------------------------------------
// the identity provider
// ---------------------------------------------------------------------------

const (
	testAudience = "stamp"
	testWorkload = "pep-1"
	testConsole  = "console-1"
	testKeyID    = "test-key"
	// testStepUpACR is the class a step-up asks for and the only one the
	// operator allowlist admits.
	testStepUpACR = "urn:mace:incommon:iap:silver"
)

// testKey is generated once: RSA key generation otherwise dominates this
// package's test time.
var testKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

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

// token mints a signed token. The client identifier decides whether the
// middleware sees a workload or an end user, because that split is operator
// configuration rather than anything inside the token.
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
	return m.sign(t, claims)
}

func (m *mockIdP) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
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

func (m *mockIdP) workload(t *testing.T, id string) string { return m.token(t, id, testWorkload) }
func (m *mockIdP) user(t *testing.T, id string) string     { return m.token(t, id, testConsole) }

// stepUp mints the token a completed delegated authentication comes back with.
//
// It carries the three claims the mfa handler judges and nothing else is
// different from an ordinary console token: the class the IdP says it
// authenticated at, when it did so, and the nonce that names which
// authorization request this answers.
func (m *mockIdP) stepUp(t *testing.T, subject, acr string, authTime time.Time, nonce string) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss":       m.server.URL,
		"sub":       subject,
		"aud":       testAudience,
		"azp":       testConsole,
		"iat":       now.Add(-time.Minute).Unix(),
		"exp":       now.Add(time.Hour).Unix(),
		"acr":       acr,
		"auth_time": authTime.Unix(),
		"nonce":     nonce,
	}
	return m.sign(t, claims)
}

// ---------------------------------------------------------------------------
// the fact source
// ---------------------------------------------------------------------------

// whitelistUpstream is the remote a synchronous fact source calls: it answers
// which destination accounts one source account may pay, and it counts how many
// times it was asked, so a test can tell a cached answer from a fetched one.
type whitelistUpstream struct {
	server *httptest.Server

	mu    sync.Mutex
	table map[string][]string
	calls int
}

func newWhitelistUpstream(t *testing.T, table map[string][]string) *whitelistUpstream {
	t.Helper()
	u := &whitelistUpstream{table: table}
	mux := http.NewServeMux()
	mux.HandleFunc("/whitelist", func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.calls++
		allowed := append([]string(nil), u.table[r.URL.Query().Get("account")]...)
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"value": allowed})
	})
	u.server = httptest.NewServer(mux)
	t.Cleanup(u.server.Close)
	return u
}

func (u *whitelistUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
}

func (u *whitelistUpstream) declaration() fact.Declaration {
	return fact.Declaration{
		Name:    "account_whitelist",
		Kind:    policy.SourceHTTP,
		Params:  []policy.Param{{Name: "account", Type: policy.TypeString}},
		Returns: policy.ListOf(policy.TypeString),
		OnError: policy.OnErrorDeny,
		TTL:     5 * time.Minute,
		Timeout: 2 * time.Second,
		URL:     u.server.URL + "/whitelist",
	}
}

// ---------------------------------------------------------------------------
// the assembled process
// ---------------------------------------------------------------------------

type harness struct {
	t        *testing.T
	app      *App
	idp      *mockIdP
	upstream *whitelistUpstream
	dsn      string
	client   *http.Client
}

type harnessOptions struct {
	roles     string
	dsn       string
	writerID  string
	noSources bool
	// stepUp configures the delegated MFA handler against the mock IdP, which
	// is what decides whether the mfa challenge kind has a handler at all.
	stepUp bool
}

func newHarness(t *testing.T, opts harnessOptions) *harness {
	t.Helper()
	if opts.roles == "" {
		opts.roles = RoleAll
	}
	if opts.dsn == "" {
		opts.dsn = freshDB(t)
	}
	if opts.writerID == "" {
		opts.writerID = "stamp-e2e"
	}

	idp := newMockIdP(t)
	upstream := newWhitelistUpstream(t, map[string][]string{
		"1001": {"2002", "3003"},
	})

	cfg := Config{
		DSN:         opts.dsn,
		MaxConns:    24,
		Migrate:     true,
		ApplyGrants: true,
		InstanceID:  "e2e",
		WriterID:    opts.writerID,
		Addresses: map[api.Surface]string{
			api.SurfacePEP:      "127.0.0.1:0",
			api.SurfaceConsole:  "127.0.0.1:0",
			api.SurfaceCallback: "127.0.0.1:0",
		},
		OIDC: OIDCConfig{
			Issuers: []IssuerConfig{{
				Issuer:          idp.server.URL,
				JWKSURL:         idp.server.URL + "/jwks",
				WorkloadClients: []string{testWorkload},
			}},
			Audience:               testAudience,
			Algorithms:             []string{"RS256"},
			AllowInsecureTransport: true,
		},
		Egress: fact.EgressConfig{
			Allow:         []string{upstream.server.URL},
			AllowLoopback: true,
		},
		AuditFailClosed:       true,
		PolicyRefreshInterval: 200 * time.Millisecond,
		AuditBatchSize:        1,
		AuditFlushInterval:    50 * time.Millisecond,
	}
	if !opts.noSources {
		cfg.FactSources = []fact.Declaration{upstream.declaration()}
	}
	if opts.stepUp {
		cfg.CallbackBaseURL = "http://127.0.0.1:1/callback"
		cfg.MFA = MFAConfig{
			AllowedACRValues:      []string{testStepUpACR},
			AuthorizationEndpoint: idp.server.URL + "/authorize",
			ClientID:              testConsole,
			RedirectURI:           "http://127.0.0.1:1/callback",
			// The mock IdP is plaintext loopback, which is the one place an
			// authorization code over http is not a code handed to the network.
			AllowInsecureTransport: true,
		}
	}

	roles, err := ParseRoles(opts.roles)
	if err != nil {
		t.Fatalf("parse roles %q: %v", opts.roles, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	app, err := Assemble(ctx, cfg, roles, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		cancel()
		t.Fatalf("assemble: %v", err)
	}
	if err := app.Listen(); err != nil {
		cancel()
		app.Close()
		t.Fatalf("listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve returned %v", err)
			}
		case <-time.After(20 * time.Second):
			t.Error("the process did not stop within 20s of cancellation")
		}
		app.Close()
	})

	return &harness{
		t: t, app: app, idp: idp, upstream: upstream, dsn: opts.dsn,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// do issues one request against a surface, optionally as an authenticated
// caller, and returns the status and the decoded body.
func (h *harness) do(method string, surface api.Surface, path, token, body string,
	headers map[string]string,
) (int, []byte) {
	h.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	url := "http://" + h.app.Addr(surface) + path
	req, err := http.NewRequestWithContext(context.Background(), method, url, reader)
	if err != nil {
		h.t.Fatalf("build request %s %s: %v", method, path, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("read %s %s: %v", method, path, err)
	}
	return resp.StatusCode, raw
}

func (h *harness) decode(raw []byte, into any) {
	h.t.Helper()
	if err := json.Unmarshal(raw, into); err != nil {
		h.t.Fatalf("decode %q: %v", string(raw), err)
	}
}

// seed writes the tenant schema and its policies directly, the way an operator
// with database access bootstraps a fresh install before there is anything to
// author against.
func (h *harness) seed(schema *policy.Schema, policies ...*policy.Policy) {
	h.t.Helper()
	ctx := context.Background()
	pool := h.app.Store().Pool()
	rec, err := store.PutSchema(ctx, pool, schema, store.OriginForm, "tester")
	if err != nil {
		h.t.Fatalf("seed schema: %v", err)
	}
	for _, p := range policies {
		if _, err := store.PutPolicy(ctx, pool, store.PolicyInput{
			Policy: p, SchemaVersion: rec.Version, Origin: store.OriginForm, Author: "tester",
		}); err != nil {
			h.t.Fatalf("seed policy %s: %v", p.ID, err)
		}
	}
	if err := h.app.Refresh(ctx); err != nil {
		h.t.Fatalf("refresh after seeding: %v", err)
	}
}

// auditPayloads returns the payloads of every audit row of a kind, oldest
// first.
func (h *harness) auditPayloads(kind string) []map[string]any {
	h.t.Helper()
	rows, err := h.app.Store().Pool().Query(context.Background(),
		`SELECT payload::text FROM audit_log WHERE kind = $1 ORDER BY writer_id, seq`, kind)
	if err != nil {
		h.t.Fatalf("read audit rows: %v", err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			h.t.Fatalf("scan audit row: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(raw), &payload); err != nil {
			h.t.Fatalf("decode audit payload: %v", err)
		}
		out = append(out, payload)
	}
	return out
}

func (h *harness) verifyChain() {
	h.t.Helper()
	report, err := h.app.Store().VerifyChain(context.Background())
	if err != nil {
		h.t.Fatalf("verify audit chain: %v", err)
	}
	if !report.OK() {
		h.t.Fatalf("audit chain is broken: %v", report.Err())
	}
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// tenantSchema declares the vocabulary both flows are written against: an
// account with a number and an amount, a transfer and a close, and the
// synchronous whitelist source.
func tenantSchema() *policy.Schema {
	return &policy.Schema{
		Entities: []policy.EntityType{{
			Name: "account",
			Attributes: []policy.Attribute{
				{Name: "number", Type: policy.TypeString},
				{Name: "amount", Type: policy.TypeInt},
			},
		}},
		Actions: []policy.Action{{Name: "transfer"}, {Name: "close"}},
		Sources: []policy.SourceDecl{{
			Name:    "account_whitelist",
			Kind:    policy.SourceHTTP,
			Params:  []policy.Param{{Name: "account", Type: policy.TypeString}},
			Returns: policy.ListOf(policy.TypeString),
			OnError: policy.OnErrorDeny,
		}},
	}
}

// whitelistPolicy is F1: a transfer is allowed when the destination account is
// on the source account's whitelist, which is a synchronous fact source lookup.
//
// Each call builds fresh condition values. Normalization rewrites the condition
// tree in place, so two policies sharing one value would be two writers on the
// same nodes.
func whitelistPolicy(id string) *policy.Policy {
	return &policy.Policy{
		ID:          id,
		Description: "a transfer may only reach a whitelisted destination",
		Subject:     "account",
		Resource:    "account",
		Actions:     []string{"transfer"},
		Condition: policy.Member{
			Left:       policy.Field(policy.RoleResource, "number"),
			Collection: policy.Source("account_whitelist", policy.Field(policy.RoleSubject, "number")),
		},
	}
}

// closurePolicy is the gated tenant policy F2 revalidates: closing a large
// account needs an approval, so a decision made against it stays pending.
func closurePolicy(id string, threshold int, approvers ...string) *policy.Policy {
	return &policy.Policy{
		ID:       id,
		Subject:  "account",
		Resource: "account",
		Actions:  []string{"close"},
		Condition: policy.Compare{
			Op: policy.OpGe, Left: policy.Field(policy.RoleResource, "amount"), Right: policy.Int(1000),
		},
		Challenges: []policy.Challenge{
			policy.Quorum{Threshold: threshold, Approvers: policy.ApproverSet{Members: approvers}},
		},
	}
}

// coolingOffPolicy is F3: closing a large account waits, and a named authority
// may cut the wait short. It is the gated policy whose challenge a revision can
// silently restart, which is why it is demonstrated end to end rather than only
// in the revision package.
func coolingOffPolicy(id string, wait time.Duration, cancellers ...string) *policy.Policy {
	delay := policy.Delay{Duration: wait}
	if len(cancellers) > 0 {
		delay.CancellableBy = &policy.ApproverSet{Members: cancellers}
	}
	return &policy.Policy{
		ID:       id,
		Subject:  "account",
		Resource: "account",
		Actions:  []string{"close"},
		Condition: policy.Compare{
			Op: policy.OpGe, Left: policy.Field(policy.RoleResource, "amount"), Right: policy.Int(1000),
		},
		Challenges: []policy.Challenge{delay},
	}
}

// stepUpPolicy gates a closure on a delegated authentication by the decision's
// subject.
func stepUpPolicy(id string, acr ...string) *policy.Policy {
	return &policy.Policy{
		ID:       id,
		Subject:  "account",
		Resource: "account",
		Actions:  []string{"close"},
		Condition: policy.Compare{
			Op: policy.OpGe, Left: policy.Field(policy.RoleResource, "amount"), Right: policy.Int(1000),
		},
		Challenges: []policy.Challenge{policy.MFA{Mode: policy.MFADelegated, ACRValues: acr}},
	}
}

// challengeRow reads one challenge's stored row.
func (h *harness) challengeRow(decisionID string, ordinal int) store.ChallengeProgress {
	h.t.Helper()
	rows, err := store.ChallengeProgressFor(context.Background(), h.app.Store().Pool(), decisionID)
	if err != nil {
		h.t.Fatalf("read challenge progress: %v", err)
	}
	for _, row := range rows {
		if row.Ordinal == ordinal {
			return row
		}
	}
	h.t.Fatalf("decision %s carries no challenge %d", decisionID, ordinal)
	return store.ChallengeProgress{}
}

// delayDetail decodes the wait a decision is holding on.
func (h *harness) delayDetail(decisionID string) challenge.DelayDetail {
	h.t.Helper()
	detail, err := challenge.DecodeDelayDetail(h.challengeRow(decisionID, 0).Detail)
	if err != nil {
		h.t.Fatalf("decode delay detail: %v", err)
	}
	return detail
}

// mfaDetail decodes the step-up a decision is waiting on.
func (h *harness) mfaDetail(decisionID string) mfa.Detail {
	h.t.Helper()
	detail, err := mfa.DecodeDetail(h.challengeRow(decisionID, 0).Detail)
	if err != nil {
		h.t.Fatalf("decode mfa detail: %v", err)
	}
	return detail
}

// nextDeadline reports the decision's scheduler column, which is what the
// sweeper wakes for.
func (h *harness) nextDeadline(decisionID string) *time.Time {
	h.t.Helper()
	d, err := store.GetDecision(context.Background(), h.app.Store().Pool(), decisionID)
	if err != nil {
		h.t.Fatalf("read decision %s: %v", decisionID, err)
	}
	return d.NextDeadline
}

// evaluation is one AuthZEN request body.
func evaluation(sourceNumber, destNumber, action string) string {
	return fmt.Sprintf(`{
		"subject":  {"type": "account", "id": "acct-src", "properties": {"number": %q}},
		"resource": {"type": "account", "id": "acct-dst", "properties": {"number": %q}},
		"action":   {"name": %q}
	}`, sourceNumber, destNumber, action)
}
