package decision_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// The lifecycle tests run against a real Postgres. What this unit promises —
// that an approval after the deadline does not count, that two sweepers resolve
// a decision once between them — is a property of row locks and conditional
// updates, and a fake store would be asserting that the fake behaves.

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
		fmt.Fprintf(os.Stderr, "decision tests need a working Docker daemon: %v\n", err)
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

// testMaxConns sizes the pool. Every claimed audit writer pins one connection
// for its whole life, so a test with two sweepers needs its two writers plus the
// connections their transactions and the test's own queries take. Leaving this
// to the pgxpool default makes the concurrency test pass or hang depending on
// the machine's core count.
const testMaxConns = 24

func freshDB(t *testing.T) string {
	t.Helper()
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

// clock is the test clock. Deadline behaviour is the subject of most of these
// tests, so it is driven rather than waited on.
type clock struct {
	mu sync.Mutex
	at time.Time
}

func newClock() *clock {
	return &clock{at: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// harness is a migrated database, a seeded policy set, an evaluator over it and
// a decision service wired to all three.
type harness struct {
	t      *testing.T
	store  *store.Store
	writer *store.AuditWriter
	clock  *clock
	svc    *decision.Service
	opts   harnessOptions
	schema *policy.Schema
	seeded []engine.PolicyVersion
}

type harnessOptions struct {
	maxOutstanding int
	ttl            time.Duration
	obligations    []decision.Obligation
	policies       []*policy.Policy
	resolver       engine.SourceResolver
	// mfaHandler replaces the default delegated-MFA stand-in, so that a test
	// can register a handler that publishes the wrong thing and check that the
	// assertions notice.
	mfaHandler challenge.Handler
	// externalHandler registers the fourth kind. It is off by default because
	// most of this package's tests are about the three kinds that name people,
	// and the whole point of this one is that it names nobody.
	externalHandler challenge.Handler
}

func newHarness(t *testing.T, opts harnessOptions) *harness {
	t.Helper()
	ctx := context.Background()
	clk := newClock()

	s, err := store.Open(ctx, store.Config{DSN: freshDB(t), MaxConns: testMaxConns, Now: clk.Now})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	h := &harness{t: t, store: s, clock: clk, schema: testSchema()}
	if _, err := store.PutSchema(ctx, s.Pool(), h.schema, store.OriginForm, "tester"); err != nil {
		t.Fatalf("put schema: %v", err)
	}
	schemaRec, err := store.LatestSchema(ctx, s.Pool())
	if err != nil {
		t.Fatalf("latest schema: %v", err)
	}
	for _, p := range opts.policies {
		rec, err := store.PutPolicy(ctx, s.Pool(), store.PolicyInput{
			Policy: p, SchemaVersion: schemaRec.Version, Origin: store.OriginForm, Author: "tester",
		})
		if err != nil {
			t.Fatalf("put policy %s: %v", p.ID, err)
		}
		stored, err := rec.Policy()
		if err != nil {
			t.Fatalf("decode stored policy %s: %v", p.ID, err)
		}
		h.seeded = append(h.seeded, engine.PolicyVersion{
			Version: strconv.FormatInt(rec.Version, 10),
			Policy:  *stored,
		})
	}

	h.writer = h.claimWriter("decide-1")
	h.opts = opts
	h.svc = h.newService(h.writer, opts)
	return h
}

// evaluator builds a second evaluator over the same snapshot and fact plane,
// so a test can ask what an evaluation resolves without going through the
// service that is supposed to freeze it.
func (h *harness) evaluator() *engine.DecideEvaluator {
	h.t.Helper()
	snap, err := engine.NewSnapshot("1", *h.schema, h.seeded)
	if err != nil {
		h.t.Fatalf("new snapshot: %v", err)
	}
	if h.opts.resolver != nil {
		return engine.NewDecideEvaluator(snap, engine.WithSourceResolver(h.opts.resolver))
	}
	return engine.NewDecideEvaluator(snap)
}

func (h *harness) claimWriter(id string) *store.AuditWriter {
	h.t.Helper()
	w, err := h.store.ClaimWriter(context.Background(), id, "test")
	if err != nil {
		h.t.Fatalf("claim writer %s: %v", id, err)
	}
	h.t.Cleanup(func() { _ = w.Close(context.Background()) })
	return w
}

func (h *harness) newService(writer *store.AuditWriter, opts harnessOptions) *decision.Service {
	h.t.Helper()
	snap, err := engine.NewSnapshot("1", *h.schema, h.seeded)
	if err != nil {
		h.t.Fatalf("new snapshot: %v", err)
	}
	var mfa challenge.Handler = &stepUpHandler{}
	if opts.mfaHandler != nil {
		mfa = opts.mfaHandler
	}
	handlers := []challenge.Handler{
		&quorumHandler{writer: writer, pool: h.store.Pool()},
		&delayHandler{},
		mfa,
	}
	if opts.externalHandler != nil {
		handlers = append(handlers, opts.externalHandler)
	}
	registry, err := challenge.NewRegistry(handlers...)
	if err != nil {
		h.t.Fatalf("new challenge registry: %v", err)
	}
	evaluator := engine.NewDecideEvaluator(snap)
	if opts.resolver != nil {
		evaluator = engine.NewDecideEvaluator(snap, engine.WithSourceResolver(opts.resolver))
	}
	cfg := decision.Config{
		Store:          h.store,
		Audit:          writer,
		Evaluator:      evaluator,
		Challenges:     registry,
		TTL:            opts.ttl,
		MaxOutstanding: opts.maxOutstanding,
		Now:            h.clock.Now,
	}
	if opts.obligations != nil {
		obligations := opts.obligations
		cfg.Obligations = decision.ObligationSourceFunc(
			func(_ context.Context, _ decision.ObligationRequest) ([]decision.Obligation, error) {
				return obligations, nil
			})
	}
	svc, err := decision.New(cfg)
	if err != nil {
		h.t.Fatalf("new service: %v", err)
	}
	return svc
}

// auditPayloads returns the payloads of every audit row of a kind about a
// subject, oldest first.
func (h *harness) auditPayloads(kind, subject string) []map[string]any {
	h.t.Helper()
	rows, err := h.store.Pool().Query(context.Background(), `
		SELECT payload::text FROM audit_log
		WHERE kind = $1 AND subject = $2 ORDER BY writer_id, seq`, kind, subject)
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

// sweepOnce runs one sweep of svc and fails the test if it errors.
func (h *harness) sweepOnce(svc *decision.Service) decision.SweepReport {
	h.t.Helper()
	sweeper, err := decision.NewSweeper(decision.SweeperConfig{Service: svc})
	if err != nil {
		h.t.Fatalf("new sweeper: %v", err)
	}
	report, err := sweeper.SweepOnce(context.Background())
	if err != nil {
		h.t.Fatalf("sweep: %v", err)
	}
	return report
}

func (h *harness) approvalCount(decisionID string, ordinal int) int {
	h.t.Helper()
	n, err := store.CountApprovals(context.Background(), h.store.Pool(), decisionID, ordinal, store.VerdictApprove)
	if err != nil {
		h.t.Fatalf("count approvals: %v", err)
	}
	return n
}

func (h *harness) decisionState(id string) store.DecisionState {
	h.t.Helper()
	d, err := store.GetDecision(context.Background(), h.store.Pool(), id)
	if err != nil {
		h.t.Fatalf("read decision %s: %v", id, err)
	}
	return d.State
}

// ---------------------------------------------------------------------------
// fixtures: schema, policies, callers
// ---------------------------------------------------------------------------

func testSchema() *policy.Schema {
	return &policy.Schema{
		Entities: []policy.EntityType{
			{Name: "user", Attributes: []policy.Attribute{{Name: "role", Type: policy.TypeString}}},
			{Name: "account", Attributes: []policy.Attribute{{Name: "tier", Type: policy.TypeString}}},
		},
		Actions: []policy.Action{{Name: "transfer"}},
		Sources: []policy.SourceDecl{{
			Name:    "risk_score",
			Kind:    policy.SourceHTTP,
			Params:  []policy.Param{{Name: "role", Type: policy.TypeString}},
			Returns: policy.TypeInt,
			OnError: policy.OnErrorDeny,
		}},
	}
}

// factGatedPolicy reaches a fact source from its condition, so that an
// evaluation of it resolves facts the decision has to freeze.
func factGatedPolicy(id string, threshold int, approvers ...string) *policy.Policy {
	return &policy.Policy{
		ID:       id,
		Subject:  "user",
		Resource: "account",
		Actions:  []string{"transfer"},
		Condition: policy.Compare{
			Op:    policy.OpGe,
			Left:  policy.Source("risk_score", policy.Field(policy.RoleSubject, "role")),
			Right: policy.Int(50),
		},
		Challenges: []policy.Challenge{
			policy.Quorum{Threshold: threshold, Approvers: policy.ApproverSet{Members: approvers}},
		},
	}
}

// factOpenPolicy is factGatedPolicy without a challenge: it allows outright,
// and still rests on a resolved fact.
func factOpenPolicy(id string) *policy.Policy {
	return &policy.Policy{
		ID:       id,
		Subject:  "user",
		Resource: "account",
		Actions:  []string{"transfer"},
		Condition: policy.Compare{
			Op:    policy.OpGe,
			Left:  policy.Source("risk_score", policy.Field(policy.RoleSubject, "role")),
			Right: policy.Int(50),
		},
	}
}

// recordingResolver is the fact plane: it answers every call with one value and
// counts how often it was asked, so a test can tell a resolved fact from a
// value that was merely lying around.
type recordingResolver struct {
	mu    sync.Mutex
	value int64
	calls int
	seen  []engine.SourceCall
}

func (r *recordingResolver) ResolveSources(_ context.Context, calls []engine.SourceCall) (*engine.Facts, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	facts := engine.NewFacts()
	for _, call := range calls {
		r.seen = append(r.seen, call)
		facts.Set(call, r.value)
	}
	return facts, nil
}

func (r *recordingResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// gatedPolicy returns a policy demanding a quorum. Each call builds fresh
// condition values: policy normalization rewrites the condition tree in place,
// so two policies sharing one condition value would race under -race.
func gatedPolicy(id string, threshold int, approvers ...string) *policy.Policy {
	return &policy.Policy{
		ID:        id,
		Subject:   "user",
		Resource:  "account",
		Actions:   []string{"transfer"},
		Condition: policy.Compare{Op: policy.OpEq, Left: policy.Field(policy.RoleSubject, "role"), Right: policy.String("admin")},
		Challenges: []policy.Challenge{
			policy.Quorum{Threshold: threshold, Approvers: policy.ApproverSet{Members: approvers}},
		},
	}
}

func delayedPolicy(id string, d time.Duration) *policy.Policy {
	return &policy.Policy{
		ID:         id,
		Subject:    "user",
		Resource:   "account",
		Actions:    []string{"transfer"},
		Condition:  policy.Compare{Op: policy.OpEq, Left: policy.Field(policy.RoleSubject, "role"), Right: policy.String("admin")},
		Challenges: []policy.Challenge{policy.Delay{Duration: d}},
	}
}

func openPolicy(id string) *policy.Policy {
	return &policy.Policy{
		ID:        id,
		Subject:   "user",
		Resource:  "account",
		Actions:   []string{"transfer"},
		Condition: policy.Compare{Op: policy.OpEq, Left: policy.Field(policy.RoleSubject, "role"), Right: policy.String("admin")},
	}
}

func transferRequest(subject string) engine.Input {
	return engine.Input{
		Action:   "transfer",
		Subject:  engine.Entity{Type: "user", ID: subject, Attributes: map[string]any{"role": "admin"}},
		Resource: engine.Entity{Type: "account", ID: "acct-1", Attributes: map[string]any{"tier": "gold"}},
	}
}

func workload(id string) *identity.Subject {
	return &identity.Subject{Kind: identity.SubjectWorkload, Issuer: "https://idp.test", ID: id}
}

func user(id string) *identity.Subject {
	return &identity.Subject{Kind: identity.SubjectUser, Issuer: "https://idp.test", ID: id}
}

// ---------------------------------------------------------------------------
// challenge handlers
//
// These are test doubles for the handlers U20 and U11 own. They implement the
// contract this unit fixes, which is the point: the lifecycle is exercised
// through the same three verbs a real handler is called through.
// ---------------------------------------------------------------------------

type quorumDetail struct {
	Threshold int      `json:"threshold"`
	Approvers []string `json:"approvers"`
}

type quorumHandler struct {
	writer *store.AuditWriter
	pool   *pgxpool.Pool
}

func (q *quorumHandler) Kind() policy.ChallengeType { return policy.ChallengeQuorum }

func (q *quorumHandler) Issue(_ context.Context, req challenge.IssueRequest) (challenge.IssueResult, error) {
	spec, ok := req.Spec.(policy.Quorum)
	if !ok {
		return challenge.IssueResult{}, fmt.Errorf("%w: %T", challenge.ErrUnsupportedSpec, req.Spec)
	}
	return challenge.IssueResult{
		State:  challenge.StatePending,
		Detail: quorumDetail{Threshold: spec.Threshold, Approvers: spec.Approvers.Members},
	}, nil
}

func (q *quorumHandler) Submit(ctx context.Context, req challenge.SubmitRequest) (challenge.SubmitResult, error) {
	detail, err := decodeQuorumDetail(req.Detail)
	if err != nil {
		return challenge.SubmitResult{}, err
	}
	if !contains(detail.Approvers, req.Submitter.ID) {
		return challenge.SubmitResult{}, fmt.Errorf("%w: %q", challenge.ErrNotTarget, req.Submitter.ID)
	}
	binding := sha256.Sum256(append([]byte(req.Instance.DecisionID), req.Decision.Obligations...))
	_, err = q.writer.RecordApproval(ctx, store.NewApproval{
		DecisionID:       req.Instance.DecisionID,
		ChallengeOrdinal: req.Instance.Ordinal,
		ApproverID:       req.Submitter.ID,
		Verdict:          store.VerdictApprove,
		BindingHash:      binding,
	})
	if err != nil && !errorIsConflict(err) {
		return challenge.SubmitResult{}, err
	}
	have, err := q.count(ctx, req.Instance)
	if err != nil {
		return challenge.SubmitResult{}, err
	}
	return challenge.SubmitResult{State: quorumState(have, detail.Threshold), Have: have, Need: detail.Threshold}, nil
}

func (q *quorumHandler) Status(ctx context.Context, req challenge.StatusRequest) (challenge.Status, error) {
	detail, err := decodeQuorumDetail(req.Detail)
	if err != nil {
		return challenge.Status{}, err
	}
	have, err := q.count(ctx, req.Instance)
	if err != nil {
		return challenge.Status{}, err
	}
	state := req.Stored
	if state == challenge.StatePending {
		state = quorumState(have, detail.Threshold)
	}
	return challenge.Status{State: state, Have: have, Need: detail.Threshold, Deadline: req.Deadline}, nil
}

func (q *quorumHandler) IsTarget(_ context.Context, req challenge.TargetRequest) (bool, error) {
	detail, err := decodeQuorumDetail(req.Detail)
	if err != nil {
		return false, err
	}
	return contains(detail.Approvers, req.Subject.ID), nil
}

func (q *quorumHandler) count(ctx context.Context, in challenge.Instance) (int, error) {
	return store.CountApprovals(ctx, q.pool, in.DecisionID, in.Ordinal, store.VerdictApprove)
}

func quorumState(have, need int) challenge.State {
	if have >= need {
		return challenge.StateSatisfied
	}
	return challenge.StatePending
}

func decodeQuorumDetail(raw json.RawMessage) (quorumDetail, error) {
	var detail quorumDetail
	if err := json.Unmarshal(raw, &detail); err != nil {
		return quorumDetail{}, fmt.Errorf("%w: %w", challenge.ErrInvalidPayload, err)
	}
	return detail, nil
}

// delayHandler is the shape a delay challenge has: nothing to submit, and a
// deadline whose passing means satisfied rather than failed. It is here because
// that distinction is why the contract answers elapsed timers through Status.
type delayHandler struct{}

func (*delayHandler) Kind() policy.ChallengeType { return policy.ChallengeDelay }

func (*delayHandler) Issue(_ context.Context, req challenge.IssueRequest) (challenge.IssueResult, error) {
	spec, ok := req.Spec.(policy.Delay)
	if !ok {
		return challenge.IssueResult{}, fmt.Errorf("%w: %T", challenge.ErrUnsupportedSpec, req.Spec)
	}
	deadline := req.Now.Add(spec.Duration)
	return challenge.IssueResult{
		State:    challenge.StatePending,
		Deadline: &deadline,
		Detail:   map[string]any{"duration_seconds": spec.Duration.Seconds()},
	}, nil
}

func (*delayHandler) Submit(_ context.Context, _ challenge.SubmitRequest) (challenge.SubmitResult, error) {
	return challenge.SubmitResult{}, challenge.ErrNotSubmittable
}

func (*delayHandler) Status(_ context.Context, req challenge.StatusRequest) (challenge.Status, error) {
	state := req.Stored
	if state == challenge.StatePending && req.Deadline != nil && !req.Now.Before(*req.Deadline) {
		state = challenge.StateSatisfied
	}
	return challenge.Status{State: state, Deadline: req.Deadline}, nil
}

// stepUpHandler is the shape a delegated MFA challenge has, and the only shape
// this package is allowed to know about it: a handler whose stored detail holds
// secrets and which publishes one derived, public value through the optional
// [challenge.Viewer] seam.
//
// The real handler lives in internal/challenge/mfa and this package must not
// import it — TestTheLifecycleDoesNotImportAChallengeKind is that rule as an
// assertion. So the hazard is reproduced rather than borrowed: the detail below
// carries a correlator, a nonce and a PKCE verifier, and the view answers with
// none of them.
type stepUpHandler struct{}

// The secrets a delegated MFA challenge keeps on its row. They are distinctive
// strings so that a test can scan a serialized response for the values
// themselves and not merely for the field names carrying them.
const (
	testCorrelator   = "correlator-3f9c1d2b4a6e8f0c1d2b4a6e8f0c1d2b"
	testMFANonce     = "nonce-9a8b7c6d5e4f0011223344556677889900"
	testCodeVerifier = "verifier-11223344556677889900aabbccddeeff"

	// testAuthorizationURL is what the subject's browser must be sent to. It
	// deliberately carries none of the three values above: what a handler
	// publishes is a decision the handler makes, and this one publishes a URL
	// whose `state` is a CSRF token rather than the correlator (KTD2).
	testAuthorizationURL = "https://idp.test/authorize?client_id=stamp-stepup&state=csrf-0f0f0f&acr_values=mfa"
)

type stepUpDetail struct {
	Correlator   string `json:"correlator"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	SubjectID    string `json:"subject_id"`
	AuthURL      string `json:"authorization_url"`
}

func (*stepUpHandler) Kind() policy.ChallengeType { return policy.ChallengeMFA }

func (*stepUpHandler) Issue(_ context.Context, req challenge.IssueRequest) (challenge.IssueResult, error) {
	if _, ok := req.Spec.(policy.MFA); !ok {
		return challenge.IssueResult{}, fmt.Errorf("%w: %T", challenge.ErrUnsupportedSpec, req.Spec)
	}
	return challenge.IssueResult{
		State: challenge.StatePending,
		Detail: stepUpDetail{
			Correlator:   testCorrelator,
			Nonce:        testMFANonce,
			CodeVerifier: testCodeVerifier,
			SubjectID:    req.Decision.SubjectID,
			AuthURL:      testAuthorizationURL,
		},
	}, nil
}

func (*stepUpHandler) Submit(_ context.Context, _ challenge.SubmitRequest) (challenge.SubmitResult, error) {
	return challenge.SubmitResult{}, challenge.ErrNotSubmittable
}

func (*stepUpHandler) Status(_ context.Context, req challenge.StatusRequest) (challenge.Status, error) {
	state := req.Stored
	if state == challenge.StatePending && req.Deadline != nil && !req.Now.Before(*req.Deadline) {
		state = challenge.StateFailed
	}
	return challenge.Status{State: state, Have: 0, Need: 1, Deadline: req.Deadline}, nil
}

// View implements [challenge.Viewer]: one field, chosen by name.
func (*stepUpHandler) View(_ context.Context, req challenge.ViewRequest) (challenge.View, error) {
	detail, err := decodeStepUpDetail(req.Detail)
	if err != nil {
		return challenge.View{}, err
	}
	return challenge.View{AuthorizationURL: detail.AuthURL}, nil
}

func decodeStepUpDetail(raw json.RawMessage) (stepUpDetail, error) {
	var detail stepUpDetail
	if err := json.Unmarshal(raw, &detail); err != nil {
		return stepUpDetail{}, fmt.Errorf("%w: %w", challenge.ErrInvalidPayload, err)
	}
	return detail, nil
}

// countingStepUpHandler is stepUpHandler with a tally of how many times it was
// asked to open a challenge.
//
// The tally is the assertion an idempotent retry is actually about. A retry that
// returned the same decision identifier while quietly issuing a second challenge
// would pass every test that only looks at rows, and would still have buzzed the
// subject's phone twice — which is the failure the key exists to prevent, and the
// one a unique index on the decision row cannot catch, because the push happens
// before the row is written.
type countingStepUpHandler struct {
	stepUpHandler
	issues atomic.Int64
}

func (c *countingStepUpHandler) Issue(ctx context.Context, req challenge.IssueRequest) (challenge.IssueResult, error) {
	c.issues.Add(1)
	return c.stepUpHandler.Issue(ctx, req)
}

func (c *countingStepUpHandler) count() int { return int(c.issues.Load()) }

// refusingStepUpHandler is the shape a delegated MFA handler has when it opens
// no challenge at all: the challenge is stored failed, nothing reached the IdP,
// and the word for why travels on the row.
//
// It carries both branches because the branches are the point. `shed` is the
// per-subject issuance budget refusing to prompt anybody (R43); the other is a
// round trip that was attempted and went wrong. The lifecycle must tell them
// apart without knowing either word, so the double publishes the contract's bit
// exactly as the real handlers do.
type refusingStepUpHandler struct{ shed bool }

type refusedDetail struct {
	Failure string `json:"failure"`
	Shed    bool   `json:"shed"`
}

func (*refusingStepUpHandler) Kind() policy.ChallengeType { return policy.ChallengeMFA }

// refusedIssueRetryAfter is the wait a shed issuance reports. It is a round
// number rather than a real budget's interval so that a test reading the header
// is reading this handler's answer and not arithmetic.
const refusedIssueRetryAfter = 90 * time.Second

func (r *refusingStepUpHandler) Issue(_ context.Context, _ challenge.IssueRequest) (challenge.IssueResult, error) {
	failure := "transport"
	if r.shed {
		failure = "issue_rate_limited"
	}
	out := challenge.IssueResult{
		State:  challenge.StateFailed,
		Detail: refusedDetail{Failure: failure, Shed: r.shed},
	}
	// The contract's bit at issue as well as at Status, which is what lets the
	// lifecycle refuse before it writes a row rather than resolving a decision
	// onto the subject's history afterwards. A double that set it only on Status
	// would be a double that could not exercise the path.
	if r.shed {
		out.Shed = true
		out.RetryAfter = refusedIssueRetryAfter
	}
	return out, nil
}

func (*refusingStepUpHandler) Submit(_ context.Context, _ challenge.SubmitRequest) (challenge.SubmitResult, error) {
	return challenge.SubmitResult{}, challenge.ErrNotSubmittable
}

// Status keeps a refused issue refused, which is what the lifecycle storing
// every challenge pending obliges every handler to do.
func (*refusingStepUpHandler) Status(_ context.Context, req challenge.StatusRequest) (challenge.Status, error) {
	var detail refusedDetail
	if err := json.Unmarshal(req.Detail, &detail); err != nil {
		return challenge.Status{}, fmt.Errorf("%w: %w", challenge.ErrInvalidPayload, err)
	}
	state := req.Stored
	if !state.Terminal() && detail.Failure != "" {
		state = challenge.StateFailed
	}
	return challenge.Status{State: state, Have: 0, Need: 1, Shed: detail.Shed}, nil
}

// leakyStepUpHandler is stepUpHandler with the mistake this unit exists to
// prevent: it publishes the stored detail instead of a chosen field. It is the
// mutation the secret tests are pointed at.
type leakyStepUpHandler struct{ stepUpHandler }

func (*leakyStepUpHandler) View(_ context.Context, req challenge.ViewRequest) (challenge.View, error) {
	detail, err := decodeStepUpDetail(req.Detail)
	if err != nil {
		return challenge.View{}, err
	}
	return challenge.View{AuthorizationURL: detail.AuthURL + "#" + detail.Correlator}, nil
}

// mfaPolicy demands a delegated MFA challenge and nothing else.
func mfaPolicy(id string) *policy.Policy {
	return &policy.Policy{
		ID:        id,
		Subject:   "user",
		Resource:  "account",
		Actions:   []string{"transfer"},
		Condition: policy.Compare{Op: policy.OpEq, Left: policy.Field(policy.RoleSubject, "role"), Right: policy.String("admin")},
		Challenges: []policy.Challenge{
			policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{"urn:stamp:acr:mfa"}},
		},
	}
}

// quorumAndDelayPolicy is the two kinds that publish nothing, in one decision.
func quorumAndDelayPolicy(id string, threshold int, approvers ...string) *policy.Policy {
	return &policy.Policy{
		ID:        id,
		Subject:   "user",
		Resource:  "account",
		Actions:   []string{"transfer"},
		Condition: policy.Compare{Op: policy.OpEq, Left: policy.Field(policy.RoleSubject, "role"), Right: policy.String("admin")},
		Challenges: []policy.Challenge{
			policy.Quorum{Threshold: threshold, Approvers: policy.ApproverSet{Members: approvers}},
			policy.Delay{Duration: time.Hour},
		},
	}
}

// mfaAndQuorumPolicy pairs a kind that publishes something with one that does
// not, so a single decision exercises both branches of the type assertion.
func mfaAndQuorumPolicy(id string, approvers ...string) *policy.Policy {
	return &policy.Policy{
		ID:        id,
		Subject:   "user",
		Resource:  "account",
		Actions:   []string{"transfer"},
		Condition: policy.Compare{Op: policy.OpEq, Left: policy.Field(policy.RoleSubject, "role"), Right: policy.String("admin")},
		Challenges: []policy.Challenge{
			policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{"urn:stamp:acr:mfa"}},
			policy.Quorum{Threshold: 1, Approvers: policy.ApproverSet{Members: approvers}},
		},
	}
}

// externalHandler is the shape of the one kind that names no targets.
//
// It deliberately does not implement [challenge.Targeter], because the real one
// does not: its counterparty is a system STAMP called out to, holding a
// signature over a nonce this server minted rather than an identity the
// lifecycle could compare against an approver set. That absence is load-bearing
// — it is what the standing check in Submit has to fall through — so the double
// reproduces it rather than being convenient.
type externalHandler struct{ target string }

func (*externalHandler) Kind() policy.ChallengeType { return policy.ChallengeExternal }

func (x *externalHandler) Issue(_ context.Context, req challenge.IssueRequest) (challenge.IssueResult, error) {
	spec, ok := req.Spec.(policy.External)
	if !ok {
		return challenge.IssueResult{}, fmt.Errorf("%w: %T", challenge.ErrUnsupportedSpec, req.Spec)
	}
	x.target = spec.Target
	return challenge.IssueResult{
		State:  challenge.StatePending,
		Detail: map[string]any{"target": spec.Target, "nonce": "nonce-external-0f0f"},
	}, nil
}

// Submit accepts the body that carries the nonce this challenge was opened with,
// and nothing else. That check standing in for a signature is the point: the
// counterparty proves itself to the handler, which is why the lifecycle must not
// turn it away before the handler is asked.
func (*externalHandler) Submit(_ context.Context, req challenge.SubmitRequest) (challenge.SubmitResult, error) {
	var body struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(req.Payload, &body); err != nil {
		return challenge.SubmitResult{}, fmt.Errorf("%w: %w", challenge.ErrInvalidPayload, err)
	}
	if body.Nonce != "nonce-external-0f0f" {
		return challenge.SubmitResult{}, fmt.Errorf("%w: the callback carries no nonce of this challenge",
			challenge.ErrNotTarget)
	}
	return challenge.SubmitResult{State: challenge.StateSatisfied, Have: 1, Need: 1}, nil
}

func (*externalHandler) Status(_ context.Context, req challenge.StatusRequest) (challenge.Status, error) {
	return challenge.Status{State: req.Stored, Have: 0, Need: 1, Deadline: req.Deadline}, nil
}

// externallyGatedPolicy waits on a system rather than on a person.
func externallyGatedPolicy(id string) *policy.Policy {
	return &policy.Policy{
		ID:        id,
		Subject:   "user",
		Resource:  "account",
		Actions:   []string{"transfer"},
		Condition: policy.Compare{Op: policy.OpEq, Left: policy.Field(policy.RoleSubject, "role"), Right: policy.String("admin")},
		Challenges: []policy.Challenge{
			policy.External{Target: "https://sanctions.test/screen"},
		},
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func errorIsConflict(err error) bool {
	return errors.Is(err, store.ErrConflict)
}
