package revision_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/challenge/mfa"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// The governance tests run against a real Postgres and the real quorum handler.
//
// Neither is a detail. "One pending revision at a time" is a partial unique
// index, "the revision and the revalidation land together" is a transaction,
// and "the proposer's approval does not count" is the quorum handler refusing a
// submitter who is not in the frozen set. A fake for any of the three would be
// a test that the fake behaves.

const postgresImage = "postgres:17-alpine"

// postgresDSN starts the container on first use, so the pure tests in this
// package — the classifier, the delta type — still run without a Docker daemon.
var postgresDSN = sync.OnceValues(func() (string, error) {
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase("stamp"),
		tcpostgres.WithUsername("stamp"),
		tcpostgres.WithPassword("stamp"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		return "", fmt.Errorf("the governance tests need a working Docker daemon: %w", err)
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
// its whole life, so leaving this to the pgxpool default makes a test that
// claims more than one writer pass or hang depending on the machine.
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

// clock is the test clock: deadline and warning-interval behaviour are driven
// rather than waited on.
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

// ---------------------------------------------------------------------------
// the harness
// ---------------------------------------------------------------------------

type harness struct {
	t           *testing.T
	dsn         string
	store       *store.Store
	writer      *store.AuditWriter
	clock       *clock
	registry    *challenge.Registry
	webhook     *webhookTarget
	gov         *revision.Service
	token       string
	resolver    *countingResolver
	obligations *mutableObligations
}

type harnessOptions struct {
	floor    revision.Floor
	resolver *countingResolver
}

// mutableObligations is the obligation seam, with a setter. A revision that
// changes what a decision obliges the caller to do is the cleanest way to move
// the approval binding hash without touching the quorum, which is exactly the
// case R31 draws a line through.
type mutableObligations struct {
	mu   sync.Mutex
	list []decision.Obligation
}

func (m *mutableObligations) set(list []decision.Obligation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.list = list
}

func (m *mutableObligations) ObligationsFor(context.Context, decision.ObligationRequest) ([]decision.Obligation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]decision.Obligation(nil), m.list...), nil
}

func newHarness(t *testing.T, opts harnessOptions) *harness {
	t.Helper()
	ctx := context.Background()
	clk := newClock()
	dsn := freshDB(t)

	s, err := store.Open(ctx, store.Config{DSN: dsn, MaxConns: testMaxConns, Now: clk.Now})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	writer, err := s.ClaimWriter(ctx, "governance-1", "test")
	if err != nil {
		t.Fatalf("claim writer: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close(context.Background()) })

	webhook := newWebhookTarget(t)
	registry, err := allHandlers(t, writer, s, webhook)
	if err != nil {
		t.Fatalf("build challenge registry: %v", err)
	}
	obligations := &mutableObligations{}
	revalidator, err := decision.NewRevalidator(decision.RevalidatorConfig{
		Challenges: registry, Obligations: obligations, Now: clk.Now,
	})
	if err != nil {
		t.Fatalf("build revalidator: %v", err)
	}

	h := &harness{
		t: t, dsn: dsn, store: s, writer: writer, clock: clk, webhook: webhook,
		registry: registry, resolver: opts.resolver, obligations: obligations,
	}
	cfg := revision.Config{
		Store:       s,
		Audit:       writer,
		Challenges:  registry,
		Revalidator: revalidator,
		Floor:       opts.floor,
		Now:         clk.Now,
	}
	if opts.resolver != nil {
		cfg.Resolver = opts.resolver
	}
	h.gov, err = revision.New(cfg)
	if err != nil {
		t.Fatalf("build governance service: %v", err)
	}

	token, err := h.gov.Install(ctx)
	if err != nil {
		t.Fatalf("install governance: %v", err)
	}
	if token == "" {
		t.Fatal("install returned no bootstrap token")
	}
	h.token = token

	// The tenant schema is seeded directly. Authoring the first schema is not
	// what these tests are about, and a revision that carried it would have to
	// validate its own policies against a schema that does not exist yet.
	if _, err := store.PutSchema(ctx, s.Pool(), tenantSchema(), store.OriginForm, "tester"); err != nil {
		t.Fatalf("seed tenant schema: %v", err)
	}
	return h
}

// releaseWriter drops the harness's audit-writer claim, which is what a stopped
// service looks like to the break-glass liveness check.
func (h *harness) releaseWriter() {
	h.t.Helper()
	if err := h.writer.Close(context.Background()); err != nil {
		h.t.Fatalf("release audit writer: %v", err)
	}
}

// reclaimWriter takes a fresh claim and rebuilds the governance service on it,
// the way a restarted instance would.
func (h *harness) reclaimWriter() {
	h.t.Helper()
	ctx := context.Background()
	writer, err := h.store.ClaimWriter(ctx, "governance-2", "test")
	if err != nil {
		h.t.Fatalf("reclaim audit writer: %v", err)
	}
	h.t.Cleanup(func() { _ = writer.Close(context.Background()) })
	h.writer = writer

	registry, err := allHandlers(h.t, writer, h.store, h.webhook)
	if err != nil {
		h.t.Fatalf("build challenge registry: %v", err)
	}
	h.registry = registry
	revalidator, err := decision.NewRevalidator(decision.RevalidatorConfig{
		Challenges: registry, Obligations: h.obligations, Now: h.clock.Now,
	})
	if err != nil {
		h.t.Fatalf("build revalidator: %v", err)
	}
	h.gov, err = revision.New(revision.Config{
		Store: h.store, Audit: writer, Challenges: registry,
		Revalidator: revalidator, Now: h.clock.Now,
	})
	if err != nil {
		h.t.Fatalf("rebuild governance service: %v", err)
	}
}

// lock installs quorum governance with the given approvers.
func (h *harness) lock(threshold int, approvers ...string) {
	h.t.Helper()
	err := h.gov.Lock(context.Background(), revision.LockRequest{
		Actor: user("root"),
		Token: h.token,
		Quorum: policy.Quorum{
			Threshold: threshold,
			Approvers: policy.ApproverSet{Members: approvers},
		},
	})
	if err != nil {
		h.t.Fatalf("lock governance: %v", err)
	}
}

// propose submits a revision and fails the test if it is refused.
func (h *harness) propose(proposer string, d revision.Delta, mode decision.ApplicationMode) revision.Proposal {
	h.t.Helper()
	p, err := h.gov.Propose(context.Background(), revision.ProposeRequest{
		Proposer: user(proposer), Delta: d, Mode: mode,
	})
	if err != nil {
		h.t.Fatalf("propose: %v", err)
	}
	return p
}

// approve submits one approval toward a revision's governance decision, through
// the same surface an approver uses.
func (h *harness) approve(p revision.Proposal, approver string) error {
	h.t.Helper()
	svc := h.decisionService()
	_, err := svc.Submit(context.Background(), decision.Submission{
		Caller: user(approver), DecisionID: p.DecisionID, Ordinal: 0,
	})
	return err
}

// decisionService is a lifecycle service over the governance snapshot. It is
// only used to submit approvals, which is the one thing an approver's request
// path does.
func (h *harness) decisionService() *decision.Service {
	h.t.Helper()
	rec, err := store.EffectivePolicy(context.Background(), h.store.Pool(), revision.GovernancePolicyID)
	if err != nil {
		h.t.Fatalf("read governance policy: %v", err)
	}
	p, err := rec.Policy()
	if err != nil {
		h.t.Fatalf("decode governance policy: %v", err)
	}
	snap, err := engine.NewSnapshot("1", *revision.GovernanceSchema(), []engine.PolicyVersion{{
		Version: revision.GovernancePolicyID + "@1", Policy: *p,
	}})
	if err != nil {
		h.t.Fatalf("build governance snapshot: %v", err)
	}
	svc, err := decision.New(decision.Config{
		Store: h.store, Audit: h.writer, Evaluator: engine.NewDecideEvaluator(snap),
		Challenges: h.registry, MaxOutstanding: -1, Now: h.clock.Now,
	})
	if err != nil {
		h.t.Fatalf("build decision service: %v", err)
	}
	return svc
}

// tenantDecision creates a decision against the live tenant policy set, the way
// a PEP call would. The snapshot excludes the reserved policy, which is what
// every caller that assembles a tenant set has to do.
func (h *harness) tenantDecision(in engine.Input) decision.Result {
	h.t.Helper()
	ctx := context.Background()
	schema, err := store.LatestSchema(ctx, h.store.Pool())
	if err != nil {
		h.t.Fatalf("read latest schema: %v", err)
	}
	set, err := policy.Decode(strings.NewReader(schema.Document))
	if err != nil {
		h.t.Fatalf("decode schema: %v", err)
	}
	records, err := store.EffectivePolicies(ctx, h.store.Pool())
	if err != nil {
		h.t.Fatalf("read effective policies: %v", err)
	}
	var versions []engine.PolicyVersion
	for _, rec := range records {
		if revision.IsReserved(rec.ID) {
			continue
		}
		p, perr := rec.Policy()
		if perr != nil {
			h.t.Fatalf("decode policy %s: %v", rec.ID, perr)
		}
		versions = append(versions, engine.PolicyVersion{
			Version: rec.ID + "@" + strconv.FormatInt(rec.Version, 10), Policy: *p,
		})
	}
	snap, err := engine.NewSnapshot(strconv.FormatInt(schema.Version, 10), set.Schema, versions)
	if err != nil {
		h.t.Fatalf("build tenant snapshot: %v", err)
	}
	var opts []engine.Option
	if h.resolver != nil {
		opts = append(opts, engine.WithSourceResolver(h.resolver))
	}
	svc, err := decision.New(decision.Config{
		Store: h.store, Audit: h.writer,
		Evaluator:      engine.NewDecideEvaluator(snap, opts...),
		Challenges:     h.registry,
		Obligations:    h.obligations,
		MaxOutstanding: -1,
		Now:            h.clock.Now,
	})
	if err != nil {
		h.t.Fatalf("build tenant decision service: %v", err)
	}
	result, err := svc.Decide(ctx, decision.Request{Caller: user("pep"), Input: in})
	if err != nil {
		h.t.Fatalf("decide: %v", err)
	}
	return result
}

// submitApproval hands one approval to a tenant decision.
func (h *harness) submitApproval(decisionID, approver string) error {
	h.t.Helper()
	svc, err := decision.New(decision.Config{
		Store: h.store, Audit: h.writer,
		Evaluator:      engine.NewDecideEvaluator(mustEmptySnapshot(h.t)),
		Challenges:     h.registry,
		MaxOutstanding: -1,
		Now:            h.clock.Now,
	})
	if err != nil {
		h.t.Fatalf("build decision service: %v", err)
	}
	_, err = svc.Submit(context.Background(), decision.Submission{
		Caller: user(approver), DecisionID: decisionID, Ordinal: 0,
	})
	return err
}

// mustEmptySnapshot is a snapshot with no policies. Submitting an approval never
// evaluates anything, so the evaluator a submission-only service holds is
// required by the constructor and used by nothing.
func mustEmptySnapshot(t *testing.T) *engine.Snapshot {
	t.Helper()
	snap, err := engine.NewSnapshot("empty", policy.Schema{}, nil)
	if err != nil {
		t.Fatalf("build empty snapshot: %v", err)
	}
	return snap
}

func (h *harness) approvalCount(decisionID string) int {
	h.t.Helper()
	n, err := store.CountApprovals(context.Background(), h.store.Pool(), decisionID, 0, store.VerdictApprove)
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

func (h *harness) decisionPolicyVersion(id string) (string, int64) {
	h.t.Helper()
	d, err := store.GetDecision(context.Background(), h.store.Pool(), id)
	if err != nil {
		h.t.Fatalf("read decision %s: %v", id, err)
	}
	return d.PolicyID, d.PolicyVersion
}

func (h *harness) reconcile() []revision.Proposal {
	h.t.Helper()
	applied, err := h.gov.Reconcile(context.Background())
	if err != nil {
		h.t.Fatalf("reconcile: %v", err)
	}
	return applied
}

func (h *harness) effective(id string) (*policy.Policy, bool) {
	h.t.Helper()
	rec, err := store.EffectivePolicy(context.Background(), h.store.Pool(), id)
	if err != nil {
		return nil, false
	}
	if rec.Deleted {
		return nil, false
	}
	p, err := rec.Policy()
	if err != nil {
		h.t.Fatalf("decode policy %s: %v", id, err)
	}
	return p, true
}

func (h *harness) state(id string) revision.State {
	h.t.Helper()
	p, err := h.gov.Get(context.Background(), id)
	if err != nil {
		h.t.Fatalf("read revision %s: %v", id, err)
	}
	return p.State
}

func (h *harness) mode() revision.Mode {
	h.t.Helper()
	m, err := h.gov.Mode(context.Background())
	if err != nil {
		h.t.Fatalf("read governance mode: %v", err)
	}
	return m
}

// auditPayloads returns the payloads of every audit row of a kind, oldest
// first.
func (h *harness) auditPayloads(kind string) []map[string]any {
	h.t.Helper()
	rows, err := h.store.Pool().Query(context.Background(),
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

// auditPayloadsFor is auditPayloads narrowed to one subject.
func (h *harness) auditPayloadsFor(kind, subject string) []map[string]any {
	h.t.Helper()
	rows, err := h.store.Pool().Query(context.Background(),
		`SELECT payload::text FROM audit_log WHERE kind = $1 AND subject = $2 ORDER BY writer_id, seq`,
		kind, subject)
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

// challengeNeed reports the threshold a decision's quorum currently carries.
func (h *harness) challengeNeed(decisionID string) int {
	h.t.Helper()
	progress, err := store.ChallengeProgressFor(context.Background(), h.store.Pool(), decisionID)
	if err != nil {
		h.t.Fatalf("read challenge progress: %v", err)
	}
	if len(progress) == 0 {
		h.t.Fatalf("decision %s carries no challenges", decisionID)
	}
	var detail struct {
		Threshold int `json:"threshold"`
	}
	if err := json.Unmarshal(progress[0].Detail, &detail); err != nil {
		h.t.Fatalf("decode challenge detail: %v", err)
	}
	return detail.Threshold
}

// factSnapshotOf returns the fact snapshot a decision currently holds.
func (h *harness) factSnapshotOf(decisionID string) map[string]any {
	h.t.Helper()
	d, err := store.GetDecision(context.Background(), h.store.Pool(), decisionID)
	if err != nil {
		h.t.Fatalf("read decision: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(d.FactSnapshot, &out); err != nil {
		h.t.Fatalf("decode fact snapshot: %v", err)
	}
	return out
}

func (h *harness) verifyChain() {
	h.t.Helper()
	report, err := h.store.VerifyChain(context.Background())
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

func tenantSchema() *policy.Schema {
	return &policy.Schema{
		Entities: []policy.EntityType{
			{Name: "user", Attributes: []policy.Attribute{{Name: "role", Type: policy.TypeString}}},
			{Name: "account", Attributes: []policy.Attribute{{Name: "amount", Type: policy.TypeInt}}},
		},
		Actions: []policy.Action{{Name: "transfer"}, {Name: "close"}},
		Sources: []policy.SourceDecl{
			{
				Name: "risk_score", Kind: policy.SourceHTTP,
				Params: []policy.Param{{Name: "role", Type: policy.TypeString}}, Returns: policy.TypeInt,
				OnError: policy.OnErrorDeny,
			},
			{
				Name: "sanctions_hits", Kind: policy.SourceHTTP,
				Params: []policy.Param{{Name: "role", Type: policy.TypeString}}, Returns: policy.TypeInt,
				OnError: policy.OnErrorDeny,
			},
		},
	}
}

// tenantPolicy builds a gated tenant policy. Each call builds fresh condition
// values: normalization rewrites the condition tree in place, so two policies
// sharing one value would be two writers on the same nodes.
func tenantPolicy(id string, threshold int, approvers ...string) *policy.Policy {
	return &policy.Policy{
		ID:       id,
		Subject:  "user",
		Resource: "account",
		Actions:  []string{"transfer"},
		Condition: policy.Compare{
			Op: policy.OpGe, Left: policy.Field(policy.RoleResource, "amount"), Right: policy.Int(1000),
		},
		Challenges: []policy.Challenge{
			policy.Quorum{Threshold: threshold, Approvers: policy.ApproverSet{Members: approvers}},
		},
	}
}

// factPolicy reaches a fact source from its condition, so a decision made
// against it freezes a fact snapshot.
func factPolicy(id, source string, threshold int, approvers ...string) *policy.Policy {
	return &policy.Policy{
		ID:       id,
		Subject:  "user",
		Resource: "account",
		Actions:  []string{"transfer"},
		Condition: policy.Compare{
			Op:    policy.OpGe,
			Left:  policy.Source(source, policy.Field(policy.RoleSubject, "role")),
			Right: policy.Int(50),
		},
		Challenges: []policy.Challenge{
			policy.Quorum{Threshold: threshold, Approvers: policy.ApproverSet{Members: approvers}},
		},
	}
}

func user(id string) *identity.Subject {
	return &identity.Subject{Kind: identity.SubjectUser, Issuer: "https://idp.test", ID: id}
}

func transferRequest(subject string, amount int64) engine.Input {
	return engine.Input{
		Action:   "transfer",
		Subject:  engine.Entity{Type: "user", ID: subject, Attributes: map[string]any{"role": "admin"}},
		Resource: engine.Entity{Type: "account", ID: "acct-1", Attributes: map[string]any{"amount": amount}},
	}
}

// countingResolver is the fact plane. It answers every call with one value and
// counts how often it was asked, so a test can tell a frozen fact from a
// re-fetched one.
type countingResolver struct {
	mu     sync.Mutex
	value  int64
	calls  int
	sought []string
}

func newResolver(value int64) *countingResolver { return &countingResolver{value: value} }

func (r *countingResolver) ResolveSources(_ context.Context, calls []engine.SourceCall) (*engine.Facts, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	facts := engine.NewFacts()
	for _, call := range calls {
		r.sought = append(r.sought, call.Name)
		facts.Set(call, r.value)
	}
	return facts, nil
}

func (r *countingResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *countingResolver) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.sought...)
}

// ---------------------------------------------------------------------------
// the four challenge kinds
//
// M2's exit condition is that all four run together, so the harness registers
// all four rather than the quorum alone. The delay and the quorum are the real
// handlers with no configuration at all; the external handler talks to a real
// HTTP target through the real egress gate; the mfa handler holds a stub
// initiator, which is the one double here and is the seam U10 designed for —
// everything the revision path asks an mfa challenge is downstream of the
// transport.
// ---------------------------------------------------------------------------

const (
	testACR         = "urn:mace:incommon:iap:silver"
	testStrongACR   = "urn:mace:incommon:iap:gold"
	testMFAIssuer   = "https://idp.test"
	testMFAClient   = "stamp-console"
	testMFAAudience = "stamp"
)

func allHandlers(t *testing.T, writer *store.AuditWriter, s *store.Store, webhook *webhookTarget) (*challenge.Registry, error) {
	t.Helper()
	quorum, err := challenge.NewQuorum(challenge.QuorumConfig{Audit: writer, DB: s.Pool()})
	if err != nil {
		return nil, err
	}
	gate, err := fact.NewGate(fact.EgressConfig{Allow: webhook.origins(), AllowLoopback: true})
	if err != nil {
		return nil, err
	}
	external, err := challenge.NewExternal(challenge.ExternalConfig{Gate: gate, Targets: webhook.targets()})
	if err != nil {
		return nil, err
	}
	delegated, err := mfa.NewDelegated(mfa.Config{
		Initiator:        stubInitiator{},
		AllowedACRValues: []string{testACR, testStrongACR},
		Issuer:           testMFAIssuer,
		ClientID:         testMFAClient,
		Audience:         testMFAAudience,
		// Suppression is disabled so that a re-issue this package asks for is a
		// re-issue it observes. The suppression window is U10's own property and
		// is tested there.
		MinReissueInterval: -1,
	})
	if err != nil {
		return nil, err
	}
	return challenge.NewRegistry(quorum, challenge.NewDelay(challenge.DelayConfig{}), external, delegated)
}

// stubInitiator stands in for an IdP. It reports the step-up transport, which
// is D26's default path, and records nothing: what the revision path cares
// about is whether Issue was called at all, and the correlator in the stored
// detail answers that.
type stubInitiator struct{}

func (stubInitiator) Initiate(_ context.Context, req mfa.InitiateRequest) (mfa.InitiateResult, error) {
	return mfa.InitiateResult{
		Method:           mfa.MethodStepUp,
		AuthorizationURL: "https://idp.test/authorize?state=" + req.Correlator,
	}, nil
}

// webhookTarget is a real external target: a real listener, reached through the
// real egress gate, counting the notifications it received. The count is the
// assertion that matters here — a revision that re-issued an external challenge
// would show up as a second POST.
type webhookTarget struct {
	server *httptest.Server

	mu    sync.Mutex
	calls int
}

const (
	webhookPrimary   = "reviewer"
	webhookSecondary = "reviewer-b"
	webhookSecret    = "0123456789abcdef0123456789abcdef"
)

func newWebhookTarget(t *testing.T) *webhookTarget {
	t.Helper()
	w := &webhookTarget{}
	w.server = httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		w.mu.Lock()
		w.calls++
		w.mu.Unlock()
	}))
	t.Cleanup(w.server.Close)
	return w
}

func (w *webhookTarget) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.calls
}

func (w *webhookTarget) origins() []string { return []string{w.server.URL} }

// targets configures two entries pointing at the same listener. Two are needed
// because the revision case that matters is a policy repointed from one
// configured target to another, and a target the operator never configured is a
// different refusal entirely.
func (w *webhookTarget) targets() []challenge.ExternalTarget {
	return []challenge.ExternalTarget{
		{Name: webhookPrimary, URL: w.server.URL + "/a", Secret: webhookSecret},
		{Name: webhookSecondary, URL: w.server.URL + "/b", Secret: webhookSecret},
	}
}

// ---------------------------------------------------------------------------
// gated-policy fixtures for the three new kinds
// ---------------------------------------------------------------------------

// gatedPolicy is tenantPolicy with an arbitrary challenge list. Each call builds
// fresh condition values, for the reason tenantPolicy does.
func gatedPolicy(id string, challenges ...policy.Challenge) *policy.Policy {
	return &policy.Policy{
		ID:       id,
		Subject:  "user",
		Resource: "account",
		Actions:  []string{"transfer"},
		Condition: policy.Compare{
			Op: policy.OpGe, Left: policy.Field(policy.RoleResource, "amount"), Right: policy.Int(1000),
		},
		Challenges: challenges,
	}
}

func delayPolicy(id string, wait time.Duration, cancellers ...string) *policy.Policy {
	d := policy.Delay{Duration: wait}
	if len(cancellers) > 0 {
		d.CancellableBy = &policy.ApproverSet{Members: cancellers}
	}
	return gatedPolicy(id, d)
}

func mfaPolicy(id string, acr ...string) *policy.Policy {
	return gatedPolicy(id, policy.MFA{Mode: policy.MFADelegated, ACRValues: acr})
}

func externalPolicy(id, target string) *policy.Policy {
	return gatedPolicy(id, policy.External{Target: target})
}

// challengeRow reads one challenge's stored row.
func (h *harness) challengeRow(decisionID string, ordinal int) store.ChallengeProgress {
	h.t.Helper()
	rows, err := store.ChallengeProgressFor(context.Background(), h.store.Pool(), decisionID)
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

func (h *harness) delayDetail(decisionID string) challenge.DelayDetail {
	h.t.Helper()
	detail, err := challenge.DecodeDelayDetail(h.challengeRow(decisionID, 0).Detail)
	if err != nil {
		h.t.Fatalf("decode delay detail: %v", err)
	}
	return detail
}

func (h *harness) externalDetail(decisionID string) challenge.ExternalDetail {
	h.t.Helper()
	detail, err := challenge.DecodeExternalDetail(h.challengeRow(decisionID, 0).Detail)
	if err != nil {
		h.t.Fatalf("decode external detail: %v", err)
	}
	return detail
}

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
	d, err := store.GetDecision(context.Background(), h.store.Pool(), decisionID)
	if err != nil {
		h.t.Fatalf("read decision: %v", err)
	}
	return d.NextDeadline
}
