package decision_test

import (
	"context"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// A decision is a lifecycle object, so a quorum that is not yet met is not a
// deny — it is a pending decision that reports how far along it is.
func TestQuorumTwoOfThreeCollectsThenResolves(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		ttl:      30 * time.Minute,
		policies: []*policy.Policy{gatedPolicy("wire-transfer", 2, "alice", "bob", "carol")},
	})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if res.State != store.DecisionPending {
		t.Fatalf("new decision is %q, want pending", res.State)
	}
	if len(res.Challenges) != 1 {
		t.Fatalf("decision opened %d challenges, want 1", len(res.Challenges))
	}
	if got := res.Challenges[0]; got.Kind != policy.ChallengeQuorum || got.Have != 0 || got.Need != 2 {
		t.Fatalf("challenge = %+v, want a quorum at 0/2", got)
	}
	if res.ExpiresAt != h.clock.Now().Add(30*time.Minute) {
		t.Errorf("expires_at = %s, want %s", res.ExpiresAt, h.clock.Now().Add(30*time.Minute))
	}

	after, err := h.svc.Submit(ctx, decision.Submission{
		Caller: user("alice"), DecisionID: res.ID, Ordinal: 0,
	})
	if err != nil {
		t.Fatalf("submit alice: %v", err)
	}
	if after.State != store.DecisionPending {
		t.Fatalf("decision is %q after one of two approvals, want pending", after.State)
	}
	if got := after.Challenges[0]; got.Have != 1 || got.Need != 2 || got.State != challenge.StatePending {
		t.Fatalf("challenge = %+v, want pending at 1/2", got)
	}

	final, err := h.svc.Submit(ctx, decision.Submission{
		Caller: user("bob"), DecisionID: res.ID, Ordinal: 0,
	})
	if err != nil {
		t.Fatalf("submit bob: %v", err)
	}
	if !final.Allowed() {
		t.Fatalf("decision is %q after the quorum was met, want allowed", final.State)
	}
	if final.Reason != decision.ReasonChallengeSatisfied {
		t.Errorf("reason = %q, want %q", final.Reason, decision.ReasonChallengeSatisfied)
	}
	if h.decisionState(res.ID) != store.DecisionAllowed {
		t.Errorf("stored state = %q, want allowed", h.decisionState(res.ID))
	}
}

// The same quorum, left alone: reaching the deadline expires it, and the one
// approval it did collect does not carry it over the line.
func TestQuorumReachingExpiryIsExpired(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		ttl:      30 * time.Minute,
		policies: []*policy.Policy{gatedPolicy("wire-transfer", 2, "alice", "bob", "carol")},
	})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if _, err := h.svc.Submit(ctx, decision.Submission{
		Caller: user("alice"), DecisionID: res.ID, Ordinal: 0,
	}); err != nil {
		t.Fatalf("submit alice: %v", err)
	}

	h.clock.Advance(31 * time.Minute)
	report := h.sweepOnce(h.svc)
	if report.Expired != 1 {
		t.Fatalf("sweep expired %d decisions, want 1 (report %+v)", report.Expired, report)
	}
	if h.decisionState(res.ID) != store.DecisionExpired {
		t.Fatalf("stored state = %q, want expired", h.decisionState(res.ID))
	}

	got, err := h.svc.Get(ctx, workload("payments"), res.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.State != store.DecisionExpired || got.Reason != decision.ReasonExpired {
		t.Errorf("read back %q/%q, want expired/%q", got.State, got.Reason, decision.ReasonExpired)
	}
	if got.Allowed() {
		t.Error("an expired decision reported itself as allowed")
	}
}

// The sweeper is deferred cleanup, not the source of truth. An approval that
// arrives after the deadline but before the sweep must not complete a quorum,
// or the guarantee would be "expires within one sweep interval, unless someone
// is quick".
func TestApprovalAfterDeadlineDoesNotSatisfyQuorum(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		ttl:      10 * time.Minute,
		policies: []*policy.Policy{gatedPolicy("wire-transfer", 2, "alice", "bob", "carol")},
	})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if _, err := h.svc.Submit(ctx, decision.Submission{
		Caller: user("alice"), DecisionID: res.ID, Ordinal: 0,
	}); err != nil {
		t.Fatalf("submit alice: %v", err)
	}

	h.clock.Advance(11 * time.Minute)
	if h.decisionState(res.ID) != store.DecisionPending {
		t.Fatal("the row was resolved before the sweeper ran; this test is not testing what it thinks")
	}

	_, err = h.svc.Submit(ctx, decision.Submission{Caller: user("bob"), DecisionID: res.ID, Ordinal: 0})
	if !errors.Is(err, store.ErrDecisionExpired) {
		t.Fatalf("late submission returned %v, want ErrDecisionExpired", err)
	}

	if n := h.approvalCount(res.ID, 0); n != 1 {
		t.Errorf("the decision has %d approvals, want 1: the late one was recorded", n)
	}
	h.sweepOnce(h.svc)
	if got := h.decisionState(res.ID); got != store.DecisionExpired {
		t.Fatalf("stored state = %q, want expired", got)
	}
}

// R8: the obligation list is part of the decision response. R7: it is frozen on
// the audit row. The two have to be the same list, which is only interesting
// because they are produced by different code.
func TestObligationsAppearInResponseAndAuditRow(t *testing.T) {
	ctx := context.Background()
	obligations := []decision.Obligation{
		{Type: "notify", Attributes: map[string]any{"channel": "#treasury"}},
		{Type: "log_retention", Attributes: map[string]any{"days": float64(365)}},
	}
	h := newHarness(t, harnessOptions{
		policies:    []*policy.Policy{gatedPolicy("wire-transfer", 2, "alice", "bob", "carol")},
		obligations: obligations,
	})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	want := mustJSON(t, obligations)
	if got := mustJSON(t, res.Obligations); got != want {
		t.Errorf("response obligations = %s, want %s", got, want)
	}

	rows := h.auditPayloads(store.AuditKindDecisionCreated, res.ID)
	if len(rows) != 1 {
		t.Fatalf("decision.created audit rows = %d, want 1", len(rows))
	}
	if got := mustJSON(t, rows[0]["obligations"]); got != want {
		t.Errorf("audited obligations = %s, want %s", got, want)
	}

	// And they survive a read, which is where a caller that polls sees them.
	read, err := h.svc.Get(ctx, workload("payments"), res.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got := mustJSON(t, read.Obligations); got != want {
		t.Errorf("read-back obligations = %s, want %s", got, want)
	}
}

// R40: a decision is readable by the caller who created it and by the approvers
// it targets. Everyone else is refused, and the refusal is audited.
func TestReadIsLimitedToCreatorAndTargets(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		policies: []*policy.Policy{gatedPolicy("wire-transfer", 2, "alice", "bob", "carol")},
	})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}

	if _, err := h.svc.Get(ctx, workload("payments"), res.ID); err != nil {
		t.Errorf("the creating caller was refused its own decision: %v", err)
	}
	if _, err := h.svc.Get(ctx, user("carol"), res.ID); err != nil {
		t.Errorf("a target approver was refused: %v", err)
	}

	// The subject of the decision is not on the list either: the person a
	// decision is about is often the person it guards against.
	for _, stranger := range []string{"mallory", "u1"} {
		if _, err := h.svc.Get(ctx, user(stranger), res.ID); !errors.Is(err, decision.ErrNotAuthorized) {
			t.Errorf("read by %q returned %v, want ErrNotAuthorized", stranger, err)
		}
	}

	refusals := h.auditPayloads(decision.AuditKindAccessRefused, res.ID)
	if len(refusals) != 2 {
		t.Fatalf("audited access refusals = %d, want 2", len(refusals))
	}
	if got := refusals[0]["caller_id"]; got != user("mallory").CallerID() {
		t.Errorf("audited caller_id = %v, want %q", got, user("mallory").CallerID())
	}

	if _, err := h.svc.Get(ctx, nil, res.ID); !errors.Is(err, decision.ErrUnauthenticated) {
		t.Errorf("unauthenticated read returned %v, want ErrUnauthenticated", err)
	}
}

// R43: a subject that already holds the configured number of unresolved
// decisions cannot open another. The refusal is a deny with an audit row, not a
// silent drop.
func TestOutstandingCapRefusesAndAudits(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		ttl:            time.Hour,
		maxOutstanding: 2,
		policies:       []*policy.Policy{gatedPolicy("wire-transfer", 2, "alice", "bob", "carol")},
	})

	for i := 0; i < 2; i++ {
		res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
		if err != nil {
			t.Fatalf("decide %d: %v", i, err)
		}
		if res.State != store.DecisionPending {
			t.Fatalf("decide %d is %q, want pending", i, res.State)
		}
	}

	refused, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("capped decide returned an error rather than a deny: %v", err)
	}
	if refused.Outcome != engine.Deny || refused.Reason != decision.ReasonOutstandingCap {
		t.Fatalf("capped decide = %v/%q, want deny/%q", refused.Outcome, refused.Reason, decision.ReasonOutstandingCap)
	}
	if refused.ID != "" {
		t.Errorf("a refused decide created decision %q", refused.ID)
	}

	rows := h.auditPayloads(decision.AuditKindDecisionRefused, "u1")
	if len(rows) != 1 {
		t.Fatalf("audited refusals = %d, want 1", len(rows))
	}
	if rows[0]["reason"] != string(decision.ReasonOutstandingCap) {
		t.Errorf("audited reason = %v, want %q", rows[0]["reason"], decision.ReasonOutstandingCap)
	}
	if rows[0]["cap"] != float64(2) || rows[0]["outstanding"] != float64(2) {
		t.Errorf("audited cap detail = %v/%v, want 2/2", rows[0]["cap"], rows[0]["outstanding"])
	}

	// A different subject is unaffected: the cap is per subject, not global.
	if _, err := h.svc.Decide(ctx, decision.Request{
		Caller: workload("payments"), Input: transferRequest("u2"),
	}); err != nil {
		t.Fatalf("decide for a second subject: %v", err)
	}

	// And a slot comes back when a decision stops being outstanding — the
	// count is on expires_at, so it does not wait for the sweeper.
	h.clock.Advance(2 * time.Hour)
	if _, err := h.svc.Decide(ctx, decision.Request{
		Caller: workload("payments"), Input: transferRequest("u1"),
	}); err != nil {
		t.Fatalf("decide after the earlier decisions expired: %v", err)
	}
}

// A policy that demands nothing still produces a decision object: same row,
// same frozen policy version and facts, resolved in the same call.
func TestUngatedPolicyResolvesImmediately(t *testing.T) {
	ctx := context.Background()
	resolver := &recordingResolver{value: 77}
	h := newHarness(t, harnessOptions{
		policies: []*policy.Policy{factOpenPolicy("read-only")},
		resolver: resolver,
	})

	res, err := h.svc.Decide(ctx, decision.Request{
		Caller: workload("payments"),
		Input:  transferRequest("u1"),
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !res.Allowed() {
		t.Fatalf("decision is %q, want allowed", res.State)
	}
	if res.ID == "" {
		t.Fatal("an allow produced no decision object")
	}
	if res.Reason != engine.ReasonPolicyMatched {
		t.Errorf("reason = %q, want %q", res.Reason, engine.ReasonPolicyMatched)
	}
	if len(res.Challenges) != 0 {
		t.Errorf("an ungated allow opened %d challenges", len(res.Challenges))
	}
	if got := h.auditPayloads(store.AuditKindDecisionResolved, res.ID); len(got) != 1 {
		t.Errorf("decision.resolved audit rows = %d, want 1", len(got))
	}

	stored, err := store.GetDecision(ctx, h.store.Pool(), res.ID)
	if err != nil {
		t.Fatalf("read decision: %v", err)
	}
	// An immediate allow freezes its evidence too. It resolved a fact to reach
	// that allow, and a decision that cannot show what it rested on is not
	// explainable later just because nothing had to be collected.
	evaluated, err := h.evaluator().Evaluate(ctx, transferRequest("u1"))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got, want := mustJSON(t, stored.FactSnapshot), mustJSON(t, evaluated.Facts()); got != want {
		t.Errorf("frozen fact snapshot = %s, want the evaluated %s", got, want)
	}
	var frozen map[string]any
	if err := json.Unmarshal(stored.FactSnapshot, &frozen); err != nil {
		t.Fatalf("decode frozen fact snapshot: %v", err)
	}
	if len(frozen) != 1 {
		t.Errorf("frozen fact snapshot holds %d facts, want the one the condition reached", len(frozen))
	}
	if stored.PolicyVersion == 0 {
		t.Error("the decision did not pin a policy version")
	}
}

// A deny creates no decision object — there is no policy version to pin one to
// when nothing matched — but it is still audited, because a decision the system
// made and cannot show is not auditable.
func TestDenyIsAuditedWithoutADecisionRow(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u9")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if res.Outcome != engine.Deny || res.Reason != engine.ReasonNoMatchingPolicy {
		t.Fatalf("decide over an empty policy set = %v/%q, want deny/no_matching_policy", res.Outcome, res.Reason)
	}
	if res.ID != "" {
		t.Errorf("a deny created decision %q", res.ID)
	}
	rows := h.auditPayloads(decision.AuditKindDecisionRefused, "u9")
	if len(rows) != 1 {
		t.Fatalf("audited denies = %d, want 1", len(rows))
	}
	if rows[0]["caller_id"] != workload("payments").CallerID() {
		t.Errorf("audited caller_id = %v, want %q", rows[0]["caller_id"], workload("payments").CallerID())
	}

	var count int
	if err := h.store.Pool().QueryRow(ctx, `SELECT count(*) FROM decisions`).Scan(&count); err != nil {
		t.Fatalf("count decisions: %v", err)
	}
	if count != 0 {
		t.Errorf("the decisions table holds %d rows after a deny, want 0", count)
	}
}

func TestUnauthenticatedDecideIsRefusedBeforeEvaluation(t *testing.T) {
	h := newHarness(t, harnessOptions{policies: []*policy.Policy{openPolicy("read-only")}})
	if _, err := h.svc.Decide(context.Background(), decision.Request{Input: transferRequest("u1")}); !errors.Is(err, decision.ErrUnauthenticated) {
		t.Fatalf("decide without a caller returned %v, want ErrUnauthenticated", err)
	}
}

// A submission from someone the challenge does not target is refused by the
// handler and audited by the lifecycle.
func TestSubmissionFromNonTargetIsRefusedAndAudited(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		policies: []*policy.Policy{gatedPolicy("wire-transfer", 2, "alice", "bob", "carol")},
	})
	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}

	_, err = h.svc.Submit(ctx, decision.Submission{Caller: user("mallory"), DecisionID: res.ID, Ordinal: 0})
	if !errors.Is(err, challenge.ErrNotTarget) {
		t.Fatalf("submission from a non-target returned %v, want ErrNotTarget", err)
	}
	if n := h.approvalCount(res.ID, 0); n != 0 {
		t.Errorf("a refused submission recorded %d approvals", n)
	}
	if rows := h.auditPayloads(decision.AuditKindAccessRefused, res.ID); len(rows) != 1 {
		t.Errorf("audited submission refusals = %d, want 1", len(rows))
	}
}

// R7: the fact snapshot frozen onto a decision is the one the evaluation
// rested on. Not one the caller passed alongside the request, and not one
// re-resolved afterwards — the same values, from the same resolution, that
// decided whether the policy applied at all.
//
// This is load-bearing beyond tidiness. The approval binding hash is computed
// over this snapshot, and a revision preserves collected approvals only when
// that hash is unchanged. A snapshot that never gated the decision would put
// approval preservation on a value nothing checked.
func TestFrozenFactSnapshotIsTheEvaluatedOne(t *testing.T) {
	ctx := context.Background()
	resolver := &recordingResolver{value: 91}
	h := newHarness(t, harnessOptions{
		policies: []*policy.Policy{factGatedPolicy("wire-transfer", 2, "alice", "bob", "carol")},
		resolver: resolver,
	})

	// What an evaluation of this request resolves, asked independently of the
	// service that has to freeze it.
	evaluated, err := h.evaluator().Evaluate(ctx, transferRequest("u1"))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if evaluated.Facts().Len() == 0 {
		t.Fatal("the evaluation resolved no facts, so this test would pass vacuously")
	}
	want := mustJSON(t, evaluated.Facts())

	before := resolver.count()
	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if got := resolver.count() - before; got != 1 {
		t.Fatalf("decide resolved facts %d times, want exactly once", got)
	}

	stored, err := store.GetDecision(ctx, h.store.Pool(), res.ID)
	if err != nil {
		t.Fatalf("read decision: %v", err)
	}
	if got := mustJSON(t, stored.FactSnapshot); got != want {
		t.Errorf("frozen fact snapshot = %s, want the evaluated %s", got, want)
	}

	// The audit row carries the same snapshot, because that is where a
	// verifier reads it from.
	rows := h.auditPayloads(store.AuditKindDecisionCreated, res.ID)
	if len(rows) != 1 {
		t.Fatalf("decision.created audit rows = %d, want 1", len(rows))
	}
	if got := mustJSON(t, rows[0]["fact_snapshot"]); got != want {
		t.Errorf("audited fact snapshot = %s, want the evaluated %s", got, want)
	}
}

// A decision must outlive the challenges it opened. A cooling-off period longer
// than the default lifetime would otherwise be unsatisfiable by construction.
func TestDecisionOutlivesALongerChallengeTimer(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		ttl:      15 * time.Minute,
		policies: []*policy.Policy{delayedPolicy("cooling-off", 2*time.Hour)},
	})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	deadline := res.Challenges[0].Deadline
	if deadline == nil {
		t.Fatal("the delay challenge opened without a timer")
	}
	if res.ExpiresAt.Before(*deadline) {
		t.Fatalf("decision expires at %s, before its own challenge deadline %s", res.ExpiresAt, *deadline)
	}
}

// mustJSON canonicalizes a value to JSON with map keys sorted, so that a list
// of obligations compares equal whether it arrived as a typed slice from the
// response or as decoded JSON from the audit row.
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode %T: %v", v, err)
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("decode %T: %v", v, err)
	}
	canonical, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-encode %T: %v", v, err)
	}
	return string(canonical)
}

// ---------------------------------------------------------------------------
// what a caller is told about a challenge in progress (R2, R28)
//
// A challenge that is completed in a browser is unreachable unless the response
// says where to send the subject. The stored detail already knows — and it also
// knows the correlator, the nonce and the PKCE verifier, none of which a caller
// is owed. So the handler publishes a chosen field and the lifecycle copies that
// field, rather than the lifecycle projecting a detail it cannot read safely.
// ---------------------------------------------------------------------------

// TestAChallengeViewCarriesWhereToSendTheSubject is the gap this unit closes:
// before it, a decision waiting on a delegated MFA challenge told its caller
// that an `mfa` challenge was pending and nothing about how to satisfy it.
func TestAChallengeViewCarriesWhereToSendTheSubject(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		ttl:      30 * time.Minute,
		policies: []*policy.Policy{mfaPolicy("ledger-export")},
	})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if len(res.Challenges) != 1 || res.Challenges[0].Kind != policy.ChallengeMFA {
		t.Fatalf("challenges = %+v, want one mfa challenge", res.Challenges)
	}
	if got := res.Challenges[0].AuthorizationURL; got != testAuthorizationURL {
		t.Fatalf("authorization url = %q, want %q", got, testAuthorizationURL)
	}

	// A later read is the caller's second chance to find it — a PEP that lost
	// the create response has no other way back to the URL.
	again, err := h.svc.Get(ctx, workload("payments"), res.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got := again.Challenges[0].AuthorizationURL; got != testAuthorizationURL {
		t.Fatalf("authorization url on read = %q, want %q", got, testAuthorizationURL)
	}
}

// TestAChallengeViewCarriesNoStoredSecret is the reason this unit is a whitelist
// rather than a projection of the stored detail.
//
// It scans the serialized response for the secret values themselves and not for
// the names of the fields holding them, because a correlator pasted into a URL's
// `state` has leaked exactly as much as a correlator in a `correlator` field.
func TestAChallengeViewCarriesNoStoredSecret(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		ttl:      30 * time.Minute,
		policies: []*policy.Policy{mfaPolicy("ledger-export")},
	})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("encode result: %v", err)
	}
	body := string(raw)
	var decoded struct {
		Challenges []map[string]any `json:"challenges"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(decoded.Challenges) != 1 {
		t.Fatalf("challenges = %v, want one", decoded.Challenges)
	}
	// The response has to be worth scanning: a view that published nothing
	// would satisfy every assertion below for the wrong reason. The check is on
	// the decoded value rather than on the bytes because encoding/json escapes
	// `&`, which a query string is full of and a secret is not.
	if got := decoded.Challenges[0]["authorization_url"]; got != testAuthorizationURL {
		t.Fatalf("the response carries no authorization url, so this scan proves nothing: %s", body)
	}
	for name, secret := range map[string]string{
		"correlator":    testCorrelator,
		"nonce":         testMFANonce,
		"code_verifier": testCodeVerifier,
	} {
		if strings.Contains(body, secret) {
			t.Errorf("the decision response carries the challenge's %s: %s", name, body)
		}
	}
	// And the field names too: a caller that can read a key called `correlator`
	// has been handed one whatever the value turned out to be.
	for _, banned := range []string{"correlator", "nonce", "code_verifier", "detail", "subject_id"} {
		if _, ok := decoded.Challenges[0][banned]; ok {
			t.Errorf("the challenge view carries a %q field: %v", banned, decoded.Challenges[0])
		}
	}
}

// TestTheSecretScanCatchesAHandlerThatPublishesOne keeps the test above from
// being vacuous. It registers a handler that makes the mistake — the correlator
// smuggled into the published URL rather than into a field of its own — and
// asserts the same scan finds it.
//
// Without this, a whitelist that published nothing at all would leave the suite
// green while closing nothing.
func TestTheSecretScanCatchesAHandlerThatPublishesOne(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		ttl:        30 * time.Minute,
		policies:   []*policy.Policy{mfaPolicy("ledger-export")},
		mfaHandler: &leakyStepUpHandler{},
	})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("encode result: %v", err)
	}
	if !strings.Contains(string(raw), testCorrelator) {
		t.Fatalf("a handler that publishes the correlator produced a response without it, "+
			"so the scan in TestAChallengeViewCarriesNoStoredSecret proves nothing: %s", raw)
	}
}

// TestChallengeKindsWithNothingToPublishSerializeUnchanged is the compatibility
// half: a quorum and a delay answer no view seam, and their responses have to
// look to an existing consumer exactly as they did before this field existed.
func TestChallengeKindsWithNothingToPublishSerializeUnchanged(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		ttl:      30 * time.Minute,
		policies: []*policy.Policy{quorumAndDelayPolicy("wire-transfer", 2, "alice", "bob")},
	})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if len(res.Challenges) != 2 {
		t.Fatalf("challenges = %+v, want a quorum and a delay", res.Challenges)
	}
	for _, c := range res.Challenges {
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("encode challenge view: %v", err)
		}
		var view map[string]any
		if err := json.Unmarshal(raw, &view); err != nil {
			t.Fatalf("decode challenge view: %v", err)
		}
		if _, ok := view["authorization_url"]; ok {
			t.Errorf("a %s challenge grew an authorization_url: %s", c.Kind, raw)
		}
		// The fields an existing consumer reads are all still there and are
		// still the only ones.
		for _, want := range []string{"ordinal", "kind", "state", "have", "need"} {
			if _, ok := view[want]; !ok {
				t.Errorf("a %s challenge lost its %q: %s", c.Kind, want, raw)
			}
		}
	}
}

// TestAHandlerThatPublishesNothingDoesNotBreakTheView asks the assembly question
// directly: one decision, two challenges, one of the two answering the optional
// interface. Neither the missing implementation nor the present one may cost the
// other its view.
func TestAHandlerThatPublishesNothingDoesNotBreakTheView(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		ttl:      30 * time.Minute,
		policies: []*policy.Policy{mfaAndQuorumPolicy("dual-control", "alice")},
	})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if len(res.Challenges) != 2 {
		t.Fatalf("challenges = %+v, want two", res.Challenges)
	}
	byKind := map[policy.ChallengeType]decision.ChallengeView{}
	for _, c := range res.Challenges {
		byKind[c.Kind] = c
	}
	if got := byKind[policy.ChallengeMFA].AuthorizationURL; got != testAuthorizationURL {
		t.Errorf("the mfa challenge's authorization url = %q, want %q", got, testAuthorizationURL)
	}
	if got := byKind[policy.ChallengeQuorum].AuthorizationURL; got != "" {
		t.Errorf("the quorum challenge published %q, want nothing", got)
	}
	if got := byKind[policy.ChallengeQuorum]; got.Need != 1 {
		t.Errorf("the quorum challenge lost its progress counts: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// the ground a shed challenge denies on (#40, the half U4 could not reach)
// ---------------------------------------------------------------------------

// U4 gave the challenge-issuance limit a word of its own — `issue_rate_limited`
// — but that word lives on the challenge row, and the decision it denied still
// reported `challenge_failed`: the same word a step-up the subject rejected
// produces. An operator watching denies could not tell "the person refused" from
// "we never asked", and those call for opposite responses.
//
// So the assertion is a separation, not an equality. The ground of a decision
// denied by a shed issuance has to differ from all four of the other ways a
// decide can come back denied.
func TestAShedChallengeDeniesOnItsOwnGround(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		ttl:        time.Hour,
		policies:   []*policy.Policy{mfaPolicy("step-up")},
		mfaHandler: &refusingStepUpHandler{shed: true},
	})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if res.State != store.DecisionDenied {
		t.Fatalf("a decision whose only challenge was shed is %q, want denied", res.State)
	}
	if res.Reason != decision.ReasonChallengeRateLimited {
		t.Fatalf("reason = %q, want %q", res.Reason, decision.ReasonChallengeRateLimited)
	}
	for name, other := range map[string]engine.Reason{
		"a challenge that was answered and not met": decision.ReasonChallengeFailed,
		"the outstanding-decision cap":              decision.ReasonOutstandingCap,
		"the decide surface's own rate limit":       decision.ReasonRateLimited,
		"a policy that matched nothing":             engine.ReasonNoMatchingPolicy,
		"a policy whose condition was not met":      engine.ReasonConditionNotMet,
	} {
		if res.Reason == other {
			t.Errorf("a shed issuance is reported as %s (%q)", name, other)
		}
	}

	// The ground is derived on every read rather than remembered, so the read
	// has to agree with the response that created the decision. A reason that
	// was right once and wrong afterwards is worse than one that was never
	// right, because only the second is noticed.
	got, err := h.svc.Get(ctx, workload("payments"), res.ID)
	if err != nil {
		t.Fatalf("read the decision back: %v", err)
	}
	if got.Reason != decision.ReasonChallengeRateLimited {
		t.Errorf("the decision reads back as %q, want %q", got.Reason, decision.ReasonChallengeRateLimited)
	}
}

// The other half of the separation: a challenge that failed for any reason other
// than being shed still denies on the old ground. The bit is one bit and it is
// not set by "failed".
func TestAChallengeThatFailedForAnotherReasonStillSaysChallengeFailed(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		ttl:        time.Hour,
		policies:   []*policy.Policy{mfaPolicy("step-up")},
		mfaHandler: &refusingStepUpHandler{shed: false},
	})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if res.State != store.DecisionDenied {
		t.Fatalf("state = %q, want denied", res.State)
	}
	if res.Reason != decision.ReasonChallengeFailed {
		t.Errorf("reason = %q, want %q", res.Reason, decision.ReasonChallengeFailed)
	}
}

// ---------------------------------------------------------------------------
// idempotent decide (#47(a))
// ---------------------------------------------------------------------------

// A client that times out and retries must not leave a decision nobody can name
// behind, and — the part a unique index cannot deliver — must not push a second
// prompt at the person.
//
// The issuance tally is the assertion that matters. Decide mints the identifier,
// issues every challenge and only then writes the row, so a key enforced solely
// as a uniqueness constraint at insert time would send the subject a second
// step-up on every retry and refuse afterwards. That is why the lookup stands
// ahead of the evaluation rather than beside the insert (KTD5).
func TestARetriedDecideReturnsTheSameDecisionAndIssuesNoSecondChallenge(t *testing.T) {
	ctx := context.Background()
	issuer := &countingStepUpHandler{}
	h := newHarness(t, harnessOptions{
		ttl:        time.Hour,
		policies:   []*policy.Policy{mfaPolicy("step-up")},
		mfaHandler: issuer,
	})

	req := decision.Request{
		Caller:         workload("payments"),
		Input:          transferRequest("u1"),
		IdempotencyKey: "transfer-9f3c",
	}
	first, err := h.svc.Decide(ctx, req)
	if err != nil {
		t.Fatalf("first decide: %v", err)
	}
	if first.ID == "" {
		t.Fatal("the first decide created no decision")
	}
	if issuer.count() != 1 {
		t.Fatalf("the first decide issued %d challenges, want 1", issuer.count())
	}

	second, err := h.svc.Decide(ctx, req)
	if err != nil {
		t.Fatalf("retried decide: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("the retry answered decision %q, want the first one %q", second.ID, first.ID)
	}
	if second.State != first.State {
		t.Errorf("the retry reported state %q, want %q", second.State, first.State)
	}
	if issuer.count() != 1 {
		t.Errorf("challenges issued after one retry = %d, want 1: the retry reached the IdP again",
			issuer.count())
	}
	if got := countDecisions(t, h); got != 1 {
		t.Errorf("the decisions table holds %d rows after one retry, want 1", got)
	}
	// The retry answers the decision as it stands, so the caller that lost the
	// first response gets the same thing it would have got by reading the row.
	if len(second.Challenges) != len(first.Challenges) {
		t.Errorf("the retry reported %d challenges, want %d", len(second.Challenges), len(first.Challenges))
	}
}

// The key is the caller's, not the deployment's. Two workloads that happen to
// number their retries the same way are two callers, and one of them must not
// receive the other's decision — which would hand it a decision identifier it
// may then read (R40).
func TestTheSameKeyFromADifferentCallerIsADifferentDecision(t *testing.T) {
	ctx := context.Background()
	issuer := &countingStepUpHandler{}
	h := newHarness(t, harnessOptions{
		ttl:        time.Hour,
		policies:   []*policy.Policy{mfaPolicy("step-up")},
		mfaHandler: issuer,
	})

	one, err := h.svc.Decide(ctx, decision.Request{
		Caller: workload("payments"), Input: transferRequest("u1"), IdempotencyKey: "retry-1",
	})
	if err != nil {
		t.Fatalf("decide as payments: %v", err)
	}
	two, err := h.svc.Decide(ctx, decision.Request{
		Caller: workload("ledger"), Input: transferRequest("u1"), IdempotencyKey: "retry-1",
	})
	if err != nil {
		t.Fatalf("decide as ledger: %v", err)
	}
	if one.ID == two.ID {
		t.Errorf("two callers sharing the key %q got one decision %q", "retry-1", one.ID)
	}
	if issuer.count() != 2 {
		t.Errorf("challenges issued = %d, want 2: two callers are two decisions", issuer.count())
	}
	if got := countDecisions(t, h); got != 2 {
		t.Errorf("the decisions table holds %d rows, want 2", got)
	}
}

// A caller that names nothing is retrying nothing. Two identical calls with no
// key are two decisions, exactly as they were before the key existed.
func TestDecidesWithoutAKeyAreStillTwoDecisions(t *testing.T) {
	ctx := context.Background()
	issuer := &countingStepUpHandler{}
	h := newHarness(t, harnessOptions{
		ttl:        time.Hour,
		policies:   []*policy.Policy{mfaPolicy("step-up")},
		mfaHandler: issuer,
	})

	req := decision.Request{Caller: workload("payments"), Input: transferRequest("u1")}
	one, err := h.svc.Decide(ctx, req)
	if err != nil {
		t.Fatalf("first decide: %v", err)
	}
	two, err := h.svc.Decide(ctx, req)
	if err != nil {
		t.Fatalf("second decide: %v", err)
	}
	if one.ID == two.ID {
		t.Errorf("two keyless decides collapsed into decision %q", one.ID)
	}
	if issuer.count() != 2 {
		t.Errorf("challenges issued = %d, want 2: a keyless decide opens its own challenge", issuer.count())
	}
	if got := countDecisions(t, h); got != 2 {
		t.Errorf("the decisions table holds %d rows, want 2", got)
	}
}

// The lookup ahead of the evaluation is what a retry hits; the unique index is
// what a race hits. Two calls that both miss the lookup still converge on one
// decision, because the second insert violates the index and the loser reads the
// winner's row rather than reporting a conflict to a caller that did nothing
// wrong.
//
// The second challenge issuance is not asserted away here, and that is honest:
// in a true race both callers are already past the lookup and past the issue
// loop before either row lands. The backstop bounds the damage to one extra
// prompt in a genuine race, which is a different thing from one extra prompt on
// every retry.
func TestConcurrentDecidesUnderOneKeyConvergeOnOneDecision(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		ttl:      time.Hour,
		policies: []*policy.Policy{gatedPolicy("wire-transfer", 2, "alice", "bob")},
	})

	const racers = 4
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		ids     []string
		errored []error
	)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res, err := h.svc.Decide(ctx, decision.Request{
				Caller: workload("payments"), Input: transferRequest("u1"), IdempotencyKey: "race-1",
			})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errored = append(errored, err)
				return
			}
			ids = append(ids, res.ID)
		}()
	}
	close(start)
	wg.Wait()

	for _, err := range errored {
		t.Errorf("a racing decide failed rather than converging: %v", err)
	}
	if len(ids) != racers {
		t.Fatalf("%d of %d racing decides answered", len(ids), racers)
	}
	for _, id := range ids {
		if id != ids[0] {
			t.Fatalf("racing decides answered %v, want one decision", ids)
		}
	}
	if got := countDecisions(t, h); got != 1 {
		t.Errorf("the decisions table holds %d rows after a race under one key, want 1", got)
	}
}

// A conflicting insert is reported as [store.ErrConflict] and not as an opaque
// database failure, on the precedent of approvals_unique_approver: the service
// re-reads on it, and a driver error it could not classify would come back out
// of decide as a 500 for what is a retry.
func TestASecondDecisionUnderOneKeyIsAConflict(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{ttl: time.Hour, policies: []*policy.Policy{openPolicy("read-only")}})

	first, err := h.svc.Decide(ctx, decision.Request{
		Caller: workload("payments"), Input: transferRequest("u1"), IdempotencyKey: "dup-1",
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	stored, err := store.GetDecision(ctx, h.store.Pool(), first.ID)
	if err != nil {
		t.Fatalf("read decision: %v", err)
	}

	_, err = h.writer.CreateDecision(ctx, store.NewDecision{
		CallerID:       stored.CallerID,
		PolicyID:       stored.PolicyID,
		PolicyVersion:  stored.PolicyVersion,
		SubjectID:      stored.SubjectID,
		ResourceID:     stored.ResourceID,
		Action:         stored.Action,
		Request:        json.RawMessage(stored.Request),
		FactSnapshot:   json.RawMessage(stored.FactSnapshot),
		ExpiresAt:      stored.ExpiresAt,
		IdempotencyKey: "dup-1",
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a second decision under one key returned %v, want store.ErrConflict", err)
	}
}

func countDecisions(t *testing.T, h *harness) int {
	t.Helper()
	var n int
	if err := h.store.Pool().QueryRow(context.Background(), `SELECT count(*) FROM decisions`).Scan(&n); err != nil {
		t.Fatalf("count decisions: %v", err)
	}
	return n
}

// TestTheDecisionLayerKnowsAChallengeKindInOneKnownPlace is KTD1 as an
// assertion, written against what is true rather than against what the plan
// assumed.
//
// The rule is that this package combines challenge answers without knowing which
// kinds exist: the moment it imports one it can be asked to special-case it, and
// the next kind arrives as a second special case. `deploy/demo/README.md` states
// the rule and the open-issues plan restates it as KTD1.
//
// **The rule already has one exception, and it predates this unit.** R31
// revalidation (`revalidate.go`) imports the delegated MFA package to ask whether
// a policy revision preserved a completion, because re-issuing a step-up is not
// a neutral way to bring a challenge up to date — it rotates the correlator and
// moves the freshness floor. That is a real reason and a real violation; naming
// it is what keeps it from being joined by others.
//
// So the assertion is per file: no file in this package may reach a challenge
// kind except the one that already does. In particular `service.go`, which
// assembles the view, may not — a type assertion against an optional interface
// is the whole point of the seam, and reaching for the concrete type is the
// mutation this test is pointed at.
func TestTheDecisionLayerKnowsAChallengeKindInOneKnownPlace(t *testing.T) {
	// The file allowed to know a kind, and why.
	known := map[string]string{
		"revalidate.go": "R31 revalidation asks mfa whether a revision preserved a completion",
	}
	byFile := directInternalImports(t, "internal/decision")
	if len(byFile) == 0 {
		t.Fatal("the import scan read no files, so it proves nothing")
	}
	const kindPrefix = "github.com/d0lim/stamp/internal/challenge/"
	saw := map[string]bool{}
	for file, imports := range byFile {
		for _, imported := range imports {
			if !strings.HasPrefix(imported, kindPrefix) {
				continue
			}
			if why, ok := known[file]; ok {
				saw[file] = true
				t.Logf("known exception: %s imports %s — %s", file, imported, why)
				continue
			}
			t.Errorf("%s imports the challenge kind %s; the lifecycle must ask through "+
				"an optional interface on challenge.Handler instead", file, imported)
		}
	}
	for file, why := range known {
		if !saw[file] {
			t.Logf("%s no longer imports a challenge kind (%s); drop it from the exceptions", file, why)
		}
	}
}

// TestTheChallengeContractDoesNotImportAChallengeKind guards the seam itself.
//
// Every kind imports the contract, so the contract importing a kind would be a
// cycle — but the interesting failure is not the cycle, it is a helper landing in
// the contract package that only one kind needs. The whole point of an optional
// interface is that the contract stays the four things every handler answers.
func TestTheChallengeContractDoesNotImportAChallengeKind(t *testing.T) {
	const root = "github.com/d0lim/stamp/internal/challenge"
	deps := transitiveInternalImports(t, root)
	// The walk has to have walked: a typo in the root would report every
	// forbidden package as absent.
	if len(deps) < 2 {
		t.Fatalf("the import walk found nothing beyond the root, so it proves nothing: %v", deps)
	}
	for pkg := range deps {
		if strings.HasPrefix(pkg, root+"/") {
			t.Errorf("the challenge contract reaches the kind %s:\n  %s",
				pkg, strings.Join(importChain(deps, pkg), "\n  -> "))
		}
	}
}

// directInternalImports maps each non-test source file of a package directory to
// the module-internal packages it imports.
func directInternalImports(t *testing.T, dir string) map[string][]string {
	t.Helper()
	const module = "github.com/d0lim/stamp/"
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("locate repository root: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(repo, filepath.FromSlash(dir)))
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	out := map[string][]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(repo, filepath.FromSlash(dir), name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		out[name] = nil
		for _, spec := range file.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("import path %s in %s: %v", spec.Path.Value, name, err)
			}
			if strings.HasPrefix(imported, module) {
				out[name] = append(out[name], imported)
			}
		}
	}
	return out
}

// transitiveInternalImports walks the module's own import graph from a package,
// reading source rather than asking the toolchain, and returns every reachable
// module-internal package mapped to the package that pulled it in.
//
// Test files are skipped on purpose: what a package imports and what its tests
// import are different claims, and only the first one ships.
func transitiveInternalImports(t *testing.T, root string) map[string]string {
	t.Helper()
	const module = "github.com/d0lim/stamp/"
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("locate repository root: %v", err)
	}
	seen := map[string]string{root: ""}
	queue := []string{root}
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		dir := filepath.Join(repo, filepath.FromSlash(strings.TrimPrefix(pkg, module)))
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read package %s: %v", pkg, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			for _, spec := range file.Imports {
				imported, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatalf("import path %s in %s: %v", spec.Path.Value, name, err)
				}
				if !strings.HasPrefix(imported, module) {
					continue
				}
				if _, ok := seen[imported]; ok {
					continue
				}
				seen[imported] = pkg
				queue = append(queue, imported)
			}
		}
	}
	return seen
}

// importChain reconstructs how a package was reached, so a failure names the
// edge to delete instead of only the destination.
func importChain(from map[string]string, target string) []string {
	var chain []string
	for at := target; at != ""; at = from[at] {
		chain = append([]string{at}, chain...)
	}
	return chain
}
