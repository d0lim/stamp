package decision_test

import (
	"context"
	"encoding/json"
	"errors"
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
