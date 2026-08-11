package runtime

// wiring_test.go is M1's exit condition — F1 and F2 demonstrated end to end
// through the assembled process, against a real Postgres — and M2's, which adds
// F3: a decision gated by a delay, carried across three revisions.
//
// Every flow is driven over HTTP against the process's own listeners, with
// tokens from a real OIDC issuer, because the point is that the units meet —
// and every one of them meets the others at a boundary that only exists once
// the composition root is there.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/challenge/mfa"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// ---------------------------------------------------------------------------
// F1 — 계좌 화이트리스트 검사 (R1, R7, R13, R14)
// ---------------------------------------------------------------------------

// TestF1AccountWhitelistCheck walks the whole check path: a PEP presents a
// workload credential, the request matches a policy, the policy reaches a
// synchronous fact source over the egress gate, the condition is evaluated, and
// the caller gets an immediate AuthZEN verdict that lands in the audit chain.
func TestF1AccountWhitelistCheck(t *testing.T) {
	h := newHarness(t, harnessOptions{writerID: "f1-writer"})
	h.seed(tenantSchema(), whitelistPolicy("whitelist-transfer"))

	pep := h.idp.workload(t, "svc-payments")

	t.Run("an unauthenticated request is refused before evaluation", func(t *testing.T) {
		// R40: the refusal is the credential check, not a deny with a reason.
		code, _ := h.do(http.MethodPost, api.SurfacePEP, api.EvaluationPath, "",
			evaluation("1001", "2002", "transfer"), nil)
		if code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated evaluation = %d, want %d", code, http.StatusUnauthorized)
		}
		if h.upstream.count() != 0 {
			t.Errorf("the fact source was called %d times for a refused request, want 0", h.upstream.count())
		}
	})

	t.Run("a whitelisted destination is allowed", func(t *testing.T) {
		decisionValue, reason, policyID := h.evaluate(t, pep, evaluation("1001", "2002", "transfer"))
		if !decisionValue {
			t.Fatalf("transfer to a whitelisted account = deny (%s), want allow", reason)
		}
		if reason != string(engine.ReasonPolicyMatched) {
			t.Errorf("reason = %q, want %q", reason, engine.ReasonPolicyMatched)
		}
		if policyID != "whitelist-transfer" {
			t.Errorf("policy id = %q, want %q", policyID, "whitelist-transfer")
		}
		if h.upstream.count() != 1 {
			t.Fatalf("the fact source was called %d times, want 1", h.upstream.count())
		}
	})

	t.Run("a destination off the whitelist is denied", func(t *testing.T) {
		decisionValue, reason, _ := h.evaluate(t, pep, evaluation("1001", "9999", "transfer"))
		if decisionValue {
			t.Fatal("transfer to an account off the whitelist was allowed")
		}
		if reason != string(engine.ReasonConditionNotMet) {
			t.Errorf("reason = %q, want %q", reason, engine.ReasonConditionNotMet)
		}
	})

	t.Run("a repeat lookup is served from the declared TTL", func(t *testing.T) {
		// R14: the freshness bound is the source declaration's TTL, and the
		// second judgment within it does not reach the network again. The deny
		// above used the same source argument, so the count is still one.
		before := h.upstream.count()
		allowed, reason, _ := h.evaluate(t, pep, evaluation("1001", "2002", "transfer"))
		if !allowed {
			t.Fatalf("the repeated transfer was denied (%s)", reason)
		}
		if after := h.upstream.count(); after != before {
			t.Errorf("the fact source was called %d more times inside its TTL, want 0", after-before)
		}
	})

	t.Run("an unmatched action denies with no matching policy", func(t *testing.T) {
		// R53: a request no policy governs is a deny, and the ground says so.
		decisionValue, reason, _ := h.evaluate(t, pep, evaluation("1001", "2002", "close"))
		if decisionValue {
			t.Fatal("an action no policy governs was allowed")
		}
		if reason != string(engine.ReasonNoMatchingPolicy) {
			t.Errorf("reason = %q, want %q", reason, engine.ReasonNoMatchingPolicy)
		}
	})

	t.Run("the judgments reach the audit chain", func(t *testing.T) {
		// R7: the check path batches its judgments into one chain row per
		// batch, and the chain has to verify with them in it.
		batches := h.awaitAudit(t, store.AuditKindCheckBatch, 1)
		var counted float64
		for _, b := range batches {
			if n, ok := b["count"].(float64); ok {
				counted += n
			}
		}
		if counted < 4 {
			t.Errorf("the chain accounts for %v check events, want at least the 4 this test made", counted)
		}
		h.verifyChain()
	})
}

// ---------------------------------------------------------------------------
// F2 — 정책 수정 정족수 승인 (R2, R3, R4, R6, R7, R21, R23)
// ---------------------------------------------------------------------------

// TestF2RevisionQuorumApproval walks the whole decide path for a policy change:
// governance is locked with a quorum, an author submits a revision, the
// revision becomes a pending decision with a quorum challenge, two approvers
// approve through the console surface, and on the second approval the decision
// resolves to allow, the revision takes effect, and the chosen application mode
// runs against the decisions that were already open.
func TestF2RevisionQuorumApproval(t *testing.T) {
	h := newHarness(t, harnessOptions{writerID: "f2-writer"})
	h.seed(tenantSchema(),
		whitelistPolicy("whitelist-transfer"),
		closurePolicy("closure-approval", 1, "carol"))

	author := h.idp.user(t, "author")
	alice := h.idp.user(t, "alice")
	bob := h.idp.user(t, "bob")

	// A tenant decision that is already open when the revision lands. R5's
	// application mode is about these, so without one the mode would run over
	// an empty set and prove nothing.
	open, err := h.app.Decisions().Decide(context.Background(), decision.Request{
		Caller: &identity.Subject{Kind: identity.SubjectWorkload, Issuer: h.idp.server.URL, ID: "svc-ops"},
		Input: engine.Input{
			Action:   "close",
			Subject:  engine.Entity{Type: "account", ID: "acct-src", Attributes: map[string]any{"number": "1001"}},
			Resource: engine.Entity{Type: "account", ID: "acct-dst", Attributes: map[string]any{"amount": int64(5000)}},
		},
	})
	if err != nil {
		t.Fatalf("open a tenant decision: %v", err)
	}
	if !open.Pending() {
		t.Fatalf("the tenant decision is %s, want it pending on its quorum", open.State)
	}

	t.Run("governance starts in solo-admin mode with a live bootstrap token", func(t *testing.T) {
		if h.app.BootstrapToken() == "" {
			t.Fatal("the first start issued no bootstrap token")
		}
		code, body := h.do(http.MethodGet, api.SurfaceConsole, "/governance", author, "", nil)
		if code != http.StatusOK {
			t.Fatalf("GET /governance = %d: %s", code, body)
		}
		var view api.GovernanceView
		h.decode(body, &view)
		if view.Mode != revision.ModeSolo {
			t.Errorf("mode = %q, want %q", view.Mode, revision.ModeSolo)
		}
		if view.Bootstrap == nil || !view.Bootstrap.Issued || view.Bootstrap.Consumed {
			t.Errorf("bootstrap status = %+v, want issued and unconsumed", view.Bootstrap)
		}
	})

	t.Run("the lock installs a quorum and consumes the token", func(t *testing.T) {
		code, body := h.do(http.MethodPost, api.SurfaceConsole, "/governance/lock",
			h.idp.user(t, "root"), `{"threshold": 2, "approvers": ["alice", "bob"]}`,
			map[string]string{api.BootstrapTokenHeader: h.app.BootstrapToken()})
		if code != http.StatusOK {
			t.Fatalf("POST /governance/lock = %d: %s", code, body)
		}
		mode, err := h.app.Governance().Mode(context.Background())
		if err != nil {
			t.Fatalf("read governance mode: %v", err)
		}
		if mode != revision.ModeQuorum {
			t.Fatalf("mode after the lock = %q, want %q", mode, revision.ModeQuorum)
		}
	})

	// The revision itself: one added policy. Adding is not a weakening, so the
	// requirement is the governance quorum in force plus the operator floor.
	added := whitelistPolicy("whitelist-transfer-audit")
	added.Description = "a second reading of the same rule, added by revision"
	delta := revision.Single(nil, added)

	var proposal revision.Proposal
	t.Run("the revision is refused nothing and becomes a pending decision", func(t *testing.T) {
		// R23: the author sees the classification and the affected decisions
		// before submitting.
		preview := h.preview(t, author, delta)
		if preview.Weakening {
			t.Errorf("adding a policy classified as weakening: %+v", preview.Findings)
		}
		if preview.Threshold != 2 {
			t.Errorf("preview threshold = %d, want 2", preview.Threshold)
		}
		if preview.AffectedDecisions != 1 {
			t.Errorf("preview affected decisions = %d, want the one that is open", preview.AffectedDecisions)
		}
		if !preview.Admissible() {
			t.Fatalf("the revision is inadmissible: %v", preview.Violations)
		}

		// R6: a policy change goes through STAMP's own decide.
		proposal = h.propose(t, author, delta, decision.ModeRevaluate)
		if proposal.State != revision.StatePending {
			t.Fatalf("proposal state = %q, want %q", proposal.State, revision.StatePending)
		}
		if proposal.DecisionID == "" {
			t.Fatal("the proposal carries no decision")
		}
		if proposal.Threshold != 2 {
			t.Errorf("proposal threshold = %d, want 2", proposal.Threshold)
		}
		if _, ok := h.effective("whitelist-transfer-audit"); ok {
			t.Error("the revised policy took effect before the quorum was collected")
		}
	})

	t.Run("an approver reads what they are being asked to authorise", func(t *testing.T) {
		// R21: the approval screen's read, including R31's binding hash.
		path := fmt.Sprintf("/decisions/%s/challenges/0/approval", proposal.DecisionID)
		code, body := h.do(http.MethodGet, api.SurfaceConsole, path, alice, "", nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", path, code, body)
		}
		var review struct {
			BindingHash string `json:"binding_hash"`
			Have        int    `json:"have"`
			Need        int    `json:"need"`
		}
		h.decode(body, &review)
		if review.BindingHash == "" {
			t.Error("the review carries no binding hash")
		}
		if review.Have != 0 || review.Need != 2 {
			t.Errorf("progress = %d of %d, want 0 of 2", review.Have, review.Need)
		}
	})

	t.Run("the proposer's own approval does not count", func(t *testing.T) {
		// R33's floor, enforced by the quorum handler rather than arithmetic
		// after the fact: the proposer was removed from the eligible set.
		code, _ := h.approve(t, proposal.DecisionID, author)
		if code == http.StatusOK {
			t.Fatal("the proposer's approval was accepted")
		}
	})

	t.Run("the quorum resolves the decision and the revision takes effect", func(t *testing.T) {
		if code, body := h.approve(t, proposal.DecisionID, alice); code != http.StatusOK {
			t.Fatalf("alice's approval = %d: %s", code, body)
		}
		if state := h.decisionState(proposal.DecisionID); state != store.DecisionPending {
			t.Fatalf("the decision is %s after one of two approvals, want pending", state)
		}
		if _, ok := h.effective("whitelist-transfer-audit"); ok {
			t.Fatal("the revision took effect on one of two approvals")
		}

		if code, body := h.approve(t, proposal.DecisionID, bob); code != http.StatusOK {
			t.Fatalf("bob's approval = %d: %s", code, body)
		}
		// R4: the decision transitions out of pending on the quorum.
		if state := h.decisionState(proposal.DecisionID); state != store.DecisionAllowed {
			t.Fatalf("the decision is %s after the quorum, want allowed", state)
		}
		// The approval surface reconciles inline, so the revision is in force
		// by the time the second approval returns.
		if _, ok := h.effective("whitelist-transfer-audit"); !ok {
			t.Fatal("the revision did not take effect after the quorum")
		}
		if state := h.revisionState(t, author, proposal.ID); state != revision.StateApplied {
			t.Fatalf("revision state = %q, want %q", state, revision.StateApplied)
		}
	})

	t.Run("the chosen application mode ran at effect time", func(t *testing.T) {
		// R5: revaluation is the default and it ran over the decision that was
		// open, reusing that decision's frozen fact snapshot.
		applied := h.auditPayloads(revision.AuditKindRevisionApplied)
		if len(applied) != 1 {
			t.Fatalf("%d revision.applied audit rows, want 1", len(applied))
		}
		row := applied[0]
		if row["application_mode"] != string(decision.ModeRevaluate) {
			t.Errorf("application mode = %v, want %q", row["application_mode"], decision.ModeRevaluate)
		}
		if considered, _ := row["decisions_considered"].(float64); considered != 1 {
			t.Errorf("decisions considered = %v, want 1 (the open tenant decision)", row["decisions_considered"])
		}
		if fetched, _ := row["sources_fetched"].(float64); fetched != 0 {
			t.Errorf("sources fetched = %v, want 0: revaluation reuses the frozen snapshot", row["sources_fetched"])
		}
		revalidated := h.auditPayloads(decision.AuditKindRevalidated)
		if len(revalidated) != 1 {
			t.Errorf("%d decision.revalidated audit rows, want the one open decision", len(revalidated))
		}
		if state := h.decisionState(open.ID); state != store.DecisionPending {
			t.Errorf("the revalidated decision is %s, want it still pending on its own quorum", state)
		}
	})

	t.Run("the check tier serves the revised set", func(t *testing.T) {
		// R24: the new version reaches the check tier by the refresh poll and
		// nothing else — no invalidation message, no restart.
		deadline := time.Now().Add(10 * time.Second)
		for !contains(policyIDs(h.listPolicies(t, author)), "whitelist-transfer-audit") {
			if time.Now().After(deadline) {
				t.Fatal("the revised policy never appeared in the effective set")
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err := h.app.Refresh(context.Background()); err != nil {
			t.Fatalf("refresh: %v", err)
		}
		pep := h.idp.workload(t, "svc-payments")
		allowed, reason, _ := h.evaluate(t, pep, evaluation("1001", "2002", "transfer"))
		if !allowed {
			t.Fatalf("the check tier denies (%s) after the revision", reason)
		}
	})

	t.Run("the audit chain still verifies", func(t *testing.T) {
		h.awaitAudit(t, store.AuditKindCheckBatch, 1)
		h.verifyChain()
	})
}

// ---------------------------------------------------------------------------
// F3 — 시간 지연 결정과 정책 개정 (R3(delay), R5, R17, R18)
// ---------------------------------------------------------------------------

// TestF3DelayedDecisionSurvivesARevision is M2's exit condition for the delay
// kind, driven through the assembled process.
//
// It is here rather than only in the revision package because the failure it
// guards against is silent and cumulative. Nothing observable goes wrong when a
// revision restarts a wait: the decision stays pending, the audit trail records
// a revaluation, every unit test still passes. What changes is that the wait
// never ends — each revision, including revisions about entirely different
// policies, hands the subject the full duration back. The only way to see it is
// to hold a wait across a revision and read the instant it is going to end.
//
// The three steps are the three answers a revision can owe a running wait: leave
// it alone, move it from where it started, and end it.
func TestF3DelayedDecisionSurvivesARevision(t *testing.T) {
	const wait = time.Hour

	h := newHarness(t, harnessOptions{writerID: "f3-writer"})
	h.seed(tenantSchema(), coolingOffPolicy("cooling-off", wait, "carol"))

	author := h.idp.user(t, "author")
	alice := h.idp.user(t, "alice")
	bob := h.idp.user(t, "bob")

	open, err := h.app.Decisions().Decide(context.Background(), decision.Request{
		Caller: &identity.Subject{Kind: identity.SubjectWorkload, Issuer: h.idp.server.URL, ID: "svc-ops"},
		Input: engine.Input{
			Action:   "close",
			Subject:  engine.Entity{Type: "account", ID: "acct-src", Attributes: map[string]any{"number": "1001"}},
			Resource: engine.Entity{Type: "account", ID: "acct-dst", Attributes: map[string]any{"amount": int64(5000)}},
		},
	})
	if err != nil {
		t.Fatalf("open a delayed decision: %v", err)
	}
	if !open.Pending() {
		t.Fatalf("the decision is %s, want it pending on its wait", open.State)
	}

	// The instant the wait started, recovered the way the effect hook recovers
	// it: the frozen release instant minus the duration it was opened under.
	// Everything below is stated against this rather than against wall clock.
	startedAt := h.delayDetail(open.ID).ReleaseAt.Add(-wait)

	// The wait has to be observably older than the revisions below, because the
	// whole question is what a revision does to time already served. Without any
	// elapsed time "kept its start" and "restarted from now" are the same instant
	// to within a rounding error, and the test would pass on both.
	time.Sleep(250 * time.Millisecond)

	h.lockGovernance(t, author)

	t.Run("the wait is running with its own timer in the scheduler column", func(t *testing.T) {
		detail := h.delayDetail(open.ID)
		if detail.CancellableBy == nil || len(detail.CancellableBy.Members) != 1 {
			t.Fatalf("cancellation authority = %+v, want the declared one", detail.CancellableBy)
		}
		want := startedAt.Add(wait)
		if !sameInstant(h.nextDeadline(open.ID), &want) {
			t.Errorf("the decision wakes at %v, want the wait's end %s", h.nextDeadline(open.ID), want)
		}
	})

	t.Run("a revision about another policy does not restart the wait", func(t *testing.T) {
		// R5's revaluation runs over this decision — the audit row below proves
		// it did — and leaves the wait exactly where it was. A rebinding that
		// re-issued the challenge would move the end of the wait forward by a
		// full hour, here and on every revision after it.
		before := h.delayDetail(open.ID)
		rowBefore := h.challengeRow(open.ID, 0)

		added := whitelistPolicy("whitelist-transfer-audit")
		added.Description = "a policy about transfers, landed while a closure is waiting"
		h.landRevision(t, author, alice, bob, revision.Single(nil, added))

		after := h.delayDetail(open.ID)
		if !after.ReleaseAt.Equal(before.ReleaseAt) {
			t.Fatalf("the wait now ends at %s and was going to end at %s: the revision restarted a "+
				"wait that was already %s old", after.ReleaseAt, before.ReleaseAt, time.Since(startedAt))
		}
		if after.Duration != before.Duration {
			t.Errorf("duration = %q, want the unchanged %q", after.Duration, before.Duration)
		}
		if !sameInstant(h.challengeRow(open.ID, 0).Deadline, rowBefore.Deadline) {
			t.Errorf("the challenge timer moved from %v to %v",
				rowBefore.Deadline, h.challengeRow(open.ID, 0).Deadline)
		}
		if got := h.decisionState(open.ID); got != store.DecisionPending {
			t.Fatalf("decision state = %q, want pending", got)
		}
		if rows := h.auditPayloadsFor(decision.AuditKindRevalidated, open.ID); len(rows) != 1 {
			t.Fatalf("%d revalidation audit rows for the waiting decision, want 1", len(rows))
		}
	})

	t.Run("a shortened wait is measured from where it started", func(t *testing.T) {
		// The subject has already served part of this wait. A revised duration
		// counts from the instant the wait began, so the answer is startedAt plus
		// the new duration — never now plus the new duration, which would hand
		// back every minute already served.
		h.landRevision(t, author, alice, bob, revision.Single(
			coolingOffPolicy("cooling-off", wait, "carol"),
			coolingOffPolicy("cooling-off", 30*time.Minute, "carol")))

		want := startedAt.Add(30 * time.Minute)
		got := h.delayDetail(open.ID).ReleaseAt
		if !got.Equal(want) {
			t.Fatalf("the wait now ends at %s, want %s (its start plus the revised 30m); "+
				"now plus 30m would be %s", got, want, time.Now().UTC().Add(30*time.Minute))
		}
		// The detail is the authority on when a wait ends and the column is what
		// wakes the sweeper up. A revision that moved one without the other is a
		// wait that ends with nobody watching.
		if !sameInstant(h.challengeRow(open.ID, 0).Deadline, &want) {
			t.Errorf("the challenge timer is %v, want %s", h.challengeRow(open.ID, 0).Deadline, want)
		}
		if !sameInstant(h.nextDeadline(open.ID), &want) {
			t.Errorf("the decision wakes at %v, want %s", h.nextDeadline(open.ID), want)
		}
		if got := h.decisionState(open.ID); got != store.DecisionPending {
			t.Fatalf("decision state = %q, want pending with most of the half hour left", got)
		}
	})

	t.Run("a wait shortened past its start is over", func(t *testing.T) {
		h.landRevision(t, author, alice, bob, revision.Single(
			coolingOffPolicy("cooling-off", 30*time.Minute, "carol"),
			coolingOffPolicy("cooling-off", time.Millisecond, "carol")))

		want := startedAt.Add(time.Millisecond)
		if got := h.delayDetail(open.ID).ReleaseAt; !got.Equal(want) {
			t.Fatalf("the wait now ends at %s, want %s", got, want)
		}
		if got := h.challengeRow(open.ID, 0).State; got != store.ChallengeSatisfied {
			t.Fatalf("challenge state = %q, want satisfied: the revised wait ended before now", got)
		}
		if got := h.decisionState(open.ID); got != store.DecisionAllowed {
			t.Fatalf("decision state = %q, want it resolved by the elapsed wait", got)
		}
	})

	t.Run("the audit chain still verifies", func(t *testing.T) { h.verifyChain() })
}

// TestDelayCancellationReachesTheMountedConsoleRoute is the composition-root
// half of the delay kind. The handler's authority rule is U11's and is tested
// there; what is new here is that the route exists at all, on the surface the
// mount table admits an end-user credential on, and that a cancellation through
// it resolves the decision.
func TestDelayCancellationReachesTheMountedConsoleRoute(t *testing.T) {
	h := newHarness(t, harnessOptions{writerID: "cancel-writer"})
	h.seed(tenantSchema(), coolingOffPolicy("cooling-off", time.Hour, "carol"))

	open, err := h.app.Decisions().Decide(context.Background(), decision.Request{
		Caller: &identity.Subject{Kind: identity.SubjectWorkload, Issuer: h.idp.server.URL, ID: "svc-ops"},
		Input: engine.Input{
			Action:   "close",
			Subject:  engine.Entity{Type: "account", ID: "acct-src", Attributes: map[string]any{"number": "1002"}},
			Resource: engine.Entity{Type: "account", ID: "acct-dst", Attributes: map[string]any{"amount": int64(9000)}},
		},
	})
	if err != nil {
		t.Fatalf("open a delayed decision: %v", err)
	}
	path := fmt.Sprintf("/decisions/%s/challenges/0/cancellation", open.ID)

	if code, _ := h.do(http.MethodPost, api.SurfaceConsole, path, "", "", nil); code != http.StatusUnauthorized {
		t.Errorf("an unauthenticated cancellation = %d, want %d", code, http.StatusUnauthorized)
	}
	// R40: somebody outside the frozen authority is refused, and the refusal is
	// indistinguishable from a decision that does not exist.
	if code, body := h.do(http.MethodPost, api.SurfaceConsole, path,
		h.idp.user(t, "mallory"), "", nil); code == http.StatusOK {
		t.Fatalf("a cancellation from outside the authority succeeded: %s", body)
	}
	if code, body := h.do(http.MethodPost, api.SurfaceConsole, path,
		h.idp.user(t, "carol"), "", nil); code != http.StatusOK {
		t.Fatalf("carol's cancellation = %d: %s", code, body)
	}
	if got := h.decisionState(open.ID); got != store.DecisionDenied {
		t.Fatalf("decision state = %q, want the cancellation to deny it", got)
	}
	h.verifyChain()
}

// lockGovernance moves governance out of solo-admin mode into a two-approver
// quorum, which is the state every revision below is landed under.
func (h *harness) lockGovernance(t *testing.T, author string) {
	t.Helper()
	code, body := h.do(http.MethodPost, api.SurfaceConsole, "/governance/lock", author,
		`{"threshold": 2, "approvers": ["alice", "bob"]}`,
		map[string]string{api.BootstrapTokenHeader: h.app.BootstrapToken()})
	if code != http.StatusOK {
		t.Fatalf("POST /governance/lock = %d: %s", code, body)
	}
}

// landRevision proposes a revision and collects the quorum that puts it in
// force, through the same console surface an operator uses.
func (h *harness) landRevision(t *testing.T, author, first, second string, delta revision.Delta) {
	t.Helper()
	proposal := h.propose(t, author, delta, decision.ModeRevaluate)
	if code, body := h.approve(t, proposal.DecisionID, first); code != http.StatusOK {
		t.Fatalf("first approval = %d: %s", code, body)
	}
	if code, body := h.approve(t, proposal.DecisionID, second); code != http.StatusOK {
		t.Fatalf("second approval = %d: %s", code, body)
	}
	if state := h.revisionState(t, author, proposal.ID); state != revision.StateApplied {
		t.Fatalf("revision state = %q, want %q", state, revision.StateApplied)
	}
}

// auditPayloadsFor is auditPayloads narrowed to one subject.
func (h *harness) auditPayloadsFor(kind, subject string) []map[string]any {
	h.t.Helper()
	rows, err := h.app.Store().Pool().Query(context.Background(),
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

// sameInstant compares two nullable timestamps at the resolution Postgres
// stores them at.
func sameInstant(a, b *time.Time) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.UTC().Truncate(time.Microsecond).Equal(b.UTC().Truncate(time.Microsecond))
	}
}

// ---------------------------------------------------------------------------
// F5 — decide over HTTP (R2, R40)
// ---------------------------------------------------------------------------

// TestF5TheDecideSurfaceCreatesAndServesDecisions is the decide path driven the
// way a PEP drives it: over the wire, with a workload credential, against the
// assembled process.
//
// Every other flow in this file reaches the lifecycle in process, through
// [App.Decisions]. That is enough to demonstrate what a decision does and not
// enough to demonstrate that anything outside this binary can make one — which
// is the whole of what this unit adds, and the reason the check for it is here
// rather than only in the api package's own tests.
func TestF5TheDecideSurfaceCreatesAndServesDecisions(t *testing.T) {
	h := newHarness(t, harnessOptions{writerID: "f4-writer"})
	h.seed(tenantSchema(), closurePolicy("closure-approval", 1, "carol"), whitelistPolicy("whitelist-transfer"))

	pep := h.idp.workload(t, "svc-payments")
	other := h.idp.workload(t, "svc-someone-else")

	var created decision.Result
	t.Run("a workload creates a pending decision", func(t *testing.T) {
		code, body := h.do(http.MethodPost, api.SurfacePEP, api.DecisionsPath, pep,
			decideRequest("acct-src", "close", 5000, "45m"), nil)
		if code != http.StatusCreated {
			t.Fatalf("POST %s = %d: %s", api.DecisionsPath, code, body)
		}
		h.decode(body, &created)

		// R2: the object carries its state, the challenge it is waiting on with
		// the progress of collection, when it stops waiting, and its obligations.
		if !created.Pending() || created.ID == "" {
			t.Fatalf("the decision is %+v, want a pending object with an identifier", created)
		}
		if len(created.Challenges) != 1 {
			t.Fatalf("challenges = %+v, want the quorum the policy demands", created.Challenges)
		}
		if got := created.Challenges[0]; got.Kind != policy.ChallengeQuorum || got.Have != 0 || got.Need != 1 {
			t.Errorf("challenge = %+v, want a quorum collecting 0 of 1", got)
		}
		if created.Obligations == nil {
			t.Error("the decision reports no obligation list at all, not even an empty one")
		}
		if created.ExpiresAt.IsZero() || created.PolicyID != "closure-approval" {
			t.Errorf("decision = %+v, want it pinned to the policy that gated it, with a deadline", created)
		}
		// The lifetime the caller asked for is the lifetime it got.
		if lived := created.ExpiresAt.Sub(created.CreatedAt); lived < 44*time.Minute || lived > 46*time.Minute {
			t.Errorf("the decision lives %s, want the 45m the request asked for", lived)
		}
	})

	t.Run("the creator reads it back", func(t *testing.T) {
		code, body := h.do(http.MethodGet, api.SurfacePEP, api.DecisionsPath+"/"+created.ID, pep, "", nil)
		if code != http.StatusOK {
			t.Fatalf("the creator's read = %d: %s", code, body)
		}
		var got decision.Result
		h.decode(body, &got)
		if got.ID != created.ID || !got.Pending() {
			t.Errorf("read back %+v, want the decision that was created", got)
		}
	})

	t.Run("another workload is refused, and cannot tell that from a decision that is not there", func(t *testing.T) {
		// R40. This is the assertion the endpoint exists to satisfy: a workload
		// holding a perfectly good credential must not be able to use this
		// surface to learn which decision identifiers name anything.
		refusedCode, refused := h.do(http.MethodGet, api.SurfacePEP,
			api.DecisionsPath+"/"+created.ID, other, "", nil)
		missingCode, missing := h.do(http.MethodGet, api.SurfacePEP,
			api.DecisionsPath+"/3f1b0f2a-0000-4000-8000-00000000f4f4", other, "", nil)
		if refusedCode != http.StatusNotFound || missingCode != http.StatusNotFound {
			t.Fatalf("refused = %d and missing = %d, want both %d", refusedCode, missingCode, http.StatusNotFound)
		}
		if string(refused) != string(missing) {
			t.Errorf("a refused read answers %q and a missing one %q; the two must not be tellable apart",
				refused, missing)
		}

		// And the refusal is in the chain, which is what makes it a refusal
		// somebody can be shown rather than a silence.
		rows := h.auditPayloadsFor(decision.AuditKindAccessRefused, created.ID)
		if len(rows) != 1 {
			t.Fatalf("%d %s rows, want the one refused read", len(rows), decision.AuditKindAccessRefused)
		}
		if rows[0]["operation"] != "read" || rows[0]["decision_id"] != created.ID {
			t.Errorf("the refusal row is %v, want it to name the read and the decision", rows[0])
		}
		if caller, _ := rows[0]["caller_id"].(string); !strings.HasSuffix(caller, "#svc-someone-else") {
			t.Errorf("the refusal row names %q, want the workload that was turned away", caller)
		}
	})

	t.Run("the targeted approver reads it on the console surface instead", func(t *testing.T) {
		// KTD2: the creator is a workload and the approver is a person, and the
		// mount table admits one credential kind per surface — so the two reads
		// are two routes over one rule, not one route serving both.
		code, body := h.do(http.MethodGet, api.SurfaceConsole,
			"/audit/decisions/"+created.ID, h.idp.user(t, "carol"), "", nil)
		if code != http.StatusOK {
			t.Fatalf("the approver's console read = %d: %s", code, body)
		}
		if code, _ := h.do(http.MethodGet, api.SurfaceConsole,
			"/audit/decisions/"+created.ID, h.idp.user(t, "mallory"), "", nil); code == http.StatusOK {
			t.Error("a person who is not an approver read the decision on the console surface")
		}
		// The approver's own token buys nothing on the PEP surface: it is not a
		// workload credential, and the route does not admit one.
		if code, _ := h.do(http.MethodGet, api.SurfacePEP,
			api.DecisionsPath+"/"+created.ID, h.idp.user(t, "carol"), "", nil); code != http.StatusForbidden {
			t.Errorf("an approver's token on the PEP read = %d, want %d", code, http.StatusForbidden)
		}
	})

	t.Run("a decide that needs nothing resolves at once and is still an object", func(t *testing.T) {
		// The body is F1's check fixture, unchanged. That is KTD1 as an
		// executable claim: a PEP asks the two questions with one value, and the
		// second one reaches the same fact source and the same policy the first
		// one did.
		code, body := h.do(http.MethodPost, api.SurfacePEP, api.DecisionsPath, pep,
			evaluation("1001", "2002", "transfer"), nil)
		if code != http.StatusCreated {
			t.Fatalf("an immediate allow = %d: %s", code, body)
		}
		var allowed decision.Result
		h.decode(body, &allowed)
		if !allowed.Allowed() || allowed.ID == "" {
			t.Fatalf("the decision is %+v, want an allow with an identifier", allowed)
		}
		if len(allowed.Challenges) != 0 || allowed.PolicyID != "whitelist-transfer" {
			t.Errorf("decision = %+v, want it resolved by the ungated policy with no challenges", allowed)
		}
		// R2's promise is about the object, not about the moment: a decision
		// that needed nothing is still there to be read afterwards.
		readCode, read := h.do(http.MethodGet, api.SurfacePEP, api.DecisionsPath+"/"+allowed.ID, pep, "", nil)
		if readCode != http.StatusOK {
			t.Fatalf("reading back a resolved decision = %d: %s", readCode, read)
		}
		var got decision.Result
		h.decode(read, &got)
		if got.ID != allowed.ID || !got.Allowed() || got.ResolvedAt == nil {
			t.Errorf("read back %+v, want the resolved decision with the instant it resolved", got)
		}
	})

	t.Run("a deny creates no decision and is recorded anyway", func(t *testing.T) {
		before := h.countDecisions()
		code, body := h.do(http.MethodPost, api.SurfacePEP, api.DecisionsPath, pep,
			decideRequest("acct-small", "close", 10, ""), nil)
		if code != http.StatusOK {
			t.Fatalf("a denied decide = %d, want %d: %s", code, http.StatusOK, body)
		}
		var denied decision.Result
		h.decode(body, &denied)
		if denied.ID != "" {
			t.Errorf("the deny carries the identifier %q of a decision that should not exist", denied.ID)
		}
		if denied.State != store.DecisionDenied {
			t.Errorf("state = %q, want %q", denied.State, store.DecisionDenied)
		}
		if after := h.countDecisions(); after != before {
			t.Errorf("the decisions table grew by %d on a deny, want 0", after-before)
		}
		refusals := h.auditPayloadsFor(decision.AuditKindDecisionRefused, "acct-small")
		if len(refusals) != 1 {
			t.Fatalf("%d %s rows, want the one deny", len(refusals), decision.AuditKindDecisionRefused)
		}
		if refusals[0]["reason"] != string(denied.Reason) {
			t.Errorf("the audit row's ground is %v and the answer's is %q; they have to be the same",
				refusals[0]["reason"], denied.Reason)
		}
	})

	t.Run("a request the policy set cannot map is refused, not decided", func(t *testing.T) {
		before := h.countDecisions()
		body := `{
			"subject":  {"type": "account", "id": "acct-src", "properties": {"number": "1001"}},
			"resource": {"type": "account", "id": "acct-dst", "properties": {"amount": "a lot"}},
			"action":   {"name": "close"}
		}`
		code, resp := h.do(http.MethodPost, api.SurfacePEP, api.DecisionsPath, pep, body, nil)
		if code != http.StatusBadRequest {
			t.Fatalf("a mistyped declared property = %d, want %d: %s", code, http.StatusBadRequest, resp)
		}
		if after := h.countDecisions(); after != before {
			t.Errorf("the decisions table grew on a refused request")
		}
	})

	t.Run("the audit chain still verifies", func(t *testing.T) { h.verifyChain() })
}

// decideRequest is one decide body: the AuthZEN evaluation body the check
// surface takes, plus the lifetime only a decision has.
func decideRequest(subjectID, action string, amount int, ttl string) string {
	body := fmt.Sprintf(`{
		"subject":  {"type": "account", "id": %q, "properties": {"number": "1001"}},
		"resource": {"type": "account", "id": "acct-dst", "properties": {"amount": %d}},
		"action":   {"name": %q}`, subjectID, amount, action)
	if ttl != "" {
		body += fmt.Sprintf(",\n\t\t\"ttl\": %q", ttl)
	}
	return body + "\n\t}"
}

// countDecisions is how many decision rows exist, for the assertions about what
// a deny does not leave behind.
func (h *harness) countDecisions() int {
	h.t.Helper()
	var n int
	if err := h.app.Store().Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM decisions`).Scan(&n); err != nil {
		h.t.Fatalf("count decisions: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------
// the composition root, for the three kinds M2 adds
// ---------------------------------------------------------------------------

// TestTheChallengeKindsAndTheirSurfacesAreWired is the other half of M2: four
// kinds registered and three new endpoints reachable.
//
// The mfa kind is deliberately conditional. [mfa.Config].AllowedACRValues is
// mandatory — an IdP downgrades an unsatisfiable `acr` request silently, so the
// allowlist is the handler's only real check and NewDelegated refuses to exist
// without one — and making the handler unconditional would mean a check-only
// tier could not start without an IdP step-up endpoint. An unregistered kind is
// the fail-closed alternative: a policy declaring one cannot issue.
func TestTheChallengeKindsAndTheirSurfacesAreWired(t *testing.T) {
	t.Run("three kinds without a step-up configured", func(t *testing.T) {
		h := newHarness(t, harnessOptions{writerID: "wired-a"})
		want := []policy.ChallengeType{policy.ChallengeQuorum, policy.ChallengeDelay, policy.ChallengeExternal}
		if got := h.app.Challenges().Kinds(); !reflect.DeepEqual(got, want) {
			t.Errorf("registered kinds = %v, want %v", got, want)
		}
		if _, err := h.app.Challenges().Handler(policy.ChallengeMFA); !errors.Is(err, challenge.ErrNoHandler) {
			t.Errorf("the mfa kind resolves to %v, want %v", err, challenge.ErrNoHandler)
		}
	})

	t.Run("all four with a step-up configured", func(t *testing.T) {
		h := newHarness(t, harnessOptions{writerID: "wired-b", stepUp: true})
		want := []policy.ChallengeType{
			policy.ChallengeQuorum, policy.ChallengeMFA, policy.ChallengeDelay, policy.ChallengeExternal,
		}
		if got := h.app.Challenges().Kinds(); !reflect.DeepEqual(got, want) {
			t.Errorf("registered kinds = %v, want %v", got, want)
		}
	})

	t.Run("the callback and cancellation routes are mounted", func(t *testing.T) {
		h := newHarness(t, harnessOptions{writerID: "wired-c"})
		// The callback listener takes no header credential — a signature and a
		// token in the body are what authenticate there — so the assertion is
		// that the route exists at all rather than that it refuses.
		for _, path := range []string{"/external/d-1/0", "/decisions/d-1/challenges/0/mfa"} {
			code, body := h.do(http.MethodPost, api.SurfaceCallback, path, "", `{}`, nil)
			if code == http.StatusNotFound {
				t.Errorf("POST %s on the callback surface = 404: %s", path, body)
			}
		}
		// The cancellation is a console action behind an end-user credential.
		code, _ := h.do(http.MethodPost, api.SurfaceConsole,
			"/decisions/d-1/challenges/0/cancellation", "", "", nil)
		if code != http.StatusUnauthorized {
			t.Errorf("an unauthenticated cancellation = %d, want %d", code, http.StatusUnauthorized)
		}
		// And it is on the console listener alone: the callback listener admits
		// no end-user credential, so a cancellation cannot be reached from it.
		if code, _ := h.do(http.MethodPost, api.SurfaceCallback,
			"/decisions/d-1/challenges/0/cancellation", "", "", nil); code != http.StatusNotFound {
			t.Errorf("the cancellation route answers %d on the callback surface, want 404", code)
		}
	})
}

// TestADelegatedStepUpCompletesThroughTheCallbackSurface walks the mfa kind end
// to end, and pins the constraint that decides whether it can work at all.
//
// [Delegated.Submit] requires the completing token's `sub` to equal the
// decision's subject identifier, and the decision's subject identifier is
// whatever the decide request put in `subject.id`. That is a real coupling
// between a policy's vocabulary and an IdP's: a deployment whose decide requests
// name an account in `subject.id` — as F2's fixture does, where the subject is
// `acct-src` — cannot have any human complete a step-up on those decisions, and
// the refusal is [challenge.ErrNotTarget] rather than anything that mentions
// configuration. So a policy that gates on an mfa challenge is a policy whose
// subject is a person, and the second half of this test is that statement as a
// failing request.
func TestADelegatedStepUpCompletesThroughTheCallbackSurface(t *testing.T) {
	h := newHarness(t, harnessOptions{writerID: "stepup-writer", stepUp: true})
	h.seed(tenantSchema(), stepUpPolicy("step-up-close", testStepUpACR))
	pep := &identity.Subject{Kind: identity.SubjectWorkload, Issuer: h.idp.server.URL, ID: "svc-ops"}

	closure := func(subjectID string) decision.Request {
		return decision.Request{
			Caller: pep,
			Input: engine.Input{
				Action:   "close",
				Subject:  engine.Entity{Type: "account", ID: subjectID, Attributes: map[string]any{"number": "1001"}},
				Resource: engine.Entity{Type: "account", ID: "acct-dst", Attributes: map[string]any{"amount": int64(5000)}},
			},
		}
	}

	t.Run("the subject completes the step-up and the decision resolves", func(t *testing.T) {
		open, err := h.app.Decisions().Decide(context.Background(), closure("alice"))
		if err != nil {
			t.Fatalf("open a step-up decision: %v", err)
		}
		if !open.Pending() {
			t.Fatalf("the decision is %s, want it pending on the step-up", open.State)
		}
		detail := h.mfaDetail(open.ID)
		if detail.Method != mfa.MethodStepUp {
			t.Errorf("delegation method = %q, want the step-up redirect (D26)", detail.Method)
		}
		if detail.AuthorizationURL == "" {
			t.Fatal("the challenge carries no authorization url to send the subject to")
		}

		code, body := h.completeStepUp(t, open.ID, detail, "alice", testStepUpACR)
		if code != http.StatusOK {
			t.Fatalf("the completion = %d: %s", code, body)
		}
		if got := h.decisionState(open.ID); got != store.DecisionAllowed {
			t.Fatalf("decision state = %q, want it resolved by the completed step-up", got)
		}
		// R38: one consumption. The same token presented again changes nothing.
		if code, _ := h.completeStepUp(t, open.ID, detail, "alice", testStepUpACR); code == http.StatusOK {
			t.Error("a second completion against the same correlator was accepted")
		}
	})

	t.Run("a downgraded class does not satisfy the challenge", func(t *testing.T) {
		// U0's finding, at the composition root: an IdP that cannot satisfy an
		// `acr` request answers with a weaker class rather than an error, so the
		// only thing standing between a password login and a satisfied step-up
		// is the allowlist check on the way back in.
		open, err := h.app.Decisions().Decide(context.Background(), closure("bob"))
		if err != nil {
			t.Fatalf("open a step-up decision: %v", err)
		}
		code, body := h.completeStepUp(t, open.ID, h.mfaDetail(open.ID), "bob", "urn:mace:incommon:iap:bronze")
		if code == http.StatusOK {
			t.Fatalf("a downgraded authentication satisfied the step-up: %s", body)
		}
		if got := h.decisionState(open.ID); got != store.DecisionPending {
			t.Errorf("decision state = %q, want it still pending", got)
		}
	})

	t.Run("a decision whose subject is not the token sub can never be completed", func(t *testing.T) {
		open, err := h.app.Decisions().Decide(context.Background(), closure("acct-src"))
		if err != nil {
			t.Fatalf("open a step-up decision: %v", err)
		}
		detail := h.mfaDetail(open.ID)
		if detail.SubjectID != "acct-src" {
			t.Fatalf("the challenge was opened for %q, want the decision's subject id", detail.SubjectID)
		}
		// The correlator is right, the class is right, the token is valid — and
		// it is still refused, because the person is not the subject the
		// decision names.
		code, body := h.completeStepUp(t, open.ID, detail, "alice", testStepUpACR)
		if code == http.StatusOK {
			t.Fatalf("a step-up for an account was completed by a person: %s", body)
		}
		if got := h.decisionState(open.ID); got != store.DecisionPending {
			t.Errorf("decision state = %q, want it still pending", got)
		}
	})

	// ---------------------------------------------------------------------
	// the redirect the IdP actually sends (#41, U2)
	// ---------------------------------------------------------------------

	t.Run("the idp redirect completes the step-up", func(t *testing.T) {
		open, err := h.app.Decisions().Decide(context.Background(), closure("alice"))
		if err != nil {
			t.Fatalf("open a step-up decision: %v", err)
		}
		detail := h.mfaDetail(open.ID)
		// KTD2, at the composition root: the value the IdP will echo is not the
		// binding secret, and the row holds both separately.
		if detail.State == "" || detail.State == detail.Correlator {
			t.Fatalf("the challenge's state is %q and its correlator is %q; KTD2 wants them different",
				detail.State, detail.Correlator)
		}
		if detail.CodeVerifier == "" {
			t.Fatal("the challenge froze no pkce verifier (KTD3)")
		}

		code, state := h.idp.authorize(t, detail.AuthorizationURL, "alice", testStepUpACR,
			detail.IssuedAt.Add(2*time.Second))
		status, body := h.landStepUp(open.ID, code, state)
		if status != http.StatusOK {
			t.Fatalf("the redirect = %d: %s", status, body)
		}
		if got := h.decisionState(open.ID); got != store.DecisionAllowed {
			t.Fatalf("decision state = %q, want it resolved by the completed step-up", got)
		}
		// A person read this, so it is a page and not a JSON document.
		if !strings.Contains(string(body), "Verification complete") {
			t.Errorf("the landing page does not say the verification succeeded: %s", body)
		}
		// R38: one consumption. The IdP refuses to mint a second token for a
		// spent code, and the decision is no longer collecting either way.
		if status, _ := h.landStepUp(open.ID, code, state); status == http.StatusOK {
			t.Error("a replayed redirect was accepted")
		}
	})

	t.Run("a forged state is refused without a token call", func(t *testing.T) {
		open, err := h.app.Decisions().Decide(context.Background(), closure("carol"))
		if err != nil {
			t.Fatalf("open a step-up decision: %v", err)
		}
		detail := h.mfaDetail(open.ID)
		code, _ := h.idp.authorize(t, detail.AuthorizationURL, "carol", testStepUpACR,
			detail.IssuedAt.Add(2*time.Second))

		before := h.idp.tokenCalls()
		status, _ := h.landStepUp(open.ID, code, "not-the-state")
		if status != http.StatusForbidden {
			t.Fatalf("a forged state = %d, want 403", status)
		}
		if h.idp.tokenCalls() != before {
			t.Error("a forged state caused a token call: the csrf check must come first")
		}
		if got := h.decisionState(open.ID); got != store.DecisionPending {
			t.Errorf("decision state = %q, want it still pending", got)
		}
	})

	t.Run("another decision's code is refused at this challenge's path", func(t *testing.T) {
		mine, err := h.app.Decisions().Decide(context.Background(), closure("dave"))
		if err != nil {
			t.Fatalf("open a step-up decision: %v", err)
		}
		theirs, err := h.app.Decisions().Decide(context.Background(), closure("erin"))
		if err != nil {
			t.Fatalf("open a second step-up decision: %v", err)
		}
		mineDetail, theirsDetail := h.mfaDetail(mine.ID), h.mfaDetail(theirs.ID)
		otherCode, _ := h.idp.authorize(t, theirsDetail.AuthorizationURL, "erin", testStepUpACR,
			theirsDetail.IssuedAt.Add(2*time.Second))

		// The state is this challenge's, so the CSRF check passes and the
		// refusal has to come from somewhere else: the OP checks the verifier
		// and the redirect target, and both are this challenge's.
		status, _ := h.landStepUp(mine.ID, otherCode, mineDetail.State)
		if status != http.StatusForbidden {
			t.Fatalf("another decision's code = %d, want 403", status)
		}
		if got := h.decisionState(mine.ID); got != store.DecisionPending {
			t.Errorf("decision state = %q, want it still pending", got)
		}
	})

	t.Run("a silently downgraded class does not satisfy the redirect either", func(t *testing.T) {
		// S1's finding on the path that D26 made the default. The IdP answers
		// with a weaker class rather than an error, the code exchanges, the token
		// verifies — and the challenge is still unsatisfied, because the `acr`
		// check on the way back in is the only thing that looks.
		open, err := h.app.Decisions().Decide(context.Background(), closure("frank"))
		if err != nil {
			t.Fatalf("open a step-up decision: %v", err)
		}
		detail := h.mfaDetail(open.ID)
		code, state := h.idp.authorize(t, detail.AuthorizationURL, "frank",
			"urn:mace:incommon:iap:bronze", detail.IssuedAt.Add(2*time.Second))

		before := h.idp.tokenCalls()
		status, body := h.landStepUp(open.ID, code, state)
		if status == http.StatusOK {
			t.Fatalf("a downgraded authentication satisfied the step-up through the redirect: %s", body)
		}
		if h.idp.tokenCalls() == before {
			t.Fatal("the code was never exchanged, so this did not test the acr check")
		}
		if got := h.decisionState(open.ID); got != store.DecisionPending {
			t.Errorf("decision state = %q, want it still pending", got)
		}
		// The subject is told something they can act on, and never what the
		// deployment's allowlist holds.
		if !strings.Contains(string(body), "not strong enough") {
			t.Errorf("the landing page does not tell the subject their sign-in was too weak: %s", body)
		}
		if strings.Contains(string(body), testStepUpACR) {
			t.Errorf("the landing page names the operator allowlist: %s", body)
		}
	})

	t.Run("the audit chain still verifies", func(t *testing.T) { h.verifyChain() })
}

// landStepUp follows the IdP's redirect into the callback listener, the way a
// browser does: a GET with `code` and `state` in the query and no credential.
func (h *harness) landStepUp(decisionID, code, state string) (int, []byte) {
	h.t.Helper()
	path := api.MFACallbackPath(decisionID, 0) +
		"?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	return h.do(http.MethodGet, api.SurfaceCallback, path, "", "", nil)
}

// completeStepUp posts a completion to the callback listener, the way a browser
// following the IdP's redirect target would.
func (h *harness) completeStepUp(t *testing.T, decisionID string, detail mfa.Detail,
	subject, acr string,
) (int, []byte) {
	t.Helper()
	// The authentication has to postdate the challenge, which is the whole point
	// of `max_age=0` on the way out.
	authTime := detail.IssuedAt.Add(2 * time.Second)
	token := h.idp.stepUp(t, subject, acr, authTime, detail.Nonce)
	body, err := json.Marshal(map[string]string{"correlator": detail.Correlator, "id_token": token})
	if err != nil {
		t.Fatalf("encode completion: %v", err)
	}
	return h.do(http.MethodPost, api.SurfaceCallback,
		api.MFACallbackPath(decisionID, 0), "", string(body), nil)
}

// ---------------------------------------------------------------------------
// role selection over the real route table
// ---------------------------------------------------------------------------

// TestRolesDecideWhichRoutesTheProcessHas is U1's guarantee, now asserted over
// the assembled wiring rather than over placeholders: a role that is not active
// has no routes on any surface, and the difference is 404 rather than a
// refusal.
// statusServed is the expectation "this route is mounted", for a route whose
// exact status depends on something outside the process — the console shell
// answers 200 with a built bundle and 503 without one, and both are the
// opposite of the 404 an unselected role gives.
const statusServed = -1

func TestRolesDecideWhichRoutesTheProcessHas(t *testing.T) {
	dsn := freshDB(t)
	approvalPath := "/decisions/d-1/challenges/0/approvals"
	// A well-formed identifier that names nothing. The decision column is a
	// uuid, so `d-1` would come back as a database error rather than as the
	// refusal this table is about.
	mfaCallbackPath := api.MFACallbackPath("00000000-0000-4000-8000-000000000000", 0)

	cases := []struct {
		roles  string
		writer string
		want   map[api.Surface]map[string]int
	}{
		{
			roles: "check", writer: "roles-check",
			want: map[api.Surface]map[string]int{
				api.SurfacePEP: {
					"POST " + api.EvaluationPath: http.StatusUnauthorized,
					// The two halves of the PEP surface are separately mounted:
					// a check tier answers the AuthZEN endpoint and has no way to
					// create a decision, which is what the role split is for.
					"POST " + api.DecisionsPath:       http.StatusNotFound,
					"GET " + api.DecisionsPath + "/1": http.StatusNotFound,
				},
				api.SurfaceConsole: {
					"POST " + approvalPath: http.StatusNotFound,
					"GET /policies":        http.StatusNotFound,
					"GET /console/":        http.StatusNotFound,
				},
				api.SurfaceCallback: {
					// R39's separation, on the route U2 added: a check tier
					// runs no decision lifecycle, so the step-up landing is not
					// a refusal there, it is not there.
					"GET " + mfaCallbackPath:  http.StatusNotFound,
					"POST " + mfaCallbackPath: http.StatusNotFound,
				},
			},
		},
		{
			roles: "decide", writer: "roles-decide",
			want: map[api.Surface]map[string]int{
				api.SurfacePEP: {
					"POST " + api.EvaluationPath: http.StatusNotFound,
					// R2 and R40's creation and read: mounted here, and behind a
					// workload credential, so an unauthenticated caller is refused
					// a credential rather than told the route does not exist.
					"POST " + api.DecisionsPath:       http.StatusUnauthorized,
					"GET " + api.DecisionsPath + "/1": http.StatusUnauthorized,
				},
				api.SurfaceConsole: {
					"POST " + approvalPath: http.StatusUnauthorized,
					"GET /policies":        http.StatusNotFound,
				},
				api.SurfaceCallback: {
					// Mounted, and refusing uniformly: the party arriving here
					// holds no credential and has not yet proved a `state`, so
					// 403 rather than 404 is what says "this process serves the
					// route and did not accept your link".
					"GET " + mfaCallbackPath: http.StatusForbidden,
				},
			},
		},
		{
			roles: "api", writer: "roles-api",
			want: map[api.Surface]map[string]int{
				api.SurfaceConsole: {
					"GET /policies": http.StatusUnauthorized,
					// The file authoring pair rides with the authoring tier,
					// which is where the governance service that owns the
					// authoring mode, the payload limits and the export
					// capability lives. Mounted here means an unauthenticated
					// caller is refused a credential rather than told the route
					// does not exist.
					"POST " + api.PolicyApplyPath: http.StatusUnauthorized,
					"GET " + api.PolicyExportPath: http.StatusUnauthorized,
					// R51: the API tier serves the API and not one byte of the
					// bundle, including the document that would tell a bundle
					// where to point.
					"GET /console/":                http.StatusNotFound,
					"GET " + api.ConsoleConfigPath: http.StatusNotFound,
					"GET /console/assets/index.js": http.StatusNotFound,
				},
				api.SurfacePEP: {
					"POST " + api.EvaluationPath: http.StatusNotFound,
				},
			},
		},
		{
			roles: "console", writer: "roles-console",
			want: map[api.Surface]map[string]int{
				api.SurfaceConsole: {
					// The shell is static: a browser doing a top level
					// navigation has no bearer token to present, so the
					// assertion is that the route is here at all. Whether the
					// answer is the bundle or the "run npm run build" guidance
					// depends on whether this tree was built, which is not
					// something a Go test should depend on.
					"GET /console/":                statusServed,
					"GET " + api.ConsoleConfigPath: http.StatusOK,
					"GET /policies":                http.StatusNotFound,
					"POST " + approvalPath:         http.StatusNotFound,
					// 404 and not 501: a console tier does not run the
					// authoring subsystem, and "this process does not serve
					// that" has to stay distinguishable from "this deployment
					// serves no file authoring path at all".
					"POST " + api.PolicyApplyPath: http.StatusNotFound,
					"GET " + api.PolicyExportPath: http.StatusNotFound,
				},
				api.SurfacePEP: {
					"POST " + api.EvaluationPath: http.StatusNotFound,
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run("roles="+tc.roles, func(t *testing.T) {
			h := newHarness(t, harnessOptions{roles: tc.roles, dsn: dsn, writerID: tc.writer})
			for surface, expectations := range tc.want {
				for spec, want := range expectations {
					method, path, _ := cut(spec)
					code, _ := h.do(method, surface, path, "", "", nil)
					if want == statusServed {
						if code == http.StatusNotFound {
							t.Errorf("%s on the %s surface under --roles=%s = 404, want the route to be mounted",
								spec, surface, tc.roles)
						}
						continue
					}
					if code != want {
						t.Errorf("%s on the %s surface under --roles=%s = %d, want %d",
							spec, surface, tc.roles, code, want)
					}
				}
			}
			// Every process answers its own liveness probe, on every surface it
			// serves, whatever it runs.
			for _, surface := range []api.Surface{api.SurfacePEP, api.SurfaceConsole} {
				if code, _ := h.do(http.MethodGet, surface, "/healthz", "", "", nil); code != http.StatusOK {
					t.Errorf("GET /healthz on %s under --roles=%s = %d, want 200", surface, tc.roles, code)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// the mount table the release checks read
// ---------------------------------------------------------------------------
//
// internal/release holds two drift checks that need to know what this
// composition root really mounts: the contract document's endpoint table
// against the routes, and the chart's role-to-surface binding against the
// surfaces a role's routes are on. Both need the assembled registry, and the
// registry only exists after a database is open — which internal/release has
// no container for.
//
// So the registry is exported here, where it exists, into a tracked document
// internal/release reads. That is the shape console/contract/public-endpoints.
// json already uses: a Go test renders the document and fails when the tracked
// copy differs, and a second check consumes the file. Adding a route therefore
// turns this test red once, rewriting the file, and leaves internal/release red
// until the contract document and the chart agree with it.

// mountTableFile is the tracked rendering. It lives in the package that reads
// it rather than next to this test, because it is that package's input.
const mountTableFile = "../release/testdata/mounted-routes.json"

// mountedRoute is one route as the registry mounts it, with the roles that
// activate the component it came from.
type mountedRoute struct {
	Name    string   `json:"name"`
	Roles   []string `json:"roles"`
	Surface string   `json:"surface"`
	Pattern string   `json:"pattern"`
	Auth    string   `json:"auth"`
}

type mountTableDocument struct {
	Note   string         `json:"note"`
	Routes []mountedRoute `json:"routes"`
}

const mountTableNote = "Generated by TestTheMountTableFileIsUpToDate in internal/runtime, from the " +
	"registry the composition root assembles. Edit the wiring, not this file. " +
	"internal/release compares it against docs/contracts/decision-api.md and the Helm snapshots."

// renderMountTable renders every route the active components mount. Routes are
// sorted so the file is stable under a reordering of the registrations.
func renderMountTable(reg *Registry, set Set) ([]byte, error) {
	routes := []mountedRoute{}
	for _, c := range reg.Active(set) {
		roles := make([]string, 0, len(c.Roles))
		for _, r := range c.Roles {
			roles = append(roles, string(r))
		}
		sort.Strings(roles)
		for _, r := range c.Routes {
			routes = append(routes, mountedRoute{
				Name:    r.Name,
				Roles:   roles,
				Surface: string(r.Surface),
				Pattern: r.Pattern,
				Auth:    string(r.Auth),
			})
		}
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Pattern != routes[j].Pattern {
			return routes[i].Pattern < routes[j].Pattern
		}
		return routes[i].Name < routes[j].Name
	})

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(mountTableDocument{Note: mountTableNote, Routes: routes}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// TestTheMountTableFileIsUpToDate keeps the exported table and the registry
// from drifting.
//
// The process it assembles is the maximal one: every role, and the one optional
// subsystem that carries a route (event ingestion, which is mounted only when a
// stream source is declared). The contract document describes what the binary
// can serve, not what one configuration happens to, so a table rendered from a
// process with a feature switched off would ask internal/release to delete a
// row for an endpoint that exists.
func TestTheMountTableFileIsUpToDate(t *testing.T) {
	h := newHarness(t, harnessOptions{
		roles:    RoleAll,
		writerID: "mount-table",
		stepUp:   true,
		mutate:   withVelocity("mount-table"),
	})
	set, err := ParseRoles(RoleAll)
	if err != nil {
		t.Fatalf("parse roles: %v", err)
	}
	want, err := renderMountTable(h.app.registry, set)
	if err != nil {
		t.Fatalf("render the mount table: %v", err)
	}

	// The tripwire for the paragraph above: a role whose routes all vanished
	// from the rendering is far more likely to be a component this test failed
	// to configure than a role that genuinely serves nothing.
	var doc mountTableDocument
	if uerr := json.Unmarshal(want, &doc); uerr != nil {
		t.Fatalf("decode the rendering: %v", uerr)
	}
	for _, role := range knownRoles() {
		found := false
		for _, r := range doc.Routes {
			if slices.Contains(r.Roles, string(role)) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the rendered mount table has no route for the %s role: this test's "+
				"configuration is switching a component off rather than the role serving nothing", role)
		}
	}

	got, rerr := os.ReadFile(mountTableFile)
	if rerr == nil && bytes.Equal(got, want) {
		return
	}
	if werr := os.WriteFile(mountTableFile, want, 0o600); werr != nil {
		t.Fatalf("write the mount table: %v", werr)
	}
	t.Fatalf("%s was stale and has been rewritten; review the diff, commit it, and expect "+
		"internal/release to name whatever the contract document or the chart no longer agrees with",
		mountTableFile)
}

// TestAuditWriterCollisionFailsTheBoot is U4's rule at the composition root: a
// second process on one writer identifier does not wait its turn.
func TestAuditWriterCollisionFailsTheBoot(t *testing.T) {
	dsn := freshDB(t)
	first := newHarness(t, harnessOptions{dsn: dsn, writerID: "contested"})
	_ = first

	idp := newMockIdP(t)
	cfg := Config{
		DSN: dsn, MaxConns: 8, WriterID: "contested", InstanceID: "second",
		Addresses: map[api.Surface]string{api.SurfacePEP: "127.0.0.1:0"},
		OIDC: OIDCConfig{
			Issuers:                []IssuerConfig{{Issuer: idp.server.URL, JWKSURL: idp.server.URL + "/jwks"}},
			Audience:               testAudience,
			Algorithms:             []string{"RS256"},
			AllowInsecureTransport: true,
		},
	}
	roles, err := ParseRoles("check")
	if err != nil {
		t.Fatalf("parse roles: %v", err)
	}
	app, err := Assemble(context.Background(), cfg, roles, nil)
	if err == nil {
		app.Close()
		t.Fatal("a second process claimed a held audit writer, want a boot failure")
	}
	if !errors.Is(err, store.ErrWriterTaken) {
		t.Fatalf("collision error = %v, want it to wrap %v", err, store.ErrWriterTaken)
	}
}

// TestAuditAlertThresholdMovesWhenTheLossAlertFires is R32's alert sensitivity,
// observed rather than cross-referenced.
//
// The consumption check in consumption_test.go proves the composition root reads
// AuditAlertThreshold. It cannot prove the value reaches the counter the alert
// is compared against — that is the difference between the two shapes of check
// Open Question 3 named, and this test is the second shape for the one field
// this unit adds. It drives the assembled process's own buffer, so what it
// observes is the deployment configuration arriving at the behaviour, with no
// seam built for the test to look through.
//
// The two subtests are the whole of the claim: the same losses must not alert
// under a raised threshold and must alert under the default. A wiring that
// dropped the field would pass the first half of one of them and fail the other.
func TestAuditAlertThresholdMovesWhenTheLossAlertFires(t *testing.T) {
	// saturate fills the buffer's queue and then loses `losses` events, which
	// is deterministic because the queue holds one and nothing drains it: the
	// flush interval is longer than the test and the batch never fills.
	saturate := func(t *testing.T, buffer *api.AuditBuffer, losses int64) api.AuditStats {
		t.Helper()
		ctx := context.Background()
		start := buffer.Stats().Dropped
		for buffer.Stats().Queued < 1 {
			buffer.Record(ctx, api.Event{Kind: api.EventCheck, CallerID: "filler"})
		}
		for i := int64(0); i < losses; i++ {
			buffer.Record(ctx, api.Event{Kind: api.EventCheck, CallerID: "lost"})
		}
		stats := buffer.Stats()
		if got := stats.Dropped - start; got != losses {
			t.Fatalf("the buffer lost %d events, want exactly %d: the saturation is not deterministic", got, losses)
		}
		return stats
	}

	starve := func(c *Config) {
		c.AuditCapacity = 1
		c.AuditBatchSize = 1 << 20
		c.AuditFlushInterval = time.Hour
	}

	// The threshold an operator raised: R32's sensitivity. Four losses are not
	// yet the alert; the fifth is.
	t.Run("a raised threshold holds the alert until the count reaches it", func(t *testing.T) {
		const threshold = 5
		h := newHarness(t, harnessOptions{writerID: "alert-raised", mutate: func(c *Config) {
			starve(c)
			c.AuditAlertThreshold = threshold
		}})
		buffer := h.app.buffer

		if stats := saturate(t, buffer, threshold-1); stats.Alerting {
			t.Fatalf("the loss alert fired after %d of %d lost events: the configured threshold is not "+
				"reaching the buffer", stats.Dropped, threshold)
		}
		if stats := saturate(t, buffer, 1); !stats.Alerting {
			t.Fatalf("the loss alert did not fire after %d lost events, with a threshold of %d",
				stats.Dropped, threshold)
		}
	})

	// The same losses against the default, which is what every deployment got
	// while nothing carried the setting: the first lost event alerts.
	t.Run("the default alerts on the first lost event", func(t *testing.T) {
		h := newHarness(t, harnessOptions{writerID: "alert-default", mutate: starve})
		if stats := saturate(t, h.app.buffer, 1); !stats.Alerting {
			t.Fatalf("the loss alert did not fire on the first lost event, which is the default of %d",
				api.DefaultAuditAlertThreshold)
		}
	})
}

// TestMissingDSNFailsStartup is the configuration rule: nothing that would be a
// trust decision gets a default.
func TestMissingDSNFailsStartup(t *testing.T) {
	roles, err := ParseRoles("all")
	if err != nil {
		t.Fatalf("parse roles: %v", err)
	}
	_, err = Assemble(context.Background(), Config{
		Addresses: map[api.Surface]string{api.SurfacePEP: "127.0.0.1:0"},
		OIDC: OIDCConfig{
			Issuers:    []IssuerConfig{{Issuer: "https://idp.invalid", JWKSURL: "https://idp.invalid/jwks"}},
			Audience:   testAudience,
			Algorithms: []string{"RS256"},
		},
	}, roles, nil)
	if err == nil {
		t.Fatal("assembling without a DSN succeeded, want a startup failure")
	}
}

// ---------------------------------------------------------------------------
// harness helpers used by the flows
// ---------------------------------------------------------------------------

func (h *harness) evaluate(t *testing.T, token, body string) (allowed bool, reason, policyID string) {
	t.Helper()
	code, raw := h.do(http.MethodPost, api.SurfacePEP, api.EvaluationPath, token, body, nil)
	if code != http.StatusOK {
		t.Fatalf("POST %s = %d: %s", api.EvaluationPath, code, raw)
	}
	var resp api.EvaluationResponse
	h.decode(raw, &resp)
	reason, _ = resp.Context[api.ContextKeyReason].(string)
	policyID, _ = resp.Context[api.ContextKeyPolicyID].(string)
	return resp.Decision, reason, policyID
}

func (h *harness) preview(t *testing.T, token string, delta revision.Delta) revision.Preview {
	t.Helper()
	code, raw := h.do(http.MethodPost, api.SurfaceConsole, "/policies/revisions/preview", token,
		h.revisionBody(t, delta, ""), nil)
	if code != http.StatusOK {
		t.Fatalf("POST /policies/revisions/preview = %d: %s", code, raw)
	}
	var out revision.Preview
	h.decode(raw, &out)
	return out
}

func (h *harness) propose(t *testing.T, token string, delta revision.Delta, mode decision.ApplicationMode) revision.Proposal {
	t.Helper()
	code, raw := h.do(http.MethodPost, api.SurfaceConsole, "/policies/revisions", token,
		h.revisionBody(t, delta, mode), nil)
	if code != http.StatusAccepted {
		t.Fatalf("POST /policies/revisions = %d: %s", code, raw)
	}
	var out revision.Proposal
	h.decode(raw, &out)
	return out
}

func (h *harness) revisionBody(t *testing.T, delta revision.Delta, mode decision.ApplicationMode) string {
	t.Helper()
	raw, err := json.Marshal(api.RevisionRequest{Delta: delta, Mode: mode})
	if err != nil {
		t.Fatalf("encode revision request: %v", err)
	}
	return string(raw)
}

func (h *harness) approve(t *testing.T, decisionID, token string) (int, []byte) {
	t.Helper()
	return h.do(http.MethodPost, api.SurfaceConsole,
		fmt.Sprintf("/decisions/%s/challenges/0/approvals", decisionID), token, "", nil)
}

func (h *harness) revisionState(t *testing.T, token, id string) revision.State {
	t.Helper()
	code, raw := h.do(http.MethodGet, api.SurfaceConsole, "/policies/revisions/"+id, token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /policies/revisions/%s = %d: %s", id, code, raw)
	}
	var out revision.Proposal
	h.decode(raw, &out)
	return out.State
}

func (h *harness) listPolicies(t *testing.T, token string) []api.PolicyView {
	t.Helper()
	code, raw := h.do(http.MethodGet, api.SurfaceConsole, "/policies", token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /policies = %d: %s", code, raw)
	}
	var out api.PolicyListResponse
	h.decode(raw, &out)
	return out.Policies
}

func (h *harness) effective(id string) (*policy.Policy, bool) {
	rec, err := store.EffectivePolicy(context.Background(), h.app.Store().Pool(), id)
	if err != nil || rec.Deleted {
		return nil, false
	}
	p, err := rec.Policy()
	if err != nil {
		return nil, false
	}
	return p, true
}

func (h *harness) decisionState(id string) store.DecisionState {
	h.t.Helper()
	d, err := store.GetDecision(context.Background(), h.app.Store().Pool(), id)
	if err != nil {
		h.t.Fatalf("read decision %s: %v", id, err)
	}
	return d.State
}

// awaitAudit waits for the buffered check path to reach the chain. The buffer
// batches, so a judgment is in the chain a flush interval after it is made
// rather than in the same call.
func (h *harness) awaitAudit(t *testing.T, kind string, want int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		rows := h.auditPayloads(kind)
		if len(rows) >= want {
			return rows
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d %s audit rows after 10s, want at least %d", len(rows), kind, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func policyIDs(views []api.PolicyView) []string {
	out := make([]string, len(views))
	for i, v := range views {
		out[i] = v.ID
	}
	return out
}

// cut splits "METHOD /path" into its two halves.
func cut(spec string) (method, path string, ok bool) {
	for i := 0; i < len(spec); i++ {
		if spec[i] == ' ' {
			return spec[:i], spec[i+1:], true
		}
	}
	return http.MethodGet, spec, false
}
