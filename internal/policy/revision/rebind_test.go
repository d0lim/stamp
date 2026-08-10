package revision_test

// rebind_test.go is M2's half of the effect hook: what a revision does to the
// three challenge kinds that are not a quorum.
//
// Every one of them has a rule the quorum does not, and every rule exists
// because re-issuing has a side effect the subject can see. A delay re-issued
// restarts a wait somebody is already serving. A step-up re-issued rotates a
// correlator somebody is holding and moves the `auth_time` floor out from under
// an authentication already in flight. An external challenge re-issued posts a
// second webhook — from inside the transaction that is landing the revision,
// while it holds a row lock on every open decision.
//
// So these run against the real handlers, a real Postgres and a real HTTP
// target. A fake for the webhook would make "no second POST" a statement about
// the fake.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// unrelatedPolicy governs an action the open decisions do not use, so adding it
// is a revision that reaches revaluation without changing any decision's
// challenge list. A policy on the same action would change the list, and a
// changed list is the one case where restarting timers is correct.
func unrelatedPolicy(id string) *policy.Policy {
	return &policy.Policy{
		ID:       id,
		Subject:  "user",
		Resource: "account",
		Actions:  []string{"close"},
		Condition: policy.Compare{
			Op: policy.OpGe, Left: policy.Field(policy.RoleResource, "amount"), Right: policy.Int(1),
		},
	}
}

// landUnrelated proposes, approves and applies a revision that adds a policy
// nothing open is judged against.
func (h *harness) landUnrelated(id string) {
	h.t.Helper()
	p := h.propose("a", revision.Single(nil, unrelatedPolicy(id)), "")
	if err := h.approve(p, "b"); err != nil {
		h.t.Fatalf("approve the revision: %v", err)
	}
	if applied := h.reconcile(); len(applied) != 1 {
		h.t.Fatalf("reconcile applied %d revisions, want 1", len(applied))
	}
}

// land proposes, approves and applies a revision of one policy.
func (h *harness) land(before, after *policy.Policy) {
	h.t.Helper()
	p := h.propose("a", revision.Single(before, after), "")
	if err := h.approve(p, "b"); err != nil {
		h.t.Fatalf("approve the revision: %v", err)
	}
	if applied := h.reconcile(); len(applied) != 1 {
		h.t.Fatalf("reconcile applied %d revisions, want 1", len(applied))
	}
}

// writeDetail replaces a challenge's stored detail without moving its state.
//
// It is how this file reaches the one state the API cannot produce: evidence
// recorded and the state not yet written. The contract calls that window out —
// "a crash between the two statements leaves the evidence written and the state
// not yet updated" — and it is exactly the window in which a revision could
// undo something that already happened.
func (h *harness) writeDetail(decisionID string, ordinal int, detail any) {
	h.t.Helper()
	raw, err := json.Marshal(detail)
	if err != nil {
		h.t.Fatalf("encode detail: %v", err)
	}
	if _, err := h.store.Pool().Exec(context.Background(),
		`UPDATE challenge_progress SET detail = $3 WHERE decision_id = $1 AND ordinal = $2`,
		decisionID, ordinal, raw); err != nil {
		h.t.Fatalf("write challenge detail: %v", err)
	}
}

// ---------------------------------------------------------------------------
// delay
// ---------------------------------------------------------------------------

// The case that is invisible to a unit test and silent in production: a
// revision that has nothing to do with this decision must not restart its wait.
// Issue computes ReleaseAt as now plus the duration, so a rebinding that reached
// for Issue would add the whole wait again — on every revaluation, forever.
func TestAnUnrelatedRevisionDoesNotRestartADelay(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	seed(t, h, delayPolicy("cooling-off", 2*time.Hour, "carol"))
	h.lock(1, "a", "b")

	open := h.tenantDecision(transferRequest("u1", 5000))
	if !open.Pending() {
		t.Fatalf("decision state = %q, want it pending on its wait", open.State)
	}
	before := h.delayDetail(open.ID)
	rowBefore := h.challengeRow(open.ID, 0)

	// Half the wait is served before the revision lands.
	h.clock.Advance(time.Hour)
	h.landUnrelated("unrelated")

	after := h.delayDetail(open.ID)
	if !after.ReleaseAt.Equal(before.ReleaseAt) {
		t.Fatalf("the wait now ends at %s, and it was going to end at %s — the revision restarted it",
			after.ReleaseAt, before.ReleaseAt)
	}
	if after.Duration != before.Duration {
		t.Errorf("duration = %q, want the unchanged %q", after.Duration, before.Duration)
	}
	rowAfter := h.challengeRow(open.ID, 0)
	if !sameInstant(rowAfter.Deadline, rowBefore.Deadline) {
		t.Errorf("the challenge deadline moved from %v to %v", rowBefore.Deadline, rowAfter.Deadline)
	}
	if rowAfter.State != store.ChallengePending {
		t.Errorf("challenge state = %q, want it still pending", rowAfter.State)
	}
	if got := h.decisionState(open.ID); got != store.DecisionPending {
		t.Errorf("decision state = %q, want pending", got)
	}
	h.verifyChain()
}

// A revised duration is measured from the instant the wait started, which the
// detail records indirectly: ReleaseAt minus the duration it was opened under.
// `now + newDuration` is a different answer and it is the wrong one — it gives
// back time the subject has already served.
func TestARevisedDelayIsMeasuredFromTheOriginalStart(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	seed(t, h, delayPolicy("cooling-off", 2*time.Hour))
	h.lock(1, "a", "b")

	open := h.tenantDecision(transferRequest("u1", 5000))
	startedAt := h.delayDetail(open.ID).ReleaseAt.Add(-2 * time.Hour)

	// Ninety minutes of the two hours are served.
	h.clock.Advance(90 * time.Minute)

	t.Run("a shortened wait keeps its start and updates the timer column", func(t *testing.T) {
		h.land(delayPolicy("cooling-off", 2*time.Hour), delayPolicy("cooling-off", 100*time.Minute))

		want := startedAt.Add(100 * time.Minute)
		got := h.delayDetail(open.ID).ReleaseAt
		if !got.Equal(want) {
			t.Fatalf("the wait now ends at %s, want %s (the original start plus the revised 100m); "+
				"now plus 100m would have been %s", got, want, h.clock.Now().Add(100*time.Minute))
		}
		// The scheduler column is what the sweeper wakes for. A detail that moved
		// without it would be a wait that ends and nothing notices.
		row := h.challengeRow(open.ID, 0)
		if !sameInstant(row.Deadline, &want) {
			t.Errorf("the challenge deadline is %v, want %s", row.Deadline, want)
		}
		if !sameInstant(h.nextDeadline(open.ID), &want) {
			t.Errorf("the decision wakes at %v, want %s", h.nextDeadline(open.ID), want)
		}
		if got := h.decisionState(open.ID); got != store.DecisionPending {
			t.Fatalf("decision state = %q, want pending with ten minutes left", got)
		}
	})

	t.Run("a wait shortened past its own start is over", func(t *testing.T) {
		// Eighty minutes from a start ninety minutes ago is a wait that already
		// finished, so the revision resolves the decision rather than leaving it
		// pending on a deadline in the past.
		h.land(delayPolicy("cooling-off", 100*time.Minute), delayPolicy("cooling-off", 80*time.Minute))

		want := startedAt.Add(80 * time.Minute)
		if got := h.delayDetail(open.ID).ReleaseAt; !got.Equal(want) {
			t.Fatalf("the wait now ends at %s, want %s", got, want)
		}
		if got := h.challengeRow(open.ID, 0).State; got != store.ChallengeSatisfied {
			t.Fatalf("challenge state = %q, want satisfied", got)
		}
		if got := h.decisionState(open.ID); got != store.DecisionAllowed {
			t.Fatalf("decision state = %q, want it allowed on the elapsed wait", got)
		}
	})
	h.verifyChain()
}

// Changing who may stop a wait changes who may stop it and nothing else. The
// release instant is not a term the cancellation authority participates in, and
// rewriting it here would be a revision quietly extending a wait.
func TestARevisedCancellationAuthorityLeavesTheWaitRunning(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	seed(t, h, delayPolicy("cooling-off", 2*time.Hour, "carol"))
	h.lock(1, "a", "b")

	open := h.tenantDecision(transferRequest("u1", 5000))
	before := h.delayDetail(open.ID)
	rowBefore := h.challengeRow(open.ID, 0)
	h.clock.Advance(time.Hour)

	h.land(delayPolicy("cooling-off", 2*time.Hour, "carol"),
		delayPolicy("cooling-off", 2*time.Hour, "carol", "dave"))

	after := h.delayDetail(open.ID)
	if after.CancellableBy == nil {
		t.Fatal("the revised wait names no cancellation authority")
	}
	if got := after.CancellableBy.Members; len(got) != 2 || got[0] != "carol" || got[1] != "dave" {
		t.Fatalf("cancellation authority = %v, want the revised [carol dave]", got)
	}
	if !after.ReleaseAt.Equal(before.ReleaseAt) {
		t.Errorf("the wait moved from %s to %s", before.ReleaseAt, after.ReleaseAt)
	}
	rowAfter := h.challengeRow(open.ID, 0)
	if !sameInstant(rowAfter.Deadline, rowBefore.Deadline) {
		t.Errorf("the challenge deadline moved from %v to %v", rowBefore.Deadline, rowAfter.Deadline)
	}
	if rowAfter.State != store.ChallengePending {
		t.Errorf("challenge state = %q, want pending", rowAfter.State)
	}
	h.verifyChain()
}

// A cancellation is a thing that happened. A revision may change who could have
// stopped a wait; it may not un-stop one that was stopped.
func TestARevisionNeverUndoesARecordedCancellation(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	seed(t, h, delayPolicy("cooling-off", 2*time.Hour, "carol"))
	h.lock(1, "a", "b")

	open := h.tenantDecision(transferRequest("u1", 5000))
	cancelled := h.clock.Now().Add(10 * time.Minute)
	detail := h.delayDetail(open.ID)
	detail.CancelledBy = "https://idp.test#carol"
	detail.CancelledAt = &cancelled
	h.writeDetail(open.ID, 0, detail)

	h.clock.Advance(time.Hour)
	// The duration change is the branch that rewrites the row's timer and state,
	// so it is the branch that could lose a cancellation.
	h.land(delayPolicy("cooling-off", 2*time.Hour, "carol"),
		delayPolicy("cooling-off", 3*time.Hour, "carol", "dave"))

	after := h.delayDetail(open.ID)
	if after.CancelledBy != "https://idp.test#carol" {
		t.Fatalf("cancelled_by = %q, want it preserved", after.CancelledBy)
	}
	if after.CancelledAt == nil || !after.CancelledAt.Equal(cancelled) {
		t.Fatalf("cancelled_at = %v, want it preserved as %s", after.CancelledAt, cancelled)
	}
	if got := h.challengeRow(open.ID, 0).State; got != store.ChallengeFailed {
		t.Fatalf("challenge state = %q, want the cancellation to hold it failed", got)
	}
	if got := h.decisionState(open.ID); got != store.DecisionDenied {
		t.Fatalf("decision state = %q, want the cancellation to deny it", got)
	}
	h.verifyChain()
}

// ---------------------------------------------------------------------------
// mfa
// ---------------------------------------------------------------------------

// A step-up the subject may be halfway through survives a revision that did not
// change what is being authorized. The correlator is the binding and IssuedAt is
// the lower bound an `auth_time` has to beat, so rotating either would strand an
// authentication in flight.
func TestAnUnrelatedRevisionKeepsAStepUpCorrelator(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	seed(t, h, mfaPolicy("step-up", testACR))
	h.lock(1, "a", "b")

	open := h.tenantDecision(transferRequest("u1", 5000))
	before := h.mfaDetail(open.ID)
	if before.Correlator == "" {
		t.Fatal("the step-up was opened with no correlator")
	}
	h.clock.Advance(time.Hour)
	h.landUnrelated("unrelated")

	after := h.mfaDetail(open.ID)
	if after.Correlator != before.Correlator {
		t.Fatalf("the correlator rotated from %q to %q on an unrelated revision",
			before.Correlator, after.Correlator)
	}
	if !after.IssuedAt.Equal(before.IssuedAt) {
		t.Fatalf("issued_at moved from %s to %s, which moves the auth_time floor under an "+
			"authentication already in flight", before.IssuedAt, after.IssuedAt)
	}
	h.verifyChain()
}

// A completion already recorded is a completion. Nothing about an unrelated
// revision walks it back.
func TestAnUnrelatedRevisionKeepsASatisfiedStepUpSatisfied(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	seed(t, h, mfaPolicy("step-up", testACR))
	h.lock(1, "a", "b")

	open := h.tenantDecision(transferRequest("u1", 5000))
	consumed := h.clock.Now().Add(time.Minute)
	detail := h.mfaDetail(open.ID)
	detail.ConsumedAt = &consumed
	detail.ConsumedBy = "https://idp.test#u1"
	h.writeDetail(open.ID, 0, detail)

	h.clock.Advance(time.Hour)
	h.landUnrelated("unrelated")

	after := h.mfaDetail(open.ID)
	if after.ConsumedAt == nil || !after.ConsumedAt.Equal(consumed) {
		t.Fatalf("consumed_at = %v, want it preserved as %s", after.ConsumedAt, consumed)
	}
	if after.Correlator != detail.Correlator {
		t.Fatalf("the correlator rotated from %q to %q under a completed step-up",
			detail.Correlator, after.Correlator)
	}
	h.verifyChain()
}

// The one change the context hash cannot see. `acr_values` is not decision
// content, so a revision that touches only it leaves the hash exactly where it
// was — and a rebinding that trusted the hash alone would leave a challenge
// enforcing a requirement nobody declared.
func TestARevisedACRRequirementReopensTheStepUp(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	seed(t, h, mfaPolicy("step-up", testACR))
	h.lock(1, "a", "b")

	open := h.tenantDecision(transferRequest("u1", 5000))
	before := h.mfaDetail(open.ID)
	h.clock.Advance(time.Minute)

	h.land(mfaPolicy("step-up", testACR), mfaPolicy("step-up", testStrongACR))

	after := h.mfaDetail(open.ID)
	if got := after.RequiredACRValues; len(got) != 1 || got[0] != testStrongACR {
		t.Fatalf("required acr = %v, want the revised [%s]", got, testStrongACR)
	}
	if after.Correlator == before.Correlator {
		t.Fatal("the step-up kept its correlator across a raised acr requirement, so the " +
			"authentication in flight would satisfy a requirement it was not asked for")
	}
	if !after.IssuedAt.After(before.IssuedAt) {
		t.Errorf("issued_at = %s, want it moved to the re-issue instant", after.IssuedAt)
	}
	if got := h.challengeRow(open.ID, 0).State; got != store.ChallengePending {
		t.Errorf("challenge state = %q, want pending", got)
	}
	h.verifyChain()
}

// Content that moved is a different question, and an authentication requested
// for the old one no longer answers it.
func TestChangedDecisionContentReopensTheStepUp(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	seed(t, h, mfaPolicy("step-up", testACR))
	h.lock(1, "a", "b")

	h.obligations.set([]decision.Obligation{{Type: "notify", Attributes: map[string]any{"channel": "email"}}})
	open := h.tenantDecision(transferRequest("u1", 5000))
	before := h.mfaDetail(open.ID)

	h.obligations.set([]decision.Obligation{{Type: "notify", Attributes: map[string]any{"channel": "pager"}}})
	h.clock.Advance(time.Minute)
	h.land(mfaPolicy("step-up", testACR), mfaPolicy("step-up", testACR))

	after := h.mfaDetail(open.ID)
	if after.Correlator == before.Correlator {
		t.Fatal("the step-up kept its correlator although the decision content moved")
	}
	if after.ContextHash == before.ContextHash {
		t.Fatal("the context hash did not move, so this test proves nothing")
	}
	h.verifyChain()
}

// ---------------------------------------------------------------------------
// external
// ---------------------------------------------------------------------------

// The nonce binds one answer to one issuance. A revision that did not change the
// question must not invalidate a callback the target is already holding — and
// must not send a second webhook from inside the revalidation transaction.
func TestAnUnrelatedRevisionKeepsAnExternalRoundTripOpen(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	seed(t, h, externalPolicy("second-opinion", webhookPrimary))
	h.lock(1, "a", "b")

	open := h.tenantDecision(transferRequest("u1", 5000))
	before := h.externalDetail(open.ID)
	if before.Nonce == "" || !before.Acknowledged {
		t.Fatalf("the round trip did not start: %+v", before)
	}
	if got := h.webhook.count(); got != 1 {
		t.Fatalf("the target was notified %d times at issue, want 1", got)
	}

	h.clock.Advance(time.Hour)
	h.landUnrelated("unrelated")

	after := h.externalDetail(open.ID)
	if after.Nonce != before.Nonce {
		t.Fatalf("the correlator rotated from %q to %q, invalidating a callback the target holds",
			before.Nonce, after.Nonce)
	}
	if got := h.webhook.count(); got != 1 {
		t.Fatalf("the target was notified %d times, want 1: a revision must not post a webhook "+
			"from inside the transaction it is landing in", got)
	}
	if got := h.challengeRow(open.ID, 0).State; got != store.ChallengePending {
		t.Errorf("challenge state = %q, want it still waiting for a callback", got)
	}
	h.verifyChain()
}

// A revision that points the challenge at a different target fails it. The
// alternative is a second network call while this transaction holds a row lock
// on every open decision, and the fail-closed answer is the house answer
// everywhere else a round trip could not be completed.
func TestARepointedExternalTargetFailsTheChallengeWithoutASecondWebhook(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	seed(t, h, externalPolicy("second-opinion", webhookPrimary))
	h.lock(1, "a", "b")

	open := h.tenantDecision(transferRequest("u1", 5000))
	if got := h.webhook.count(); got != 1 {
		t.Fatalf("the target was notified %d times at issue, want 1", got)
	}
	h.clock.Advance(time.Minute)

	h.land(externalPolicy("second-opinion", webhookPrimary),
		externalPolicy("second-opinion", webhookSecondary))

	if got := h.webhook.count(); got != 1 {
		t.Fatalf("the target was notified %d times, want 1: re-issuing here would send a webhook "+
			"from inside the revalidation transaction", got)
	}
	after := h.externalDetail(open.ID)
	if after.Failure != challenge.ExternalFailureRetargeted {
		t.Fatalf("failure = %q, want %q", after.Failure, challenge.ExternalFailureRetargeted)
	}
	if got := h.challengeRow(open.ID, 0).State; got != store.ChallengeFailed {
		t.Fatalf("challenge state = %q, want failed", got)
	}
	if got := h.decisionState(open.ID); got != store.DecisionDenied {
		t.Fatalf("decision state = %q, want the failed challenge to deny it", got)
	}
	h.verifyChain()
}

// ---------------------------------------------------------------------------
// all four together
// ---------------------------------------------------------------------------

// M2's exit condition: one decision carrying every challenge kind survives a
// revision with each kind's rule applied, and none of the four disturbs another.
func TestARevisionRebindsEveryChallengeKindAtOnce(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	all := func() *policy.Policy {
		return gatedPolicy("everything",
			policy.Quorum{Threshold: 2, Approvers: policy.ApproverSet{Members: []string{"x", "y", "z"}}},
			policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{testACR}},
			policy.Delay{Duration: 2 * time.Hour},
			policy.External{Target: webhookPrimary},
		)
	}
	seed(t, h, all())
	h.lock(1, "a", "b")

	open := h.tenantDecision(transferRequest("u1", 5000))
	rows, err := store.ChallengeProgressFor(context.Background(), h.store.Pool(), open.ID)
	if err != nil {
		t.Fatalf("read challenge progress: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("the decision carries %d challenges, want all four kinds", len(rows))
	}
	if err := h.submitApproval(open.ID, "x"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	before := map[policy.ChallengeType]json.RawMessage{}
	for _, row := range rows {
		before[row.Kind] = row.Detail
	}
	webhooksBefore := h.webhook.count()

	h.clock.Advance(time.Hour)
	h.landUnrelated("unrelated")

	after, err := store.ChallengeProgressFor(context.Background(), h.store.Pool(), open.ID)
	if err != nil {
		t.Fatalf("read challenge progress: %v", err)
	}
	for _, row := range after {
		if string(row.Detail) != string(before[row.Kind]) {
			t.Errorf("the %s challenge was rewritten by an unrelated revision:\n before %s\n after  %s",
				row.Kind, before[row.Kind], row.Detail)
		}
	}
	if got := h.webhook.count(); got != webhooksBefore {
		t.Errorf("the external target was notified %d more times", got-webhooksBefore)
	}
	if got := h.approvalCount(open.ID); got != 1 {
		t.Errorf("approvals = %d, want the collected 1 preserved", got)
	}
	if got := h.decisionState(open.ID); got != store.DecisionPending {
		t.Errorf("decision state = %q, want pending on the three challenges still open", got)
	}
	h.verifyChain()
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
// what a relaxed challenge costs to adopt
// ---------------------------------------------------------------------------

// TestCuttingADelayIsPricedAsAWeakeningRevision is the classifier hole closed
// end to end, on the case this package already exercised for the rebinding.
//
// Before M2 this exact revision — a two-hour hold cut to eighty minutes, the
// quorum untouched, the challenge list the same length — was classified neutral.
// The author saw no findings, the approvers were shown none, and the audit row
// went in at notice severity. Nothing about the wait it was gutting appeared
// anywhere a human would read.
func TestCuttingADelayIsPricedAsAWeakeningRevision(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	seed(t, h, delayPolicy("cooling-off", 2*time.Hour))
	h.lock(2, "a", "b", "c")

	open := h.tenantDecision(transferRequest("u1", 5000))
	if !open.Pending() {
		t.Fatalf("decision state = %q, want pending on its wait", open.State)
	}
	cut := revision.Single(
		delayPolicy("cooling-off", 2*time.Hour), delayPolicy("cooling-off", 80*time.Minute))

	// R23: the author is told before submitting, which is the whole point of
	// classifying at all.
	preview, err := h.gov.Preview(context.Background(), revision.PreviewRequest{
		Proposer: user("a"), Delta: revision.Single(
			delayPolicy("cooling-off", 2*time.Hour), delayPolicy("cooling-off", 80*time.Minute)),
	})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if !preview.Weakening {
		t.Fatalf("cutting a two-hour wait to eighty minutes previewed as neutral: %+v", preview.Findings)
	}
	if !preview.ExcludeProposer {
		t.Error("the proposer is not excluded from their own weakening revision")
	}

	p := h.propose("a", cut, "")
	if !p.Weakening {
		t.Fatalf("the proposal records weakening = false; findings = %v", p.Findings)
	}
	var named bool
	for _, f := range p.Findings {
		if f.Reason == revision.ReasonDelayShortened {
			named = true
		}
	}
	if !named {
		t.Fatalf("findings = %v, want one naming %s", p.Findings, revision.ReasonDelayShortened)
	}

	t.Run("the proposer's own approval does not count", func(t *testing.T) {
		if err := h.approve(p, "a"); err == nil {
			t.Fatal("the proposer's approval was accepted")
		}
	})

	t.Run("the record says what was relaxed", func(t *testing.T) {
		// R33: the audit trail carries the severity a relaxation earns, and the
		// grounds, so an operator reading the chain afterwards sees the wait that
		// was cut rather than an unremarkable policy edit.
		rows := h.auditPayloadsFor(revision.AuditKindRevisionProposed, p.ID)
		if len(rows) != 1 {
			t.Fatalf("%d proposal audit rows, want 1", len(rows))
		}
		if got := rows[0][revision.SeverityKey]; got != revision.SeverityCritical {
			t.Errorf("severity = %v, want %q", got, revision.SeverityCritical)
		}
		findings, _ := rows[0]["findings"].([]any)
		if len(findings) == 0 {
			t.Fatal("the audit row carries no findings")
		}
		if !strings.Contains(fmt.Sprint(findings...), string(revision.ReasonDelayShortened)) {
			t.Errorf("audit findings = %v, want one naming %s", findings, revision.ReasonDelayShortened)
		}
	})

	t.Run("two approvers who did not propose it carry it", func(t *testing.T) {
		if err := h.approve(p, "b"); err != nil {
			t.Fatalf("b's approval: %v", err)
		}
		if err := h.approve(p, "c"); err != nil {
			t.Fatalf("c's approval: %v", err)
		}
		if applied := h.reconcile(); len(applied) != 1 {
			t.Fatalf("reconcile applied %d revisions, want 1", len(applied))
		}
		if got := h.state(p.ID); got != revision.StateApplied {
			t.Fatalf("revision state = %q, want %q", got, revision.StateApplied)
		}
	})
	h.verifyChain()
}
