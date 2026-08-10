package revision_test

import (
	"reflect"
	"testing"

	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// These exercise the effect hook through the whole stack, because that is the
// only place its guarantees are real: the revision writes and the revalidation
// have to land in one transaction, the frozen snapshot has to come out of a
// jsonb column, and "the approvals survived" has to be a row count.

// The author's explicit choice: pending decisions finish under the version they
// were created against, and the choice is on the record.
func TestGrandfatherKeepsPendingDecisionsOnTheOldVersion(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	seed(t, h, tenantPolicy("high-value", 2, "x", "y", "z"))
	h.lock(1, "a", "b")

	open := h.tenantDecision(transferRequest("u1", 5000))
	if !open.Pending() {
		t.Fatalf("decision state = %q, want pending", open.State)
	}
	if err := h.submitApproval(open.ID, "x"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	_, versionBefore := h.decisionPolicyVersion(open.ID)

	p := h.propose("a", revision.Single(
		tenantPolicy("high-value", 2, "x", "y", "z"),
		tenantPolicy("high-value", 3, "x", "y", "z")), decision.ModeGrandfather)
	if err := h.approve(p, "b"); err != nil {
		t.Fatalf("approve the revision: %v", err)
	}
	if applied := h.reconcile(); len(applied) != 1 {
		t.Fatalf("reconcile applied %d revisions", len(applied))
	}

	if _, version := h.decisionPolicyVersion(open.ID); version != versionBefore {
		t.Fatalf("policy version moved from %d to %d under grandfather", versionBefore, version)
	}
	if got := h.challengeNeed(open.ID); got != 2 {
		t.Fatalf("the challenge now needs %d approvals, want the original 2", got)
	}
	if got := h.approvalCount(open.ID); got != 1 {
		t.Fatalf("approvals = %d, want the collected 1", got)
	}
	if got := h.decisionState(open.ID); got != store.DecisionPending {
		t.Fatalf("decision state = %q, want pending", got)
	}

	rows := h.auditPayloadsFor(decision.AuditKindGrandfathered, open.ID)
	if len(rows) != 1 {
		t.Fatalf("audit holds %d grandfather rows for the decision, want 1", len(rows))
	}
	if rows[0]["application_mode"] != string(decision.ModeGrandfather) {
		t.Fatalf("audit records mode %v, want %q", rows[0]["application_mode"], decision.ModeGrandfather)
	}
	h.verifyChain()
}

// R31: the threshold is not an input to the binding hash, so raising a quorum
// keeps the approvals already collected and only asks for more.
func TestRaisingAQuorumPreservesCollectedApprovals(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	seed(t, h, tenantPolicy("high-value", 2, "x", "y", "z"))
	h.lock(1, "a", "b")

	open := h.tenantDecision(transferRequest("u1", 5000))
	if err := h.submitApproval(open.ID, "x"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	p := h.propose("a", revision.Single(
		tenantPolicy("high-value", 2, "x", "y", "z"),
		tenantPolicy("high-value", 3, "x", "y", "z")), "")
	if p.Weakening {
		t.Fatalf("raising a quorum classified as weakening: %v", p.Findings)
	}
	if err := h.approve(p, "b"); err != nil {
		t.Fatalf("approve the revision: %v", err)
	}
	if applied := h.reconcile(); len(applied) != 1 {
		t.Fatalf("reconcile applied %d revisions", len(applied))
	}

	if got := h.approvalCount(open.ID); got != 1 {
		t.Fatalf("approvals = %d, want 1 preserved", got)
	}
	if got := h.challengeNeed(open.ID); got != 3 {
		t.Fatalf("the challenge needs %d approvals, want the revised 3", got)
	}
	if got := h.decisionState(open.ID); got != store.DecisionPending {
		t.Fatalf("decision state = %q, want pending at one of three", got)
	}
	h.verifyChain()
}

// The same quorum set with different obligations is different material, so the
// hash moves and every approval already collected is invalidated.
func TestChangedObligationsInvalidateEveryApproval(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	seed(t, h, tenantPolicy("high-value", 2, "x", "y", "z"))
	h.lock(1, "a", "b")

	h.obligations.set([]decision.Obligation{{Type: "notify", Attributes: map[string]any{"channel": "email"}}})
	open := h.tenantDecision(transferRequest("u1", 5000))
	if err := h.submitApproval(open.ID, "x"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if got := h.approvalCount(open.ID); got != 1 {
		t.Fatalf("approvals before the revision = %d, want 1", got)
	}

	// The revision leaves the quorum set alone and changes what the decision
	// obliges the caller to do.
	h.obligations.set([]decision.Obligation{{Type: "notify", Attributes: map[string]any{"channel": "pager"}}})
	p := h.propose("a", revision.Single(
		tenantPolicy("high-value", 2, "x", "y", "z"),
		tenantPolicy("high-value", 2, "x", "y", "z")), "")
	if err := h.approve(p, "b"); err != nil {
		t.Fatalf("approve the revision: %v", err)
	}
	if applied := h.reconcile(); len(applied) != 1 {
		t.Fatalf("reconcile applied %d revisions", len(applied))
	}

	if got := h.approvalCount(open.ID); got != 0 {
		t.Fatalf("approvals = %d, want every one invalidated", got)
	}
	if got := h.decisionState(open.ID); got != store.DecisionPending {
		t.Fatalf("decision state = %q, want pending with nothing collected", got)
	}
	rows := h.auditPayloadsFor(decision.AuditKindApprovalsInvalidated, open.ID)
	if len(rows) != 1 {
		t.Fatalf("audit holds %d invalidation rows, want 1", len(rows))
	}
	h.verifyChain()
}

// R5, D5: revaluation judges against the frozen snapshot. The condition that
// held at creation no longer holds under the revision, and no source is asked
// again to establish that.
func TestRevaluationDeniesOnTheFrozenSnapshotWithoutRefetching(t *testing.T) {
	resolver := newResolver(60)
	h := newHarness(t, harnessOptions{resolver: resolver})
	seed(t, h, factPolicy("risky", "risk_score", 2, "x", "y", "z"))
	h.lock(1, "a", "b")

	open := h.tenantDecision(transferRequest("u1", 5000))
	if !open.Pending() {
		t.Fatalf("decision state = %q, want pending", open.State)
	}
	if err := h.submitApproval(open.ID, "x"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	fetchesBefore := resolver.count()

	raised := factPolicy("risky", "risk_score", 2, "x", "y", "z")
	raised.Condition = policy.Compare{
		Op:    policy.OpGe,
		Left:  policy.Source("risk_score", policy.Field(policy.RoleSubject, "role")),
		Right: policy.Int(100),
	}
	p := h.propose("a", revision.Single(factPolicy("risky", "risk_score", 2, "x", "y", "z"), raised), "")
	if err := h.approve(p, "b"); err != nil {
		t.Fatalf("approve the revision: %v", err)
	}
	if applied := h.reconcile(); len(applied) != 1 {
		t.Fatalf("reconcile applied %d revisions", len(applied))
	}

	if got := h.decisionState(open.ID); got != store.DecisionDenied {
		t.Fatalf("decision state = %q, want %q", got, store.DecisionDenied)
	}
	if got := resolver.count(); got != fetchesBefore {
		t.Fatalf("the fact plane was asked %d times during revaluation, want 0 — the snapshot is frozen",
			got-fetchesBefore)
	}
	rows := h.auditPayloadsFor(decision.AuditKindRevalidated, open.ID)
	if len(rows) != 1 || rows[0]["disposition"] != decision.DispositionDenied {
		t.Fatalf("audit rows = %v, want one denial", rows)
	}
	h.verifyChain()
}

// The one exception to "no re-fetch": a source the snapshot never held. Exactly
// that source is fetched, it is added to the snapshot, and the snapshot having
// moved invalidates every approval.
func TestANewlyReferencedSourceIsFetchedAndInvalidatesApprovals(t *testing.T) {
	resolver := newResolver(60)
	h := newHarness(t, harnessOptions{resolver: resolver})
	seed(t, h, factPolicy("risky", "risk_score", 2, "x", "y", "z"))
	h.lock(1, "a", "b")

	open := h.tenantDecision(transferRequest("u1", 5000))
	if err := h.submitApproval(open.ID, "x"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if got := h.approvalCount(open.ID); got != 1 {
		t.Fatalf("approvals before the revision = %d, want 1", got)
	}
	namesBefore := resolver.names()

	extended := factPolicy("risky", "risk_score", 2, "x", "y", "z")
	extended.Condition = policy.All(
		policy.Compare{
			Op:    policy.OpGe,
			Left:  policy.Source("risk_score", policy.Field(policy.RoleSubject, "role")),
			Right: policy.Int(50),
		},
		policy.Compare{
			Op:    policy.OpGe,
			Left:  policy.Source("sanctions_hits", policy.Field(policy.RoleSubject, "role")),
			Right: policy.Int(0),
		},
	)
	p := h.propose("a", revision.Single(factPolicy("risky", "risk_score", 2, "x", "y", "z"), extended), "")
	if err := h.approve(p, "b"); err != nil {
		t.Fatalf("approve the revision: %v", err)
	}
	applied := h.reconcile()
	if len(applied) != 1 {
		t.Fatalf("reconcile applied %d revisions", len(applied))
	}

	added := resolver.names()[len(namesBefore):]
	if !reflect.DeepEqual(added, []string{"sanctions_hits"}) {
		t.Fatalf("revaluation fetched %v, want only sanctions_hits", added)
	}
	snapshot := h.factSnapshotOf(open.ID)
	if len(snapshot) != 2 {
		t.Fatalf("the fact snapshot holds %d entries, want the original plus the new one: %v",
			len(snapshot), snapshot)
	}
	if got := h.approvalCount(open.ID); got != 0 {
		t.Fatalf("approvals = %d, want every one invalidated by the moved snapshot", got)
	}
	if got := h.decisionState(open.ID); got != store.DecisionPending {
		t.Fatalf("decision state = %q, want pending with the approvals recollected", got)
	}
	if applied[0].Report == nil || len(applied[0].Report.Fetched) != 1 {
		t.Fatalf("the revision report does not name the fetched source: %+v", applied[0].Report)
	}
	h.verifyChain()
}
