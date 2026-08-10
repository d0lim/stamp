package revision_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// ---------------------------------------------------------------------------
// bootstrap and the lock
// ---------------------------------------------------------------------------

// The reserved policy is an ordinary policy in every respect that matters: it
// validates against its own schema and compiles like any other. If it did not,
// the dogfooding would be a story rather than a mechanism.
func TestGovernancePolicyValidatesAgainstItsOwnSchema(t *testing.T) {
	t.Parallel()
	for name, p := range map[string]*policy.Policy{
		"solo admin": revision.GovernancePolicy(),
		"quorum": revision.GovernancePolicy(policy.Quorum{
			Threshold: 2, Approvers: policy.ApproverSet{Members: []string{"a", "b", "c"}},
		}),
	} {
		t.Run(name, func(t *testing.T) {
			set := &policy.Set{Schema: *revision.GovernanceSchema(), Policies: []policy.Policy{*p}}
			if diags := policy.Validate(set); len(diags) > 0 {
				t.Fatalf("the reserved policy does not validate: %v", diags)
			}
		})
	}
}

func TestInstallStartsInSoloAdminModeAndPrintsOneToken(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	if got := h.mode(); got != revision.ModeSolo {
		t.Fatalf("mode = %q, want %q", got, revision.ModeSolo)
	}
	again, err := h.gov.Install(context.Background())
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if again != "" {
		t.Fatal("a second install printed a second bootstrap token; the token is printed once")
	}
	h.verifyChain()
}

// Bypass: reach the pre-lock governance window from anywhere on the network and
// author policy without the token. Before the lock the token is the only
// control there is.
func TestPreLockRevisionNeedsTheBootstrapToken(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	d := revision.Single(nil, tenantPolicy("high-value", 2, "a", "b", "c"))

	_, err := h.gov.Propose(context.Background(), revision.ProposeRequest{
		Proposer: user("root"), Delta: d,
	})
	if !errors.Is(err, revision.ErrBootstrapRequired) {
		t.Fatalf("propose without a token: err = %v, want %v", err, revision.ErrBootstrapRequired)
	}
	if _, live := h.effective("high-value"); live {
		t.Fatal("a revision took effect without the bootstrap token")
	}

	_, err = h.gov.Propose(context.Background(), revision.ProposeRequest{
		Proposer: user("root"), Delta: revision.Single(nil, tenantPolicy("high-value", 2, "a", "b", "c")),
		BootstrapToken: "not-the-token",
	})
	if !errors.Is(err, revision.ErrBootstrapInvalid) {
		t.Fatalf("propose with a wrong token: err = %v, want %v", err, revision.ErrBootstrapInvalid)
	}

	p, err := h.gov.Propose(context.Background(), revision.ProposeRequest{
		Proposer: user("root"), Delta: revision.Single(nil, tenantPolicy("high-value", 2, "a", "b", "c")),
		BootstrapToken: h.token,
	})
	if err != nil {
		t.Fatalf("propose with the token: %v", err)
	}
	if p.State != revision.StateApplied {
		t.Fatalf("state = %q, want %q — a solo-admin revision resolves in the same call",
			p.State, revision.StateApplied)
	}
	if _, live := h.effective("high-value"); !live {
		t.Fatal("the authorized revision did not take effect")
	}
	h.verifyChain()
}

func TestLockConsumesTheTokenAndIsIrreversible(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.lock(2, "a", "b", "c")

	if got := h.mode(); got != revision.ModeQuorum {
		t.Fatalf("mode = %q, want %q", got, revision.ModeQuorum)
	}
	status, err := h.gov.Bootstrap().Status(context.Background())
	if err != nil {
		t.Fatalf("bootstrap status: %v", err)
	}
	if !status.Consumed {
		t.Fatal("the bootstrap token survived the lock")
	}

	// The token is dead, so it cannot authorize a second lock or a pre-lock
	// revision.
	err = h.gov.Lock(context.Background(), revision.LockRequest{
		Actor: user("root"), Token: h.token,
		Quorum: policy.Quorum{Threshold: 1, Approvers: policy.ApproverSet{Members: []string{"a"}}},
	})
	if !errors.Is(err, revision.ErrBootstrapSpent) {
		t.Fatalf("second lock: err = %v, want %v", err, revision.ErrBootstrapSpent)
	}

	// And no revision may take the quorum back off.
	_, err = h.gov.Propose(context.Background(), revision.ProposeRequest{
		Proposer: user("a"),
		Delta: revision.Single(
			revision.GovernancePolicy(policy.Quorum{
				Threshold: 2, Approvers: policy.ApproverSet{Members: []string{"a", "b", "c"}},
			}),
			revision.GovernancePolicy()),
	})
	if !errors.Is(err, revision.ErrAlreadyLocked) {
		t.Fatalf("un-lock revision: err = %v, want %v", err, revision.ErrAlreadyLocked)
	}

	_, err = h.gov.Propose(context.Background(), revision.ProposeRequest{
		Proposer: user("a"),
		Delta: revision.Delta{Changes: []revision.Change{{
			Kind:     revision.ChangeDelete,
			PolicyID: revision.GovernancePolicyID,
			Before: revision.GovernancePolicy(policy.Quorum{
				Threshold: 2, Approvers: policy.ApproverSet{Members: []string{"a", "b", "c"}},
			}),
		}}},
	})
	if !errors.Is(err, revision.ErrAlreadyLocked) {
		t.Fatalf("delete-governance revision: err = %v, want %v", err, revision.ErrAlreadyLocked)
	}
	h.verifyChain()
}

// An unused token is a live administrator credential nobody is watching, so it
// keeps announcing itself at the highest severity until the lock retires it.
func TestUnusedBootstrapTokenWarnsPeriodically(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	ctx := context.Background()

	warned, err := h.gov.Bootstrap().WarnIfUnused(ctx)
	if err != nil {
		t.Fatalf("warn: %v", err)
	}
	if warned {
		t.Fatal("a token warned before its first interval elapsed")
	}

	h.clock.Advance(revision.DefaultWarnInterval + time.Minute)
	if warned, err = h.gov.Bootstrap().WarnIfUnused(ctx); err != nil || !warned {
		t.Fatalf("warn after the interval: warned = %v, err = %v", warned, err)
	}
	if warned, err = h.gov.Bootstrap().WarnIfUnused(ctx); err != nil || warned {
		t.Fatalf("a second warning fired inside one interval: warned = %v, err = %v", warned, err)
	}
	h.clock.Advance(revision.DefaultWarnInterval + time.Minute)
	if warned, err = h.gov.Bootstrap().WarnIfUnused(ctx); err != nil || !warned {
		t.Fatalf("the warning did not repeat: warned = %v, err = %v", warned, err)
	}

	payloads := h.auditPayloads(revision.AuditKindBootstrapUnused)
	if len(payloads) != 2 {
		t.Fatalf("audit holds %d unused-token warnings, want 2", len(payloads))
	}
	for _, p := range payloads {
		if p[revision.SeverityKey] != revision.SeverityCritical {
			t.Fatalf("warning severity = %v, want %q", p[revision.SeverityKey], revision.SeverityCritical)
		}
	}

	// The lock retires it.
	h.lock(2, "a", "b", "c")
	h.clock.Advance(revision.DefaultWarnInterval + time.Minute)
	if warned, err = h.gov.Bootstrap().WarnIfUnused(ctx); err != nil || warned {
		t.Fatalf("a consumed token still warns: warned = %v, err = %v", warned, err)
	}
	h.verifyChain()
}

// ---------------------------------------------------------------------------
// quorum governance
// ---------------------------------------------------------------------------

func TestPostLockRevisionDoesNotTakeEffectWithoutQuorum(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.lock(2, "a", "b", "c")

	p := h.propose("proposer", revision.Single(nil, tenantPolicy("high-value", 2, "x", "y")), "")
	if p.State != revision.StatePending {
		t.Fatalf("state = %q, want %q", p.State, revision.StatePending)
	}
	if _, live := h.effective("high-value"); live {
		t.Fatal("the revision took effect with no approvals at all")
	}
	if applied := h.reconcile(); len(applied) != 0 {
		t.Fatalf("reconcile applied %d revisions with no approvals", len(applied))
	}

	if err := h.approve(p, "a"); err != nil {
		t.Fatalf("approve as a: %v", err)
	}
	if _, live := h.effective("high-value"); live {
		t.Fatal("the revision took effect one approval short of the quorum")
	}
	if applied := h.reconcile(); len(applied) != 0 {
		t.Fatalf("reconcile applied %d revisions one approval short", len(applied))
	}

	if err := h.approve(p, "b"); err != nil {
		t.Fatalf("approve as b: %v", err)
	}
	applied := h.reconcile()
	if len(applied) != 1 || applied[0].State != revision.StateApplied {
		t.Fatalf("reconcile after the quorum: %+v", applied)
	}
	if _, live := h.effective("high-value"); !live {
		t.Fatal("the approved revision did not take effect")
	}
	h.verifyChain()
}

// AE11. The proposer is not an eligible approver, so a proposer who also
// approves contributes nothing and the revision stays one short.
func TestProposerApprovalDoesNotCountTowardTheirOwnRevision(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.lock(2, "a", "b", "c")

	// a proposes lowering the governance quorum to one: a weakening revision,
	// judged under the stricter of the old two and the proposed one.
	weakened := revision.GovernancePolicy(policy.Quorum{
		Threshold: 1, Approvers: policy.ApproverSet{Members: []string{"a", "b", "c"}},
	})
	current := revision.GovernancePolicy(policy.Quorum{
		Threshold: 2, Approvers: policy.ApproverSet{Members: []string{"a", "b", "c"}},
	})
	p := h.propose("a", revision.Single(current, weakened), "")
	if !p.Weakening {
		t.Fatal("lowering the governance quorum did not classify as weakening")
	}
	if p.Threshold != 2 {
		t.Fatalf("threshold = %d, want the stricter 2", p.Threshold)
	}

	if err := h.approve(p, "a"); err == nil {
		t.Fatal("the proposer's own approval was accepted")
	}
	if err := h.approve(p, "b"); err != nil {
		t.Fatalf("approve as b: %v", err)
	}
	if applied := h.reconcile(); len(applied) != 0 {
		t.Fatal("the revision took effect on one valid approval plus the proposer's own")
	}

	if err := h.approve(p, "c"); err != nil {
		t.Fatalf("approve as c: %v", err)
	}
	applied := h.reconcile()
	if len(applied) != 1 {
		t.Fatalf("reconcile after two non-proposer approvals applied %d revisions", len(applied))
	}
	gov, live := h.effective(revision.GovernancePolicyID)
	if !live {
		t.Fatal("the governance policy is gone")
	}
	q, ok := revision.GovernanceQuorum(gov)
	if !ok || q.Threshold != 1 {
		t.Fatalf("governance quorum = %+v, want a threshold of 1", q)
	}
	h.verifyChain()
}

// R34: a revision that leaves a quorum nobody can meet is refused at
// submission, not discovered when the challenge cannot be satisfied.
func TestShrinkingTheApproverSetBelowTheQuorumIsRefusedAtSubmission(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.lock(2, "a", "b", "c")

	current := revision.GovernancePolicy(policy.Quorum{
		Threshold: 2, Approvers: policy.ApproverSet{Members: []string{"a", "b", "c"}},
	})
	shrunk := revision.GovernancePolicy(policy.Quorum{
		Threshold: 2, Approvers: policy.ApproverSet{Members: []string{"a"}},
	})
	_, err := h.gov.Propose(context.Background(), revision.ProposeRequest{
		Proposer: user("a"), Delta: revision.Single(current, shrunk),
	})
	if !errors.Is(err, revision.ErrUnsatisfiable) {
		t.Fatalf("err = %v, want %v", err, revision.ErrUnsatisfiable)
	}
	if p, open, perr := h.gov.Pending(context.Background()); perr != nil || open {
		t.Fatalf("a refused revision holds the gate: %+v (err %v)", p, perr)
	}
}

// AE23. A delete-only delta is weakening, so it takes the stricter requirement
// and the operator floor, and the proposer's approval does not count.
func TestDeleteOnlyRevisionTakesTheFloorAndExcludesTheProposer(t *testing.T) {
	h := newHarness(t, harnessOptions{floor: revision.Floor{MinApprovers: 2}})
	before := tenantPolicy("high-value", 2, "x", "y")
	seed(t, h, before)
	h.lock(1, "a", "b", "c")

	p := h.propose("a", revision.Single(before, nil), "")
	if !p.Weakening {
		t.Fatal("a deletion did not classify as weakening")
	}
	if p.Threshold != 2 {
		t.Fatalf("threshold = %d, want the operator floor of 2 over the governance quorum of 1", p.Threshold)
	}

	if err := h.approve(p, "a"); err == nil {
		t.Fatal("the proposer approved their own deletion")
	}
	if err := h.approve(p, "b"); err != nil {
		t.Fatalf("approve as b: %v", err)
	}
	if applied := h.reconcile(); len(applied) != 0 {
		t.Fatal("the deletion took effect on one approval")
	}
	if _, live := h.effective("high-value"); !live {
		t.Fatal("the policy was deleted before the requirement was met")
	}

	if err := h.approve(p, "c"); err != nil {
		t.Fatalf("approve as c: %v", err)
	}
	if applied := h.reconcile(); len(applied) != 1 {
		t.Fatalf("reconcile applied %d revisions", len(applied))
	}
	if _, live := h.effective("high-value"); live {
		t.Fatal("the approved deletion did not take effect")
	}
	h.verifyChain()
}

func TestAddOnlyRevisionIsNotWeakening(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.lock(2, "a", "b", "c")

	preview, err := h.gov.Preview(context.Background(), revision.PreviewRequest{
		Proposer: user("a"),
		Delta:    revision.Single(nil, tenantPolicy("new-rule", 2, "x", "y")),
	})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if preview.Weakening {
		t.Fatalf("an addition classified as weakening: %v", preview.Findings)
	}
	if !preview.Admissible() {
		t.Fatalf("an addition is inadmissible: %v", preview.Violations)
	}
	if preview.Threshold != 2 {
		t.Fatalf("threshold = %d, want the governance quorum of 2", preview.Threshold)
	}
}

// A delta of several policies is one decision: no partial approval, and the
// whole set takes effect or none of it does.
func TestMultiElementRevisionTakesEffectAllOrNothing(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	doomed := tenantPolicy("doomed", 2, "x", "y")
	seed(t, h, doomed)
	h.lock(2, "a", "b", "c")

	d := revision.Delta{Changes: []revision.Change{
		{Kind: revision.ChangeAdd, PolicyID: "added-one", After: tenantPolicy("added-one", 2, "x", "y")},
		{Kind: revision.ChangeAdd, PolicyID: "added-two", After: tenantPolicy("added-two", 2, "x", "y")},
		{Kind: revision.ChangeDelete, PolicyID: "doomed", Before: doomed},
	}}
	p := h.propose("a", d, "")
	if !p.Weakening {
		t.Fatal("a delta holding one deletion did not classify as weakening set-wide")
	}
	if len(p.Findings) != 1 || p.Findings[0].Subject != "doomed" {
		t.Fatalf("findings = %v, want exactly the deletion", p.Findings)
	}

	if err := h.approve(p, "b"); err != nil {
		t.Fatalf("approve as b: %v", err)
	}
	for _, id := range []string{"added-one", "added-two"} {
		if _, live := h.effective(id); live {
			t.Fatalf("%s took effect on a partial approval", id)
		}
	}
	if _, live := h.effective("doomed"); !live {
		t.Fatal("the deletion took effect on a partial approval")
	}

	if err := h.approve(p, "c"); err != nil {
		t.Fatalf("approve as c: %v", err)
	}
	if applied := h.reconcile(); len(applied) != 1 {
		t.Fatalf("reconcile applied %d revisions", len(applied))
	}
	for _, id := range []string{"added-one", "added-two"} {
		if _, live := h.effective(id); !live {
			t.Fatalf("%s did not take effect", id)
		}
	}
	if _, live := h.effective("doomed"); live {
		t.Fatal("the deletion did not take effect")
	}
	h.verifyChain()
}

// D24: one pending revision at a time, and the proposer can release the gate
// without a quorum.
func TestOnePendingRevisionAtATimeAndWithdrawalReleasesTheGate(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.lock(2, "a", "b", "c")
	ctx := context.Background()

	first := h.propose("a", revision.Single(nil, tenantPolicy("first", 2, "x", "y")), "")

	_, err := h.gov.Propose(ctx, revision.ProposeRequest{
		Proposer: user("b"), Delta: revision.Single(nil, tenantPolicy("second", 2, "x", "y")),
	})
	if !errors.Is(err, revision.ErrRevisionPending) {
		t.Fatalf("second proposal: err = %v, want %v", err, revision.ErrRevisionPending)
	}

	if _, err := h.gov.Withdraw(ctx, user("b"), first.ID); !errors.Is(err, revision.ErrNotProposer) {
		t.Fatalf("withdrawal by a non-proposer: err = %v, want %v", err, revision.ErrNotProposer)
	}
	if _, err := h.gov.Withdraw(ctx, user("a"), first.ID); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if got := h.state(first.ID); got != revision.StateWithdrawn {
		t.Fatalf("state = %q, want %q", got, revision.StateWithdrawn)
	}
	if got := h.decisionState(first.DecisionID); got != store.DecisionCancelled {
		t.Fatalf("the withdrawn revision's decision is %q, want %q", got, store.DecisionCancelled)
	}

	if _, err := h.gov.Propose(ctx, revision.ProposeRequest{
		Proposer: user("b"), Delta: revision.Single(nil, tenantPolicy("second", 2, "x", "y")),
	}); err != nil {
		t.Fatalf("proposal after the gate was released: %v", err)
	}
	h.verifyChain()
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// seed installs a tenant policy through the pre-lock path, which is how an
// installation gets its first policies in place.
func seed(t *testing.T, h *harness, policies ...*policy.Policy) {
	t.Helper()
	var changes []revision.Change
	for _, p := range policies {
		changes = append(changes, revision.Change{Kind: revision.ChangeAdd, PolicyID: p.ID, After: p})
	}
	_, err := h.gov.Propose(context.Background(), revision.ProposeRequest{
		Proposer: user("root"), Delta: revision.Delta{Changes: changes}, BootstrapToken: h.token,
		Mode: decision.ModeGrandfather,
	})
	if err != nil {
		t.Fatalf("seed policies: %v", err)
	}
}
