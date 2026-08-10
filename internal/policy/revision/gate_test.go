package revision_test

// gate_test.go is the serialization gate with both authoring paths pushing on
// it at once, which is the scenario the plan asks to be fixed as a failing test
// before anything else.
//
// One pending revision at a time is what lets an approver review a single diff
// against the state in force (D24). The cost is a gate that can stick, and the
// release path this unit owns is the fourth one: a new proposal from the origin
// that already holds the gate replaces the one it holds, so a CI applying on
// every merge converges instead of deadlocking against its own last proposal.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// TestGateRefusesTheOtherPathBeforeParsingAnything is R47 plus the ordering the
// plan fixes: the payload limits, then the gate, then the parser.
//
// The payload here is not YAML at all. If the refusal names the gate rather
// than the syntax, the parser never ran — which is the point: a pending
// revision must not be a reason to spend CPU on a document that cannot be
// applied anyway.
func TestGateRefusesTheOtherPathBeforeParsingAnything(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	ctx := context.Background()
	h.lock(2, "ann", "bob", "cid")

	held := h.propose("cid", revision.Single(nil, tenantPolicy("form.new", 1, "ann", "bob")), "")
	if err := h.approve(held, "bob"); err != nil {
		t.Fatalf("collect one approval: %v", err)
	}

	_, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer: user("ci"),
		Payload:  payload("garbage.yaml", ": this is not a policy document ["),
	})
	if !errors.Is(err, revision.ErrRevisionPending) {
		t.Fatalf("apply = %v, want ErrRevisionPending", err)
	}
	var pending *revision.PendingError
	if !errors.As(err, &pending) {
		t.Fatalf("apply = %v, want a *PendingError carrying the open proposal", err)
	}
	if pending.Pending.ID != held.ID {
		t.Errorf("the refusal names revision %q, want %q", pending.Pending.ID, held.ID)
	}
	if pending.Pending.Origin != store.OriginForm {
		t.Errorf("the open proposal's origin is %q, want %q", pending.Pending.Origin, store.OriginForm)
	}
	if pending.Pending.Collected != 1 || pending.Pending.Threshold != 2 {
		t.Errorf("the collection status is %d/%d, want 1/2",
			pending.Pending.Collected, pending.Pending.Threshold)
	}
	if !strings.Contains(err.Error(), held.ID) {
		t.Errorf("the error text does not carry the identifier a CI would report: %v", err)
	}
}

// TestSameOriginApplySupersedesThePendingProposal is D24's fourth release path.
func TestSameOriginApplySupersedesThePendingProposal(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	ctx := context.Background()
	h.lock(2, "ann", "bob", "cid")

	first, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer: user("ci"),
		Payload:  payload("schema.yaml", h.schemaDocument(), "a.yaml", h.document(tenantPolicy("file.one", 1, "ann"))),
	})
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if first.NoChange {
		t.Fatal("the first apply found no change")
	}
	if err := h.approve(first.Proposal, "ann"); err != nil {
		t.Fatalf("collect one approval: %v", err)
	}
	if got := h.approvalCount(first.Proposal.DecisionID); got != 1 {
		t.Fatalf("the first proposal collected %d approvals, want 1", got)
	}

	// The next merge lands and the CI applies again, with a different desired
	// state. Nothing has approved the first proposal to completion.
	second, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer: user("ci"),
		Payload:  payload("schema.yaml", h.schemaDocument(), "a.yaml", h.document(tenantPolicy("file.one", 2, "ann", "bob"))),
	})
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if second.Proposal.ID == first.Proposal.ID {
		t.Fatal("the second apply reused the first proposal")
	}
	if got := h.state(first.Proposal.ID); got != revision.StateSuperseded {
		t.Errorf("the replaced proposal is %q, want %q", got, revision.StateSuperseded)
	}
	if got := h.decisionState(first.Proposal.DecisionID); got != store.DecisionCancelled {
		t.Errorf("the replaced proposal's decision is %q, want cancelled", got)
	}
	if got := h.approvalCount(second.Proposal.DecisionID); got != 0 {
		t.Errorf("the replacement carries %d approvals, want 0 — the collected ones are void", got)
	}
	if got := h.state(second.Proposal.ID); got != revision.StatePending {
		t.Errorf("the replacement is %q, want pending", got)
	}

	records := h.auditPayloadsFor(revision.AuditKindRevisionSuperseded, first.Proposal.ID)
	if len(records) != 1 {
		t.Fatalf("the supersession left %d audit records, want 1", len(records))
	}
	if records[0]["replaced_by"] != second.Proposal.ID {
		t.Errorf("the audit record points at %v, want %q", records[0]["replaced_by"], second.Proposal.ID)
	}
}

// TestTheOtherOriginNeverSupersedes is the other half of the same rule. A form
// submission arriving while the file path holds the gate is refused, because a
// path replacing another path's proposal would be a way to discard a revision
// under review without a withdrawal anyone can see.
func TestTheOtherOriginNeverSupersedes(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	ctx := context.Background()
	h.lock(2, "ann", "bob", "cid")

	held, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer: user("ci"),
		Payload:  payload("schema.yaml", h.schemaDocument(), "a.yaml", h.document(tenantPolicy("file.one", 1, "ann"))),
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	_, err = h.gov.Propose(ctx, revision.ProposeRequest{
		Proposer: user("ann"),
		Delta:    revision.Single(nil, tenantPolicy("form.new", 1, "ann", "bob")),
		Origin:   store.OriginForm,
	})
	var pending *revision.PendingError
	if !errors.As(err, &pending) {
		t.Fatalf("propose = %v, want a *PendingError", err)
	}
	if pending.Pending.ID != held.Proposal.ID {
		t.Errorf("the refusal names %q, want %q", pending.Pending.ID, held.Proposal.ID)
	}
	if pending.Pending.Origin != store.OriginFile {
		t.Errorf("the open proposal's origin is %q, want %q", pending.Pending.Origin, store.OriginFile)
	}
	if got := h.state(held.Proposal.ID); got != revision.StatePending {
		t.Errorf("the file proposal is %q, want it still pending", got)
	}
}

// TestOneConsoleSubmissionDoesNotSupersedeAnother is the deliberate narrowing.
//
// Supersession is the declarative path's convergence rule, not a property of
// sharing an origin. Two console submissions are two people's separate
// intentions, and if the second replaced the first, anybody with authoring
// rights could discard a colleague's revision under review by submitting
// something else — no withdrawal, no quorum, nothing in anyone's inbox. The
// console's stuck gate is released by the three paths that already exist.
func TestOneConsoleSubmissionDoesNotSupersedeAnother(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	ctx := context.Background()
	h.lock(2, "ann", "bob", "cid")

	held := h.propose("cid", revision.Single(nil, tenantPolicy("form.one", 1, "ann", "bob")), "")
	_, err := h.gov.Propose(ctx, revision.ProposeRequest{
		Proposer: user("ann"),
		Delta:    revision.Single(nil, tenantPolicy("form.two", 1, "ann", "bob")),
		Origin:   store.OriginForm,
	})
	if !errors.Is(err, revision.ErrRevisionPending) {
		t.Fatalf("a second console submission = %v, want ErrRevisionPending", err)
	}
	if got := h.state(held.ID); got != revision.StatePending {
		t.Errorf("the first console proposal is %q, want it untouched and pending", got)
	}
}

// TestReoccupyingTheGateHitsTheRateLimit is the rate limit D24 attaches to all
// four release paths: without it, withdraw-and-resubmit is an unbounded way to
// hold the gate forever while never leaving a proposal an approver can act on.
func TestReoccupyingTheGateHitsTheRateLimit(t *testing.T) {
	h := newHarness(t, harnessOptions{rate: revision.Rate{Window: time.Minute, Burst: 2}})
	ctx := context.Background()
	h.lock(2, "ann", "bob", "cid")

	var last error
	for i := 0; i < 3; i++ {
		result, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
			Proposer: user("ci"),
			Payload: payload("schema.yaml", h.schemaDocument(),
				"a.yaml", h.document(tenantPolicy("file.one", 1+i%2, "ann", "bob"))),
		})
		if err != nil {
			last = err
			break
		}
		if _, werr := h.gov.Withdraw(ctx, user("ci"), result.Proposal.ID); werr != nil {
			t.Fatalf("withdraw %d: %v", i, werr)
		}
	}
	if !errors.Is(last, revision.ErrRateLimited) {
		t.Fatalf("three submissions inside the window ended with %v, want ErrRateLimited", last)
	}

	// The window is what releases it, and the clock is driven rather than
	// waited on.
	h.clock.Advance(2 * time.Minute)
	if _, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer: user("ci"),
		Payload:  payload("schema.yaml", h.schemaDocument(), "a.yaml", h.document(tenantPolicy("file.one", 1, "ann"))),
	}); err != nil {
		t.Fatalf("apply after the window: %v", err)
	}
}
