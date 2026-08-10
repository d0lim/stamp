package revision_test

// before_test.go is the proof that the "before" face of a revision is the
// server's and not the proposer's.
//
// The classifier decides whether a revision is weakening, and a weakening
// revision is judged by the stricter of the old and new rules (R33). Every one
// of the classifier's "previous state" inputs — Change.Before and
// Delta.SchemaBefore — arrives in the submitter's request body. A proposer who
// writes a flattering previous state therefore writes their own classification,
// and the tests here submit exactly those forgeries through Service.Propose.
//
// They go through Propose rather than calling Classify, because Classify is not
// what a proposer talks to. A unit test over the classifier proves the
// classifier is right about the inputs it is given, which is the half of the
// claim that was never in doubt.

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// loosenedSchema is the tenant schema with one fact source's failure behaviour
// moved from deny to allow. That is R33's schema-level weakening: no policy diff
// shows it, and every request the source fails on now allows instead of denies.
func loosenedSchema() *policy.Schema {
	s := tenantSchema()
	for i := range s.Sources {
		if s.Sources[i].Name == "risk_score" {
			s.Sources[i].OnError = policy.OnErrorAllow
		}
	}
	return s
}

// schemaWithExtraAction is a schema with one more action declared. It is the
// innocuous half of the forgery in
// TestForgedSchemaBeforeCannotHideALoosenedFactSource: the submitted before and
// after have to differ somewhere, or the delta changes nothing at all.
func schemaWithExtraAction(s *policy.Schema) *policy.Schema {
	out := *s
	out.Actions = append(append([]policy.Action{}, s.Actions...), policy.Action{Name: "freeze"})
	return &out
}

// namesReason reports whether the findings name a ground.
func namesReason(findings []revision.Finding, reason revision.Reason) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

// lockedWithFactPolicy seeds a fact-reaching tenant policy and locks governance
// at two of three, which is the state every test below starts from.
func lockedWithFactPolicy(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t, harnessOptions{})
	h.seed(store.OriginForm, factPolicy("risk-gate", "risk_score", 2, "x", "y", "z"))
	h.lock(2, "a", "b", "c")
	return h
}

// A revision that loosens a fact source from deny to allow, submitted without a
// schema_before at all — which is what the console sends today — must still be
// classified as weakening. Before the server reconstructed the before face the
// classifier returned early on a nil before and reported nothing.
func TestOmittedSchemaBeforeCannotHideALoosenedFactSource(t *testing.T) {
	h := lockedWithFactPolicy(t)

	p, err := h.gov.Propose(context.Background(), revision.ProposeRequest{
		Proposer: user("a"),
		Delta:    revision.Delta{SchemaAfter: loosenedSchema()},
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if !p.Weakening {
		t.Errorf("weakening = false; a revision that moves risk_score from deny to allow is weakening (R33), "+
			"and omitting schema_before must not decide that. findings = %v", p.Findings)
	}
	if !namesReason(p.Findings, revision.ReasonErrorBehaviourLoosened) {
		t.Errorf("findings = %v, want one naming %q", p.Findings, revision.ReasonErrorBehaviourLoosened)
	}
	if p.Threshold != 2 {
		t.Errorf("threshold = %d, want 2", p.Threshold)
	}
}

// The same loosening, submitted with a schema_before that echoes the after's
// failure behaviour back. The two documents still differ — an added action — so
// the revision is a schema revision and the loosening does take effect; what the
// forgery buys is a classification that never sees it.
func TestForgedSchemaBeforeCannotHideALoosenedFactSource(t *testing.T) {
	h := lockedWithFactPolicy(t)

	p, err := h.gov.Propose(context.Background(), revision.ProposeRequest{
		Proposer: user("a"),
		Delta: revision.Delta{
			SchemaBefore: loosenedSchema(),
			SchemaAfter:  schemaWithExtraAction(loosenedSchema()),
		},
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if !p.Weakening {
		t.Errorf("weakening = false; the stored schema denies on a risk_score failure and this revision "+
			"allows, whatever the submitted schema_before claims. findings = %v", p.Findings)
	}
	if !namesReason(p.Findings, revision.ReasonErrorBehaviourLoosened) {
		t.Errorf("findings = %v, want one naming %q", p.Findings, revision.ReasonErrorBehaviourLoosened)
	}
	if p.Threshold != 2 {
		t.Errorf("threshold = %d, want 2", p.Threshold)
	}
}

// A quorum cut from three to one, submitted with a Change.Before that claims it
// was one all along. The policy the store holds is the only before there is.
func TestForgedChangeBeforeCannotHideAQuorumCut(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.seed(store.OriginForm, tenantPolicy("high-value", 3, "x", "y", "z"))
	h.lock(2, "a", "b", "c")

	p, err := h.gov.Propose(context.Background(), revision.ProposeRequest{
		Proposer: user("a"),
		Delta: revision.Delta{Changes: []revision.Change{{
			Kind:     revision.ChangeModify,
			PolicyID: "high-value",
			Before:   tenantPolicy("high-value", 1, "x", "y", "z"),
			After:    tenantPolicy("high-value", 1, "x", "y", "z"),
		}}},
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if !p.Weakening {
		t.Errorf("weakening = false; high-value demands three approvals in the store and one after this "+
			"revision, and a submitted before that says one cannot decide that. findings = %v", p.Findings)
	}
	if !namesReason(p.Findings, revision.ReasonQuorumReduced) {
		t.Errorf("findings = %v, want one naming %q", p.Findings, revision.ReasonQuorumReduced)
	}
	if p.Threshold != 2 {
		t.Errorf("threshold = %d, want 2", p.Threshold)
	}
}

// The approval count itself. R33 says a weakening revision meets the stricter of
// the old and the new rule; a revision classified neutral meets only the old
// one. So a proposer who raises the governance bar in the same breath as a
// forged-neutral weakening is judged at the bar they are replacing.
func TestForgedBeforeBuysTheOldApprovalCount(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.seed(store.OriginForm, tenantPolicy("high-value", 3, "x", "y", "z"))
	h.lock(2, "a", "b", "c", "d")

	p, err := h.gov.Propose(context.Background(), revision.ProposeRequest{
		Proposer: user("a"),
		Delta: revision.Delta{Changes: []revision.Change{
			{
				Kind:     revision.ChangeModify,
				PolicyID: "high-value",
				Before:   tenantPolicy("high-value", 1, "x", "y", "z"),
				After:    tenantPolicy("high-value", 1, "x", "y", "z"),
			},
			{
				Kind:     revision.ChangeModify,
				PolicyID: revision.GovernancePolicyID,
				Before: revision.GovernancePolicy(policy.Quorum{
					Threshold: 2, Approvers: policy.ApproverSet{Members: []string{"a", "b", "c", "d"}},
				}),
				After: revision.GovernancePolicy(policy.Quorum{
					Threshold: 3, Approvers: policy.ApproverSet{Members: []string{"a", "b", "c", "d"}},
				}),
			},
		}},
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if !p.Weakening {
		t.Errorf("weakening = false, want true; findings = %v", p.Findings)
	}
	if p.Threshold != 3 {
		t.Errorf("threshold = %d, want 3 — a weakening revision is judged by the stricter of the old and "+
			"the new governance rule, and this one installs three", p.Threshold)
	}
}

// R31: the digest an approval is bound to has to cover the delta the approver is
// shown, and both have to be the reconstructed one. This fails if the before
// face is rebuilt after the digest is taken, or if the proposal records the
// submitted delta.
func TestProposalRecordsTheReconstructedDeltaAndItsDigest(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.seed(store.OriginForm, tenantPolicy("high-value", 3, "x", "y", "z"))
	h.lock(2, "a", "b", "c")

	p, err := h.gov.Propose(context.Background(), revision.ProposeRequest{
		Proposer: user("a"),
		Delta: revision.Delta{Changes: []revision.Change{{
			Kind:     revision.ChangeModify,
			PolicyID: "high-value",
			Before:   tenantPolicy("high-value", 1, "x", "y", "z"),
			After:    tenantPolicy("high-value", 1, "x", "y", "z"),
		}}},
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}

	stored, err := h.gov.Get(context.Background(), p.ID)
	if err != nil {
		t.Fatalf("read the revision back: %v", err)
	}
	change, ok := stored.Delta.Change("high-value")
	if !ok || change.Before == nil {
		t.Fatalf("the persisted delta carries no before for high-value: %+v", stored.Delta)
	}
	q, has := quorumIn(change.Before)
	if !has || q.Threshold != 3 {
		t.Errorf("the persisted before demands %+v; the store holds a quorum of 3, and that is what an "+
			"approver has to be shown", q)
	}
	digest, err := stored.Delta.Digest()
	if err != nil {
		t.Fatalf("digest the persisted delta: %v", err)
	}
	if got := hex.EncodeToString(digest[:]); got != stored.DeltaDigest {
		t.Errorf("delta_digest = %s, but the persisted delta digests to %s — the hash an approval is bound "+
			"to does not cover the delta the approver is shown", stored.DeltaDigest, got)
	}
}

// The capability half of the same change. Reconstructing before [Delta.Validate]
// means the before is an invariant rather than an echo, which is what lets a
// console that cannot read the state in force submit an edit at all (U15).
func TestASubmissionNeedNotCarryABeforeAtAll(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.seed(store.OriginForm,
		tenantPolicy("high-value", 3, "x", "y", "z"),
		tenantPolicy("doomed", 2, "x", "y"))
	h.lock(1, "a", "b")

	p, err := h.gov.Propose(context.Background(), revision.ProposeRequest{
		Proposer: user("a"),
		Delta: revision.Delta{Changes: []revision.Change{
			{Kind: revision.ChangeModify, PolicyID: "high-value", After: tenantPolicy("high-value", 1, "x", "y", "z")},
			{Kind: revision.ChangeDelete, PolicyID: "doomed"},
		}},
	})
	if err != nil {
		t.Fatalf("propose without a before: %v", err)
	}
	if !p.Weakening {
		t.Errorf("weakening = false; the revision cuts one quorum and deletes one policy. findings = %v",
			p.Findings)
	}
	if !namesReason(p.Findings, revision.ReasonQuorumReduced) ||
		!namesReason(p.Findings, revision.ReasonPolicyDeleted) {
		t.Errorf("findings = %v, want both %q and %q",
			p.Findings, revision.ReasonQuorumReduced, revision.ReasonPolicyDeleted)
	}
}

// The preview an author is shown and the submission they make must reach the
// same conclusion. They do because both go through the same reconstruction; a
// preview that classified the submitted before while the submission classified
// the stored one would be a lie about the price (R23).
func TestPreviewClassifiesTheSameReconstructedDelta(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.seed(store.OriginForm, tenantPolicy("high-value", 3, "x", "y", "z"))
	h.lock(2, "a", "b", "c")

	d := revision.Delta{Changes: []revision.Change{{
		Kind:     revision.ChangeModify,
		PolicyID: "high-value",
		Before:   tenantPolicy("high-value", 1, "x", "y", "z"),
		After:    tenantPolicy("high-value", 1, "x", "y", "z"),
	}}}
	view, err := h.gov.Preview(context.Background(), revision.PreviewRequest{
		Proposer: user("a"), Delta: d,
	})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if !view.Weakening {
		t.Errorf("preview says weakening = false; findings = %v", view.Findings)
	}

	p, err := h.gov.Propose(context.Background(), revision.ProposeRequest{
		Proposer: user("a"),
		Delta: revision.Delta{Changes: []revision.Change{{
			Kind:     revision.ChangeModify,
			PolicyID: "high-value",
			Before:   tenantPolicy("high-value", 1, "x", "y", "z"),
			After:    tenantPolicy("high-value", 1, "x", "y", "z"),
		}}},
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if p.Weakening != view.Weakening || p.Threshold != view.Threshold {
		t.Errorf("preview said weakening=%v threshold=%d, submission said weakening=%v threshold=%d",
			view.Weakening, view.Threshold, p.Weakening, p.Threshold)
	}
}

// Reconstruction fills in a before and does not decide what the change is. A
// kind that disagrees with the store is still refused where it was refused
// before — by the outcome check, whose message names the disagreement — and not
// by a shape rule that would report a missing field instead.
func TestAKindThatDisagreesWithTheStoreIsStillRefusedByTheOutcome(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.seed(store.OriginForm, tenantPolicy("high-value", 3, "x", "y", "z"))
	h.lock(1, "a", "b")

	for name, tc := range map[string]struct {
		change revision.Change
		want   string
	}{
		"modify of a policy the set does not hold": {
			change: revision.Change{
				Kind: revision.ChangeModify, PolicyID: "ghost",
				Before: tenantPolicy("ghost", 3, "x", "y", "z"),
				After:  tenantPolicy("ghost", 1, "x", "y", "z"),
			},
			want: `cannot change "ghost", which the set does not hold`,
		},
		"add of a policy the set already holds": {
			change: revision.Change{
				Kind: revision.ChangeAdd, PolicyID: "high-value",
				After: tenantPolicy("high-value", 1, "x", "y", "z"),
			},
			want: `cannot add "high-value", which the set already holds`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.gov.Propose(context.Background(), revision.ProposeRequest{
				Proposer: user("a"), Delta: revision.Delta{Changes: []revision.Change{tc.change}},
			})
			if !errors.Is(err, revision.ErrInvalidDelta) {
				t.Fatalf("err = %v, want %v", err, revision.ErrInvalidDelta)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// The file path already computed its before face from the store, so
// reconstruction has to be a no-op there — including on the one change kind that
// exists only on that path. This test is green before the reconstruction and
// green after it; it is here to say which of the two paths was ever the problem.
func TestFileApplyKeepsItsOwnBeforeFace(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	ctx := context.Background()
	h.seed(store.OriginForm, tenantPolicy("console.one", 3, "ann", "bob", "cat"))

	const adoption = "apiVersion: stamp/v1\nkind: Adoption\npolicies:\n  - console.one\n"
	result, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer:       user("ci"),
		BootstrapToken: h.token,
		Payload: payload(
			"schema.yaml", h.schemaDocument(),
			"a.yaml", h.document(tenantPolicy("console.one", 1, "ann", "bob", "cat")),
			"adopt.yaml", adoption,
		),
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	change, ok := result.Proposal.Delta.Change("console.one")
	if !ok || change.Kind != revision.ChangeTakeOwnership {
		t.Fatalf("the proposal carries %q, want a take-ownership entry", change.Kind)
	}
	q, has := quorumIn(change.Before)
	if !has || q.Threshold != 3 {
		t.Errorf("the take-ownership before demands %+v, want the stored quorum of 3", q)
	}
	if !result.Proposal.Weakening || !namesReason(result.Proposal.Findings, revision.ReasonQuorumReduced) {
		t.Errorf("a handover that also cuts the quorum is weakening; weakening = %v, findings = %v",
			result.Proposal.Weakening, result.Proposal.Findings)
	}
}

func quorumIn(p *policy.Policy) (policy.Quorum, bool) {
	if p == nil {
		return policy.Quorum{}, false
	}
	for _, c := range p.Challenges {
		if q, ok := c.(policy.Quorum); ok {
			return q, true
		}
	}
	return policy.Quorum{}, false
}
