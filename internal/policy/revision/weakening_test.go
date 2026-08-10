package revision_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// These are the bypass tests. Each one is a way to get a relaxation past the
// gate without collecting the approvals a relaxation is supposed to cost, and
// each was written before the classifier it exercises.
//
// Every fixture builds its policy values fresh. Normalization rewrites a
// condition tree in place, so two cases sharing one value would be two cases
// writing to the same nodes.

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// guarded is the shape of a policy the classifier has to reason about: a trigger
// (actions, entity bindings, condition) and a quorum challenge.
func guarded(id string, threshold int, approvers ...string) *policy.Policy {
	return &policy.Policy{
		ID:       id,
		Subject:  "user",
		Resource: "account",
		Actions:  []string{"transfer"},
		Condition: policy.Compare{
			Op:    policy.OpGe,
			Left:  policy.Field(policy.RoleResource, "amount"),
			Right: policy.Int(10000),
		},
		Challenges: []policy.Challenge{
			policy.Quorum{Threshold: threshold, Approvers: policy.ApproverSet{Members: approvers}},
		},
	}
}

// unguarded is guarded without the challenge.
func unguarded(id string) *policy.Policy {
	p := guarded(id, 2, "a", "b", "c")
	p.Challenges = nil
	return p
}

func testSchema(onError policy.OnError) *policy.Schema {
	return &policy.Schema{
		Entities: []policy.EntityType{
			{Name: "user", Attributes: []policy.Attribute{{Name: "role", Type: policy.TypeString}}},
			{Name: "account", Attributes: []policy.Attribute{{Name: "amount", Type: policy.TypeInt}}},
		},
		Actions: []policy.Action{{Name: "transfer"}, {Name: "close"}},
		Sources: []policy.SourceDecl{{
			Name:    "risk_score",
			Kind:    policy.SourceHTTP,
			Params:  []policy.Param{{Name: "role", Type: policy.TypeString}},
			Returns: policy.TypeInt,
			OnError: onError,
		}},
	}
}

func hasReason(c revision.Classification, want revision.Reason) bool {
	for _, f := range c.Findings {
		if f.Reason == want {
			return true
		}
	}
	return false
}

func reasonsOf(c revision.Classification) string {
	parts := make([]string, 0, len(c.Findings))
	for _, f := range c.Findings {
		parts = append(parts, f.String())
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, "; ")
}

// ---------------------------------------------------------------------------
// bypasses
// ---------------------------------------------------------------------------

// Bypass: delete the policy instead of removing its challenge. A delete-only
// delta that classified as non-weakening would let one approver drop the very
// control a quorum exists to protect.
func TestDeleteOnlyDeltaIsWeakening(t *testing.T) {
	d := revision.Delta{Changes: []revision.Change{{
		Kind:     revision.ChangeDelete,
		PolicyID: "high-value",
		Before:   guarded("high-value", 2, "a", "b", "c"),
	}}}

	class := revision.Classify(d)
	if !class.Weakening() {
		t.Fatalf("Classify(delete-only).Weakening() = false, want true; findings = %s", reasonsOf(class))
	}
	if !hasReason(class, revision.ReasonPolicyDeleted) {
		t.Fatalf("findings = %s, want a %s finding", reasonsOf(class), revision.ReasonPolicyDeleted)
	}
}

// Bypass: leave the policy in place but narrow its trigger until it never
// fires. Deleting a policy and adding a conjunct nothing satisfies are the same
// act with different paperwork.
func TestNarrowingATriggerIsWeakening(t *testing.T) {
	cases := map[string]struct {
		mutate func(p *policy.Policy)
	}{
		"extra conjunct": {mutate: func(p *policy.Policy) {
			p.Condition = policy.All(
				policy.Compare{Op: policy.OpGe, Left: policy.Field(policy.RoleResource, "amount"), Right: policy.Int(10000)},
				policy.Compare{Op: policy.OpEq, Left: policy.Field(policy.RoleSubject, "role"), Right: policy.String("nobody")},
			)
		}},
		"threshold raised": {mutate: func(p *policy.Policy) {
			p.Condition = policy.Compare{
				Op: policy.OpGe, Left: policy.Field(policy.RoleResource, "amount"), Right: policy.Int(1000000),
			}
		}},
		"action removed": {mutate: func(p *policy.Policy) { p.Actions = []string{} }},
		"role newly bound": {mutate: func(p *policy.Policy) {
			p.Subject = "user"
			p.Context = "user"
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			after := guarded("high-value", 2, "a", "b", "c")
			tc.mutate(after)
			d := revision.Delta{Changes: []revision.Change{{
				Kind:     revision.ChangeModify,
				PolicyID: "high-value",
				Before:   guarded("high-value", 2, "a", "b", "c"),
				After:    after,
			}}}

			class := revision.Classify(d)
			if !hasReason(class, revision.ReasonTriggerNarrowed) {
				t.Fatalf("findings = %s, want a %s finding", reasonsOf(class), revision.ReasonTriggerNarrowed)
			}
		})
	}
}

// A trigger that fires on strictly more requests than before is not a
// weakening, and reporting it as one would make every genuine tightening pay a
// weakening revision's price.
func TestWideningATriggerIsNotWeakening(t *testing.T) {
	cases := map[string]func(p *policy.Policy){
		"extra disjunct": func(p *policy.Policy) {
			p.Condition = policy.Any(
				policy.Compare{Op: policy.OpGe, Left: policy.Field(policy.RoleResource, "amount"), Right: policy.Int(10000)},
				policy.Compare{Op: policy.OpEq, Left: policy.Field(policy.RoleSubject, "role"), Right: policy.String("intern")},
			)
		},
		"threshold lowered": func(p *policy.Policy) {
			p.Condition = policy.Compare{
				Op: policy.OpGe, Left: policy.Field(policy.RoleResource, "amount"), Right: policy.Int(1000),
			}
		},
		"action added": func(p *policy.Policy) { p.Actions = []string{"transfer", "close"} },
		"role unbound": func(p *policy.Policy) { p.Context = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			before := guarded("high-value", 2, "a", "b", "c")
			before.Context = "user"
			after := guarded("high-value", 2, "a", "b", "c")
			after.Context = "user"
			mutate(after)

			d := revision.Delta{Changes: []revision.Change{{
				Kind: revision.ChangeModify, PolicyID: "high-value", Before: before, After: after,
			}}}
			class := revision.Classify(d)
			if hasReason(class, revision.ReasonTriggerNarrowed) {
				t.Fatalf("findings = %s, want no %s finding", reasonsOf(class), revision.ReasonTriggerNarrowed)
			}
		})
	}
}

// Bypass: add yourself to the approver set. The quorum number is untouched, so
// a classifier that only watched the threshold would wave it through.
func TestWideningTheApproverSetIsWeakening(t *testing.T) {
	cases := map[string]*policy.Policy{
		"member added":     guarded("high-value", 2, "a", "b", "c", "mallory"),
		"claim instead":    approverClaim("high-value", 2, "can_approve"),
		"member and claim": approverClaim("high-value", 2, "anything"),
	}
	for name, after := range cases {
		t.Run(name, func(t *testing.T) {
			d := revision.Delta{Changes: []revision.Change{{
				Kind:     revision.ChangeModify,
				PolicyID: "high-value",
				Before:   guarded("high-value", 2, "a", "b", "c"),
				After:    after,
			}}}
			class := revision.Classify(d)
			if !hasReason(class, revision.ReasonApproverSetWidened) {
				t.Fatalf("findings = %s, want a %s finding", reasonsOf(class), revision.ReasonApproverSetWidened)
			}
		})
	}
}

func approverClaim(id string, threshold int, claim string) *policy.Policy {
	p := guarded(id, threshold, "a", "b", "c")
	p.Challenges = []policy.Challenge{
		policy.Quorum{Threshold: threshold, Approvers: policy.ApproverSet{Claim: claim}},
	}
	return p
}

func TestReducingAQuorumIsWeakening(t *testing.T) {
	d := revision.Delta{Changes: []revision.Change{{
		Kind:     revision.ChangeModify,
		PolicyID: "high-value",
		Before:   guarded("high-value", 3, "a", "b", "c"),
		After:    guarded("high-value", 1, "a", "b", "c"),
	}}}
	class := revision.Classify(d)
	if !hasReason(class, revision.ReasonQuorumReduced) {
		t.Fatalf("findings = %s, want a %s finding", reasonsOf(class), revision.ReasonQuorumReduced)
	}
}

func TestRemovingAChallengeIsWeakening(t *testing.T) {
	d := revision.Delta{Changes: []revision.Change{{
		Kind:     revision.ChangeModify,
		PolicyID: "high-value",
		Before:   guarded("high-value", 2, "a", "b", "c"),
		After:    unguarded("high-value"),
	}}}
	class := revision.Classify(d)
	if !hasReason(class, revision.ReasonChallengeRemoved) {
		t.Fatalf("findings = %s, want a %s finding", reasonsOf(class), revision.ReasonChallengeRemoved)
	}
}

// Bypass: leave every policy alone and flip a fact source to fail open. Nothing
// in the policy diff moves, and every gated decision starts allowing itself
// through whenever the source is down.
func TestLooseningSourceFailureBehaviourIsWeakening(t *testing.T) {
	d := revision.Delta{
		SchemaBefore: testSchema(policy.OnErrorDeny),
		SchemaAfter:  testSchema(policy.OnErrorAllow),
	}
	class := revision.Classify(d)
	if !hasReason(class, revision.ReasonErrorBehaviourLoosened) {
		t.Fatalf("findings = %s, want a %s finding", reasonsOf(class), revision.ReasonErrorBehaviourLoosened)
	}
	if class.Findings[0].Subject != revision.SchemaSubject {
		t.Fatalf("finding subject = %q, want %q", class.Findings[0].Subject, revision.SchemaSubject)
	}
}

// Adding a policy is not weakening: a new rule can only add requirements.
func TestAddOnlyDeltaIsNotWeakening(t *testing.T) {
	d := revision.Delta{Changes: []revision.Change{
		{Kind: revision.ChangeAdd, PolicyID: "new-rule", After: guarded("new-rule", 2, "a", "b")},
		{Kind: revision.ChangeAdd, PolicyID: "other-rule", After: unguarded("other-rule")},
	}}
	class := revision.Classify(d)
	if class.Weakening() {
		t.Fatalf("Classify(add-only).Weakening() = true, want false; findings = %s", reasonsOf(class))
	}
}

// Bypass: bundle the relaxation with a pile of additions and hope the
// classification is computed per element. Weakening is a property of the delta.
func TestWeakeningInOneElementClassifiesTheWholeDelta(t *testing.T) {
	d := revision.Delta{Changes: []revision.Change{
		{Kind: revision.ChangeAdd, PolicyID: "a-new-rule", After: guarded("a-new-rule", 2, "a", "b")},
		{Kind: revision.ChangeAdd, PolicyID: "b-new-rule", After: guarded("b-new-rule", 2, "a", "b")},
		{Kind: revision.ChangeDelete, PolicyID: "high-value", Before: guarded("high-value", 2, "a", "b", "c")},
		{Kind: revision.ChangeAdd, PolicyID: "z-new-rule", After: guarded("z-new-rule", 2, "a", "b")},
	}}
	class := revision.Classify(d)
	if !class.Weakening() {
		t.Fatalf("a delta holding one deletion classifies as %s, want weakening", reasonsOf(class))
	}
	if len(class.Findings) != 1 || class.Findings[0].Subject != "high-value" {
		t.Fatalf("findings = %s, want exactly the deletion of high-value", reasonsOf(class))
	}
}

// Taking ownership of a policy moves who may author it, not what it requires.
func TestTakeOwnershipAloneIsNotWeakening(t *testing.T) {
	d := revision.Delta{Changes: []revision.Change{{
		Kind:       revision.ChangeTakeOwnership,
		PolicyID:   "high-value",
		Before:     guarded("high-value", 2, "a", "b", "c"),
		After:      guarded("high-value", 2, "a", "b", "c"),
		FromOrigin: store.OriginForm,
		ToOrigin:   store.OriginFile,
	}}}
	if class := revision.Classify(d); class.Weakening() {
		t.Fatalf("Classify(take-ownership).Weakening() = true, want false; findings = %s", reasonsOf(class))
	}
}

// ---------------------------------------------------------------------------
// the requirement
// ---------------------------------------------------------------------------

func quorumOf(threshold int, members ...string) *policy.Quorum {
	return &policy.Quorum{Threshold: threshold, Approvers: policy.ApproverSet{Members: members}}
}

// A weakening revision is decided under the stricter of the old and the new
// rules. Bypass: propose lowering the quorum and have the new, lower number
// govern its own adoption.
func TestWeakeningRevisionTakesTheStricterThreshold(t *testing.T) {
	class := revision.Classification{Findings: []revision.Finding{
		{Subject: "high-value", Reason: revision.ReasonQuorumReduced},
	}}
	req, err := revision.Require(quorumOf(2, "a", "b", "c"), quorumOf(1, "a", "b", "c"),
		class, revision.DefaultFloor(), "a")
	if err != nil {
		t.Fatalf("Require: %v", err)
	}
	if req.Threshold != 2 {
		t.Fatalf("Threshold = %d, want 2 — the stricter of the old 2 and the proposed 1", req.Threshold)
	}
	if !req.Weakening {
		t.Fatal("Weakening = false, want true")
	}
}

// The operator floor raises a requirement the governance policy set too low.
func TestOperatorFloorRaisesTheThreshold(t *testing.T) {
	class := revision.Classification{Findings: []revision.Finding{
		{Subject: "high-value", Reason: revision.ReasonPolicyDeleted},
	}}
	req, err := revision.Require(quorumOf(1, "a", "b", "c"), quorumOf(1, "a", "b", "c"),
		class, revision.Floor{MinApprovers: 2}, "a")
	if err != nil {
		t.Fatalf("Require: %v", err)
	}
	if req.Threshold != 2 {
		t.Fatalf("Threshold = %d, want the operator floor of 2", req.Threshold)
	}
}

// Bypass: propose a revision and approve it yourself. The proposer is excluded
// by removing them from the eligible set, so their submission is refused rather
// than counted and then discounted.
func TestProposerIsNotAnEligibleApprover(t *testing.T) {
	class := revision.Classification{Findings: []revision.Finding{
		{Subject: "high-value", Reason: revision.ReasonPolicyDeleted},
	}}
	req, err := revision.Require(quorumOf(2, "a", "b", "c"), quorumOf(2, "a", "b", "c"),
		class, revision.DefaultFloor(), "a")
	if err != nil {
		t.Fatalf("Require: %v", err)
	}
	if !req.ExcludeProposer {
		t.Fatal("ExcludeProposer = false, want true under the default floor")
	}
	for _, m := range req.Approvers.Members {
		if m == "a" {
			t.Fatalf("Approvers = %v, want the proposer removed", req.Approvers.Members)
		}
	}
	if len(req.Approvers.Members) != 2 {
		t.Fatalf("Approvers = %v, want b and c", req.Approvers.Members)
	}
}

// An operator may permit self-approval; it is a setting, not the default.
func TestProposerMayApproveWhenTheFloorAllowsIt(t *testing.T) {
	req, err := revision.Require(quorumOf(2, "a", "b", "c"), quorumOf(2, "a", "b", "c"),
		revision.Classification{}, revision.Floor{MinApprovers: 1, ProposerMayApprove: true}, "a")
	if err != nil {
		t.Fatalf("Require: %v", err)
	}
	if req.ExcludeProposer {
		t.Fatal("ExcludeProposer = true, want false when the operator permits it")
	}
	if len(req.Approvers.Members) != 3 {
		t.Fatalf("Approvers = %v, want all three", req.Approvers.Members)
	}
}

// The stricter approver set is the narrower one: a widened set does not get to
// govern its own adoption either.
func TestWeakeningRevisionTakesTheNarrowerApproverSet(t *testing.T) {
	class := revision.Classification{Findings: []revision.Finding{
		{Subject: "high-value", Reason: revision.ReasonApproverSetWidened},
	}}
	req, err := revision.Require(quorumOf(2, "a", "b", "c"), quorumOf(2, "a", "b", "c", "mallory"),
		class, revision.Floor{MinApprovers: 1, ProposerMayApprove: true}, "a")
	if err != nil {
		t.Fatalf("Require: %v", err)
	}
	for _, m := range req.Approvers.Members {
		if m == "mallory" {
			t.Fatalf("Approvers = %v, want the newly added approver excluded", req.Approvers.Members)
		}
	}
}

// A requirement no eligible set could meet is refused rather than opened as a
// decision nobody can resolve.
func TestRequirementNoApproverSetCouldMeetIsRefused(t *testing.T) {
	class := revision.Classification{Findings: []revision.Finding{
		{Subject: "high-value", Reason: revision.ReasonPolicyDeleted},
	}}
	_, err := revision.Require(quorumOf(2, "a", "b"), quorumOf(2, "a", "b"),
		class, revision.DefaultFloor(), "a")
	if !errors.Is(err, revision.ErrUnsatisfiable) {
		t.Fatalf("err = %v, want %v — two approvers minus the proposer cannot make a quorum of two",
			err, revision.ErrUnsatisfiable)
	}
}

// Bypass: shrink the approver set below the quorum and lock governance out
// permanently. Every quorum the delta leaves behind has to be reachable.
func TestShrinkingTheApproverSetBelowTheQuorumIsRefused(t *testing.T) {
	d := revision.Delta{Changes: []revision.Change{{
		Kind:     revision.ChangeModify,
		PolicyID: "high-value",
		Before:   guarded("high-value", 2, "a", "b", "c"),
		After:    guarded("high-value", 2, "a"),
	}}}
	if err := revision.CheckSatisfiable(d); !errors.Is(err, revision.ErrUnsatisfiable) {
		t.Fatalf("CheckSatisfiable = %v, want %v", err, revision.ErrUnsatisfiable)
	}
}

func TestSatisfiableDeltaPasses(t *testing.T) {
	d := revision.Delta{Changes: []revision.Change{{
		Kind:     revision.ChangeModify,
		PolicyID: "high-value",
		Before:   guarded("high-value", 2, "a", "b", "c"),
		After:    guarded("high-value", 2, "a", "b"),
	}}}
	if err := revision.CheckSatisfiable(d); err != nil {
		t.Fatalf("CheckSatisfiable = %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// bypasses through the three kinds M2 added
//
// Until M2 the quorum was the only challenge kind, so a classifier that
// inspected quorums was a classifier that inspected challenges. Landing delay,
// mfa and external turned that into a hole: every relaxation below left the
// challenge list the same length and every quorum untouched, which is the whole
// of what the classifier used to look at.
//
// The stance is U9's, unchanged: anything not provably a tightening is a
// loosening. Over-charging a revision is friction; under-charging it is the
// bypass.
// ---------------------------------------------------------------------------

// delayed is the shape of a policy gated by a wait.
func delayed(id string, wait time.Duration, cancellers ...string) *policy.Policy {
	p := guarded(id, 2, "a", "b", "c")
	d := policy.Delay{Duration: wait}
	if len(cancellers) > 0 {
		d.CancellableBy = &policy.ApproverSet{Members: cancellers}
	}
	p.Challenges = []policy.Challenge{d}
	return p
}

func steppedUp(id string, acr ...string) *policy.Policy {
	p := guarded(id, 2, "a", "b", "c")
	p.Challenges = []policy.Challenge{policy.MFA{Mode: policy.MFADelegated, ACRValues: acr}}
	return p
}

func referred(id, target string) *policy.Policy {
	p := guarded(id, 2, "a", "b", "c")
	p.Challenges = []policy.Challenge{policy.External{Target: target}}
	return p
}

func modify(id string, before, after *policy.Policy) revision.Delta {
	return revision.Delta{Changes: []revision.Change{{
		Kind: revision.ChangeModify, PolicyID: id, Before: before, After: after,
	}}}
}

// Bypass: leave the delay challenge in place and cut it to nothing. The
// challenge list is the same length and the quorum is untouched, so every check
// the classifier used to run passes — and a twenty-four hour hold that somebody
// was expected to notice within has become a millisecond.
func TestShorteningADelayIsWeakening(t *testing.T) {
	cases := map[string]time.Duration{
		"cut to a millisecond": time.Millisecond,
		"cut by a third":       16 * time.Hour,
		"cut by twenty pct":    80 * time.Minute,
	}
	for name, shortened := range cases {
		t.Run(name, func(t *testing.T) {
			class := revision.Classify(modify("cooling-off",
				delayed("cooling-off", 24*time.Hour), delayed("cooling-off", shortened)))
			if !hasReason(class, revision.ReasonDelayShortened) {
				t.Fatalf("findings = %s, want a %s finding", reasonsOf(class), revision.ReasonDelayShortened)
			}
		})
	}
}

// A longer wait is a stricter control, and charging it a weakening revision's
// price would make every tightening expensive — the same reason the numeric
// bound comparison exists for triggers.
func TestLengtheningADelayIsNotWeakening(t *testing.T) {
	class := revision.Classify(modify("cooling-off",
		delayed("cooling-off", time.Hour), delayed("cooling-off", 24*time.Hour)))
	if class.Weakening() {
		t.Fatalf("lengthening a wait classified as weakening: %s", reasonsOf(class))
	}
}

// Bypass: keep the wait and take away the ability to stop it.
//
// A cancellation authority is not an escape hatch from the wait — cancelling a
// delay resolves the decision to deny — so it is a veto, and taking a veto away
// grows the set of requests that end in allow. Narrowing it, dropping it, and
// swapping it for a form that cannot be compared are the same act at three
// different volumes.
func TestNarrowingACancellationAuthorityIsWeakening(t *testing.T) {
	cases := map[string]*policy.Policy{
		"member removed": delayed("cooling-off", time.Hour, "carol"),
		"dropped whole":  delayed("cooling-off", time.Hour),
		"swapped for a claim": func() *policy.Policy {
			p := delayed("cooling-off", time.Hour)
			p.Challenges = []policy.Challenge{policy.Delay{
				Duration:      time.Hour,
				CancellableBy: &policy.ApproverSet{Claim: "can_cancel"},
			}}
			return p
		}(),
	}
	for name, after := range cases {
		t.Run(name, func(t *testing.T) {
			class := revision.Classify(modify("cooling-off",
				delayed("cooling-off", time.Hour, "carol", "dave"), after))
			if !hasReason(class, revision.ReasonCancellationNarrowed) {
				t.Fatalf("findings = %s, want a %s finding", reasonsOf(class), revision.ReasonCancellationNarrowed)
			}
		})
	}
}

// Handing the veto to more people is a tightening, and this is where a delay
// parts company with a quorum: a quorum approver grants and a delay canceller
// denies, so the two run in opposite directions and reusing the approver-set
// rule here would charge a revision for strengthening a control.
func TestWideningACancellationAuthorityIsNotWeakening(t *testing.T) {
	class := revision.Classify(modify("cooling-off",
		delayed("cooling-off", time.Hour, "carol"),
		delayed("cooling-off", time.Hour, "carol", "dave")))
	if class.Weakening() {
		t.Fatalf("widening a cancellation authority classified as weakening: %s", reasonsOf(class))
	}
}

// Bypass: keep the step-up and accept a weaker authentication for it. The
// challenge is still declared, so a classifier counting challenges sees nothing,
// and `acr` is the only thing standing between a password login and a satisfied
// step-up.
func TestRelaxingTheRequiredACRIsWeakening(t *testing.T) {
	const gold, silver = "urn:mace:incommon:iap:gold", "urn:mace:incommon:iap:silver"
	cases := map[string]*policy.Policy{
		"class added":         steppedUp("step-up", gold, silver),
		"requirement dropped": steppedUp("step-up"),
		"class exchanged":     steppedUp("step-up", silver),
	}
	for name, after := range cases {
		t.Run(name, func(t *testing.T) {
			class := revision.Classify(modify("step-up", steppedUp("step-up", gold), after))
			if !hasReason(class, revision.ReasonAuthenticationRelaxed) {
				t.Fatalf("findings = %s, want a %s finding", reasonsOf(class), revision.ReasonAuthenticationRelaxed)
			}
		})
	}
}

// Naming fewer classes, or naming any at all where the operator allowlist used
// to be the whole requirement, accepts strictly fewer authentications.
func TestTighteningTheRequiredACRIsNotWeakening(t *testing.T) {
	const gold, silver = "urn:mace:incommon:iap:gold", "urn:mace:incommon:iap:silver"
	cases := map[string][2]*policy.Policy{
		"class removed":     {steppedUp("step-up", gold, silver), steppedUp("step-up", gold)},
		"requirement added": {steppedUp("step-up"), steppedUp("step-up", gold)},
		"reordered":         {steppedUp("step-up", gold, silver), steppedUp("step-up", silver, gold)},
		// Restating one class, padded and repeated, is the same requirement —
		// the classifier normalizes with the same function the handler does.
		"restated and padded": {steppedUp("step-up", gold), steppedUp("step-up", gold, " "+gold+" ", "", gold)},
	}
	for name, pair := range cases {
		t.Run(name, func(t *testing.T) {
			class := revision.Classify(modify("step-up", pair[0], pair[1]))
			if hasReason(class, revision.ReasonAuthenticationRelaxed) {
				t.Fatalf("findings = %s, want no %s finding", reasonsOf(class), revision.ReasonAuthenticationRelaxed)
			}
		})
	}
}

// Bypass: point the external challenge at a system that always says yes. The
// challenge is still there, and the operator's own target list is the only place
// the difference is visible — which is exactly why the floor should price it.
func TestRepointingAnExternalTargetIsWeakening(t *testing.T) {
	class := revision.Classify(modify("second-opinion",
		referred("second-opinion", "fraud-desk"), referred("second-opinion", "my-own-service")))
	if !hasReason(class, revision.ReasonExternalTargetChanged) {
		t.Fatalf("findings = %s, want a %s finding", reasonsOf(class), revision.ReasonExternalTargetChanged)
	}
}

// The same target respelled is the same target. The handler trims the name
// before it looks it up, so the classifier has to trim it before it compares.
func TestRestatingTheSameExternalTargetIsNotWeakening(t *testing.T) {
	class := revision.Classify(modify("second-opinion",
		referred("second-opinion", "fraud-desk"), referred("second-opinion", "  fraud-desk  ")))
	if class.Weakening() {
		t.Fatalf("restating a target classified as weakening: %s", reasonsOf(class))
	}
}

// The whole point, stated once: none of the four relaxations above changes the
// number of challenges or touches a quorum, which is all the classifier looked
// at before M2.
func TestNoneOfTheNewRelaxationsTouchesAQuorumOrTheChallengeCount(t *testing.T) {
	const gold = "urn:mace:incommon:iap:gold"
	cases := map[string]revision.Delta{
		"delay cut": modify("cooling-off",
			delayed("cooling-off", 24*time.Hour, "carol"), delayed("cooling-off", time.Millisecond, "carol")),
		"veto removed": modify("cooling-off",
			delayed("cooling-off", time.Hour, "carol"), delayed("cooling-off", time.Hour)),
		"acr relaxed": modify("step-up", steppedUp("step-up", gold), steppedUp("step-up")),
		"target repointed": modify("second-opinion",
			referred("second-opinion", "fraud-desk"), referred("second-opinion", "my-own-service")),
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			class := revision.Classify(d)
			if !class.Weakening() {
				t.Fatalf("Classify(%s).Weakening() = false, want true; findings = %s", name, reasonsOf(class))
			}
			for _, f := range class.Findings {
				if f.Reason == revision.ReasonChallengeRemoved || f.Reason == revision.ReasonQuorumReduced {
					t.Fatalf("the finding came from the pre-M2 checks (%s), so this case proves nothing", f)
				}
			}
		})
	}
}

// Every declared ground has a name in the exported list. A ground the classifier
// can produce but Reasons() does not name is a vocabulary that has drifted from
// the code, and the vocabulary is what an operator reads.
func TestEveryNewGroundIsInTheDeclaredVocabulary(t *testing.T) {
	for _, want := range []revision.Reason{
		revision.ReasonDelayShortened,
		revision.ReasonCancellationNarrowed,
		revision.ReasonAuthenticationRelaxed,
		revision.ReasonExternalTargetChanged,
	} {
		if !slices.Contains(revision.Reasons(), want) {
			t.Errorf("Reasons() does not name %q", want)
		}
	}
}
