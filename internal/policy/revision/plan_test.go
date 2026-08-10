package revision_test

// plan_test.go pins the desired-state comparison, which is the half of the file
// authoring path that has no database in it.
//
// The comparison is where D23 becomes code. Scoping it to file-authored
// policies is not an optimization — without it the next apply computes every
// console-authored policy as a deletion and a CI proposes wiping the console's
// work on every merge. So the scoping case, the conflict case and the handover
// case are all here, where they run without Docker.

import (
	"errors"
	"strings"
	"testing"

	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// current builds a current state from (id, origin) pairs over the tenant schema.
func current(t *testing.T, owned ...revision.CurrentPolicy) revision.CurrentState {
	t.Helper()
	return revision.CurrentState{Schema: *tenantSchema(), Policies: owned}
}

func owned(p *policy.Policy, origin store.Origin) revision.CurrentPolicy {
	return revision.CurrentPolicy{Policy: p, Origin: origin}
}

// desired assembles a policy set the way a directory would, through the parser,
// so the comparison is fed exactly what a hand-written file produces.
func desired(t *testing.T, policies ...*policy.Policy) *policy.Set {
	t.Helper()
	set := &policy.Set{Schema: *tenantSchema()}
	for _, p := range policies {
		set.Policies = append(set.Policies, *p)
	}
	doc, err := policy.Marshal(set)
	if err != nil {
		t.Fatalf("marshal the desired set: %v", err)
	}
	out, err := policy.Decode(strings.NewReader(string(doc)))
	if err != nil {
		t.Fatalf("decode the desired set: %v", err)
	}
	return out
}

// TestPlanScopesTheComparisonToFileAuthoredPolicies is D23 in one assertion: a
// console-authored policy absent from the directory is not a deletion.
func TestPlanScopesTheComparisonToFileAuthoredPolicies(t *testing.T) {
	t.Parallel()
	state := current(t,
		owned(tenantPolicy("console.only", 1, "ann"), store.OriginForm),
		owned(tenantPolicy("file.one", 1, "ann"), store.OriginFile),
		owned(tenantPolicy("file.two", 1, "ann"), store.OriginFile),
	)
	delta, err := revision.PlanApply(state, desired(t,
		tenantPolicy("file.one", 1, "ann"),
		tenantPolicy("file.two", 1, "ann"),
	), nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if delta.Len() != 0 {
		t.Fatalf("the delta holds %d changes, want none: %v", delta.Len(), delta.PolicyIDs())
	}
	if delta.Touches("console.only") {
		t.Error("the console-authored policy is in the delta; a CI would propose deleting it on every merge")
	}
}

// TestPlanDeletesFileAuthoredPoliciesTheDirectoryDropped is the other half: the
// scoping must not make deletion impossible for the path that owns the policy.
func TestPlanDeletesFileAuthoredPoliciesTheDirectoryDropped(t *testing.T) {
	t.Parallel()
	state := current(t,
		owned(tenantPolicy("console.only", 1, "ann"), store.OriginForm),
		owned(tenantPolicy("file.one", 1, "ann"), store.OriginFile),
		owned(tenantPolicy("file.two", 1, "ann"), store.OriginFile),
	)
	delta, err := revision.PlanApply(state, desired(t, tenantPolicy("file.one", 2, "ann", "bob")), nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if delta.Len() != 2 {
		t.Fatalf("the delta holds %d changes, want 2: %v", delta.Len(), delta.PolicyIDs())
	}
	modify, ok := delta.Change("file.one")
	if !ok || modify.Kind != revision.ChangeModify {
		t.Errorf("file.one is %v, want a modify", modify.Kind)
	}
	drop, ok := delta.Change("file.two")
	if !ok || drop.Kind != revision.ChangeDelete {
		t.Errorf("file.two is %v, want a delete", drop.Kind)
	}
}

// TestPlanTreatsAnIdenticalConsolePolicyAsNoChange is the export→apply gate at
// the comparison level.
//
// Export writes the effective set, console-authored policies included, because
// it is the entry path for a deployment moving to file authoring. Applying that
// output must be a no-op — so a document identical to a form-authored policy is
// neither a conflict nor a change. Only a document that would *alter* a policy
// the other path owns is the conflict R54 refuses.
func TestPlanTreatsAnIdenticalConsolePolicyAsNoChange(t *testing.T) {
	t.Parallel()
	state := current(t,
		owned(tenantPolicy("console.only", 1, "ann"), store.OriginForm),
		owned(tenantPolicy("file.one", 1, "ann"), store.OriginFile),
	)
	delta, err := revision.PlanApply(state, desired(t,
		tenantPolicy("console.only", 1, "ann"),
		tenantPolicy("file.one", 1, "ann"),
	), nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if delta.Len() != 0 {
		t.Fatalf("the delta holds %d changes, want none: %v", delta.Len(), delta.PolicyIDs())
	}
}

// TestPlanRefusesToEditAConsolePolicyWithoutAHandover is R54's conflict.
func TestPlanRefusesToEditAConsolePolicyWithoutAHandover(t *testing.T) {
	t.Parallel()
	state := current(t, owned(tenantPolicy("console.only", 1, "ann"), store.OriginForm))
	_, err := revision.PlanApply(state, desired(t, tenantPolicy("console.only", 2, "ann", "bob")), nil)
	if !errors.Is(err, revision.ErrOriginConflict) {
		t.Fatalf("plan = %v, want ErrOriginConflict", err)
	}
	if !strings.Contains(err.Error(), "console.only") {
		t.Errorf("the refusal does not name the policy: %v", err)
	}
}

// TestPlanMovesOriginOnlyOnAnExplicitDeclaration is R54's handover.
func TestPlanMovesOriginOnlyOnAnExplicitDeclaration(t *testing.T) {
	t.Parallel()
	state := current(t, owned(tenantPolicy("console.only", 1, "ann"), store.OriginForm))
	delta, err := revision.PlanApply(state,
		desired(t, tenantPolicy("console.only", 2, "ann", "bob")), []string{"console.only"})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	change, ok := delta.Change("console.only")
	if !ok {
		t.Fatal("the delta does not carry the adopted policy")
	}
	if change.Kind != revision.ChangeTakeOwnership {
		t.Errorf("the change is %q, want %q", change.Kind, revision.ChangeTakeOwnership)
	}
	if change.FromOrigin != store.OriginForm || change.ToOrigin != store.OriginFile {
		t.Errorf("the handover is %q → %q, want %q → %q",
			change.FromOrigin, change.ToOrigin, store.OriginForm, store.OriginFile)
	}
}

// TestPlanRefusesAnAdoptionOfSomethingItDoesNotAuthor keeps the declaration
// honest: adopting a policy the directory does not carry would move ownership
// to a path that has no document for it.
func TestPlanRefusesAnAdoptionOfSomethingItDoesNotAuthor(t *testing.T) {
	t.Parallel()
	state := current(t, owned(tenantPolicy("console.only", 1, "ann"), store.OriginForm))
	_, err := revision.PlanApply(state, desired(t), []string{"console.only"})
	if !errors.Is(err, revision.ErrInvalidPayload) {
		t.Fatalf("plan = %v, want ErrInvalidPayload", err)
	}
}

// TestPlanRefusesAReservedPolicyDocument stops the file path from authoring the
// rule that governs the file path.
func TestPlanRefusesAReservedPolicyDocument(t *testing.T) {
	t.Parallel()
	state := current(t, owned(tenantPolicy("file.one", 1, "ann"), store.OriginFile))
	set := desired(t, tenantPolicy("file.one", 1, "ann"))
	set.Policies = append(set.Policies, *tenantPolicy(revision.GovernancePolicyID, 1, "ann"))
	_, err := revision.PlanApply(state, set, nil)
	if !errors.Is(err, revision.ErrInvalidPayload) {
		t.Fatalf("plan = %v, want ErrInvalidPayload", err)
	}
}

// TestPlanLeavesGovernanceAloneOnAnEmptyDirectory is the empty-apply case. The
// reserved policy is console-owned, so the scoping already excludes it — this
// asserts that the scoping is what protects it, rather than a special case
// somebody could remove.
func TestPlanLeavesGovernanceAloneOnAnEmptyDirectory(t *testing.T) {
	t.Parallel()
	state := revision.CurrentState{
		Schema: *tenantSchema(),
		Policies: []revision.CurrentPolicy{
			owned(revision.GovernancePolicy(), store.OriginForm),
			owned(tenantPolicy("file.one", 1, "ann"), store.OriginFile),
		},
	}
	delta, err := revision.PlanApply(state, desired(t), nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if delta.Touches(revision.GovernancePolicyID) {
		t.Fatal("an empty directory proposed a change to the governance policy")
	}
	if !delta.Touches("file.one") {
		t.Error("an empty directory did not propose deleting the file-authored policy")
	}
}
