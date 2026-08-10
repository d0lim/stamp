package revision_test

import (
	"errors"
	"testing"

	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// The delta is the type every other part of governance is written against, so
// what it can and cannot express is fixed here rather than discovered later.

func TestDeltaRoundTripsThroughItsWireForm(t *testing.T) {
	d := revision.Delta{
		SchemaBefore: testSchema(policy.OnErrorDeny),
		SchemaAfter:  testSchema(policy.OnErrorAllow),
		Changes: []revision.Change{
			{Kind: revision.ChangeAdd, PolicyID: "added", After: guarded("added", 2, "a", "b")},
			{Kind: revision.ChangeModify, PolicyID: "changed",
				Before: guarded("changed", 2, "a", "b"), After: guarded("changed", 3, "a", "b", "c")},
			{Kind: revision.ChangeDelete, PolicyID: "removed", Before: guarded("removed", 1, "a")},
			{Kind: revision.ChangeTakeOwnership, PolicyID: "moved",
				Before: guarded("moved", 2, "a", "b"), After: guarded("moved", 2, "a", "b"),
				FromOrigin: store.OriginForm, ToOrigin: store.OriginFile},
		},
	}
	digest, err := d.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	raw, err := d.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var back revision.Delta
	if err := back.UnmarshalJSON(raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Len() != d.Len() {
		t.Fatalf("round trip holds %d changes, want %d", back.Len(), d.Len())
	}
	backDigest, err := back.Digest()
	if err != nil {
		t.Fatalf("digest after the round trip: %v", err)
	}
	if backDigest != digest {
		t.Fatal("the digest moved across a round trip; an approval bound to it would not survive storage")
	}
	if c, ok := back.Change("moved"); !ok || c.ToOrigin != store.OriginFile {
		t.Fatalf("the ownership handover did not survive: %+v", c)
	}
}

// The digest is what an approval is bound to, so two deltas that differ
// anywhere must not share one.
func TestDeltaDigestSeparatesDifferentChangeSets(t *testing.T) {
	one := revision.Single(nil, guarded("added", 2, "a", "b"))
	two := revision.Single(nil, guarded("added", 2, "a", "b", "c"))
	first, err := one.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	second, err := two.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if first == second {
		t.Fatal("two different change sets share a digest")
	}
}

func TestDeltaValidateRefusesMalformedProposals(t *testing.T) {
	cases := map[string]revision.Delta{
		"empty": {},
		"add carrying a previous policy": {Changes: []revision.Change{{
			Kind: revision.ChangeAdd, PolicyID: "p",
			Before: guarded("p", 1, "a"), After: guarded("p", 1, "a"),
		}}},
		"delete carrying a new policy": {Changes: []revision.Change{{
			Kind: revision.ChangeDelete, PolicyID: "p",
			Before: guarded("p", 1, "a"), After: guarded("p", 1, "a"),
		}}},
		"modify with no previous policy": {Changes: []revision.Change{{
			Kind: revision.ChangeModify, PolicyID: "p", After: guarded("p", 1, "a"),
		}}},
		"two entries for one policy": {Changes: []revision.Change{
			{Kind: revision.ChangeAdd, PolicyID: "p", After: guarded("p", 1, "a")},
			{Kind: revision.ChangeDelete, PolicyID: "p", Before: guarded("p", 1, "a")},
		}},
		"document disagrees with the entry": {Changes: []revision.Change{{
			Kind: revision.ChangeAdd, PolicyID: "p", After: guarded("q", 1, "a"),
		}}},
		"handover naming one path": {Changes: []revision.Change{{
			Kind: revision.ChangeTakeOwnership, PolicyID: "p",
			Before: guarded("p", 1, "a"), After: guarded("p", 1, "a"),
			FromOrigin: store.OriginForm,
		}}},
		"handover to itself": {Changes: []revision.Change{{
			Kind: revision.ChangeTakeOwnership, PolicyID: "p",
			Before: guarded("p", 1, "a"), After: guarded("p", 1, "a"),
			FromOrigin: store.OriginForm, ToOrigin: store.OriginForm,
		}}},
		"unknown kind": {Changes: []revision.Change{{
			Kind: "rewrite", PolicyID: "p", After: guarded("p", 1, "a"),
		}}},
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			if err := d.Validate(); !errors.Is(err, revision.ErrInvalidDelta) {
				t.Fatalf("Validate = %v, want %v", err, revision.ErrInvalidDelta)
			}
		})
	}
}

func TestDeltaValidateAcceptsAWellFormedProposal(t *testing.T) {
	d := revision.Delta{Changes: []revision.Change{
		{Kind: revision.ChangeAdd, PolicyID: "a-added", After: guarded("a-added", 2, "a", "b")},
		{Kind: revision.ChangeDelete, PolicyID: "b-removed", Before: guarded("b-removed", 1, "a")},
	}}
	if err := d.Validate(); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
}

// A schema-only revision is a revision: a source's failure behaviour lives
// there and nowhere else.
func TestSchemaOnlyDeltaIsWellFormed(t *testing.T) {
	d := revision.Delta{
		SchemaBefore: testSchema(policy.OnErrorDeny),
		SchemaAfter:  testSchema(policy.OnErrorAllow),
	}
	if !d.SchemaChanged() {
		t.Fatal("SchemaChanged = false for a changed schema")
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
}

// Diff compares by identifier and by document, so a policy that only moved
// between files is not a delete plus a create.
func TestDiffComputesAddModifyAndDelete(t *testing.T) {
	before := &policy.Set{
		Schema:   *testSchema(policy.OnErrorDeny),
		Policies: []policy.Policy{*guarded("kept", 2, "a", "b"), *guarded("changed", 2, "a", "b"), *guarded("removed", 1, "a")},
	}
	after := &policy.Set{
		Schema:   *testSchema(policy.OnErrorDeny),
		Policies: []policy.Policy{*guarded("kept", 2, "a", "b"), *guarded("changed", 3, "a", "b", "c"), *guarded("added", 1, "a")},
	}
	d := revision.Diff(before, after)

	want := map[string]revision.ChangeKind{
		"added":   revision.ChangeAdd,
		"changed": revision.ChangeModify,
		"removed": revision.ChangeDelete,
	}
	if d.Len() != len(want) {
		t.Fatalf("diff holds %d changes (%v), want %d", d.Len(), d.PolicyIDs(), len(want))
	}
	for id, kind := range want {
		c, ok := d.Change(id)
		if !ok {
			t.Fatalf("diff does not mention %q", id)
		}
		if c.Kind != kind {
			t.Fatalf("%q is a %s, want a %s", id, c.Kind, kind)
		}
	}
	if d.Touches("kept") {
		t.Fatal("an unchanged policy appears in the diff")
	}
}

func TestResultAppliesTheDeltaToASet(t *testing.T) {
	base := &policy.Set{
		Schema:   *testSchema(policy.OnErrorDeny),
		Policies: []policy.Policy{*guarded("kept", 2, "a", "b"), *guarded("doomed", 1, "a")},
	}
	d := revision.Delta{Changes: []revision.Change{
		{Kind: revision.ChangeDelete, PolicyID: "doomed", Before: guarded("doomed", 1, "a")},
		{Kind: revision.ChangeAdd, PolicyID: "fresh", After: guarded("fresh", 2, "a", "b")},
	}}
	result, err := d.Result(base)
	if err != nil {
		t.Fatalf("Result: %v", err)
	}
	if _, ok := result.Policy("doomed"); ok {
		t.Fatal("the deleted policy is still in the result")
	}
	if _, ok := result.Policy("fresh"); !ok {
		t.Fatal("the added policy is not in the result")
	}
	if _, ok := result.Policy("kept"); !ok {
		t.Fatal("an untouched policy fell out of the result")
	}
	// The base is not modified: a caller previewing a revision must not have its
	// live set rewritten underneath it.
	if len(base.Policies) != 2 {
		t.Fatalf("the base set now holds %d policies, want the original 2", len(base.Policies))
	}
}

func TestResultRefusesImpossibleChanges(t *testing.T) {
	base := &policy.Set{Policies: []policy.Policy{*guarded("kept", 2, "a", "b")}}
	cases := map[string]revision.Delta{
		"delete what is not there": {Changes: []revision.Change{
			{Kind: revision.ChangeDelete, PolicyID: "absent", Before: guarded("absent", 1, "a")},
		}},
		"add what is already there": {Changes: []revision.Change{
			{Kind: revision.ChangeAdd, PolicyID: "kept", After: guarded("kept", 1, "a")},
		}},
		"modify what is not there": {Changes: []revision.Change{
			{Kind: revision.ChangeModify, PolicyID: "absent",
				Before: guarded("absent", 1, "a"), After: guarded("absent", 2, "a", "b")},
		}},
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := d.Result(base); !errors.Is(err, revision.ErrInvalidDelta) {
				t.Fatalf("Result = %v, want %v", err, revision.ErrInvalidDelta)
			}
		})
	}
}

// A single-policy edit is a one-element delta and nothing else. If it were its
// own type, the classifier, the approval hash and the effect hook would each
// need a second implementation.
func TestSingleIsAOneElementDelta(t *testing.T) {
	cases := map[string]struct {
		before, after *policy.Policy
		kind          revision.ChangeKind
	}{
		"add":    {nil, guarded("p", 2, "a", "b"), revision.ChangeAdd},
		"modify": {guarded("p", 2, "a", "b"), guarded("p", 3, "a", "b", "c"), revision.ChangeModify},
		"delete": {guarded("p", 2, "a", "b"), nil, revision.ChangeDelete},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d := revision.Single(tc.before, tc.after)
			if d.Len() != 1 {
				t.Fatalf("Single produced %d changes, want 1", d.Len())
			}
			if d.Changes[0].Kind != tc.kind {
				t.Fatalf("kind = %q, want %q", d.Changes[0].Kind, tc.kind)
			}
			if err := d.Validate(); err != nil {
				t.Fatalf("Validate = %v, want nil", err)
			}
		})
	}
}
