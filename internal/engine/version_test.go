package engine_test

import (
	"strings"
	"testing"

	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/policy"
)

// twoPolicyDocuments is the shape every real policy set has: more than one
// policy, written against one schema.
//
// The two policies disagree about the same request on purpose. If they share a
// compiled program the disagreement is not visible as an error — it is visible
// as one policy's condition answering a request the other one matched, which is
// a wrong decision with nothing in the logs to say so.
const twoPolicyDocuments = `
apiVersion: stamp/v1
kind: Schema
entities:
  - name: user
    attributes: {id: string}
  - name: doc
    attributes: {id: string}
actions: [read, publish]
---
apiVersion: stamp/v1
kind: Policy
id: read-allowlist
subject: user
resource: doc
actions: [read]
condition:
  left: {field: subject.id}
  in: [alice]
---
apiVersion: stamp/v1
kind: Policy
id: publish-allowlist
subject: user
resource: doc
actions: [publish]
condition:
  left: {field: subject.id}
  in: [bob]
`

// The compile cache is keyed by (schema version, policy version) and by nothing
// else — not by the policy identifier. Two policies that arrive under one
// version identifier therefore share one compiled program, and the second
// policy is evaluated as the first.
//
// This is not a corner case. A store's per-policy revision counter starts at 1
// for every policy, so the straightforward loader — take the row's version
// number, stringify it — produces the collision for every set with more than
// one policy. It has to be refused where it enters, because after that point
// there is no error to notice: the evaluation succeeds and answers wrongly.
func TestNewSnapshotRejectsCollidingPolicyVersions(t *testing.T) {
	t.Parallel()
	set, err := policy.Load(strings.NewReader(twoPolicyDocuments))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(set.Policies) != 2 {
		t.Fatalf("fixture holds %d policies", len(set.Policies))
	}

	// Exactly what a loader built on store.PolicyRecord.Version produces: both
	// policies are at their own revision 1.
	_, err = engine.NewSnapshot("schema@1", set.Schema, []engine.PolicyVersion{
		{Version: "1", Policy: set.Policies[0]},
		{Version: "1", Policy: set.Policies[1]},
	})
	if err == nil {
		t.Fatal("two policies were accepted under one version identifier: they would share one compiled program")
	}
	for _, want := range []string{"publish-allowlist", "read-allowlist", "1"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error does not name %q, so it cannot be acted on: %v", want, err)
		}
	}
}

// The guard is about the pair, not about the policy revision alone: two
// policies may legitimately be at revision 1 as long as the identifier they are
// versioned under distinguishes them.
func TestNewSnapshotAcceptsDistinctVersionsPerPolicy(t *testing.T) {
	t.Parallel()
	set, err := policy.Load(strings.NewReader(twoPolicyDocuments))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	versions := make([]engine.PolicyVersion, len(set.Policies))
	for i := range set.Policies {
		versions[i] = engine.PolicyVersion{
			Version: set.Policies[i].ID + "@1",
			Policy:  set.Policies[i],
		}
	}
	snap, err := engine.NewSnapshot("schema@1", set.Schema, versions)
	if err != nil {
		t.Fatalf("new snapshot: %v", err)
	}
	if snap.Len() != 2 {
		t.Fatalf("snapshot holds %d policies", snap.Len())
	}
}

// A collision that the guard let through would show up here rather than as an
// error, which is why this asserts the decisions rather than the construction:
// with one shared program, publishing as bob is judged by the read policy's
// condition and denied, and reading as alice is judged by the publish policy's.
func TestCollidingVersionsWouldEvaluateTheWrongPolicy(t *testing.T) {
	t.Parallel()
	set, err := policy.Load(strings.NewReader(twoPolicyDocuments))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	versions := make([]engine.PolicyVersion, len(set.Policies))
	for i := range set.Policies {
		versions[i] = engine.PolicyVersion{
			Version: set.Policies[i].ID + "@1",
			Policy:  set.Policies[i],
		}
	}
	snap, err := engine.NewSnapshot("schema@1", set.Schema, versions)
	if err != nil {
		t.Fatalf("new snapshot: %v", err)
	}
	evaluator := engine.NewCheckEvaluator(snap)

	for _, tc := range []struct {
		name   string
		action string
		id     string
		allow  bool
	}{
		{"alice reads", "read", "alice", true},
		{"bob reads", "read", "bob", false},
		{"bob publishes", "publish", "bob", true},
		{"alice publishes", "publish", "alice", false},
	} {
		in := engine.Input{
			Action:   tc.action,
			Subject:  engine.Entity{Type: "user", ID: tc.id, Attributes: map[string]any{"id": tc.id}},
			Resource: engine.Entity{Type: "doc", ID: "doc-1", Attributes: map[string]any{"id": "doc-1"}},
		}
		result, err := evaluator.Evaluate(t.Context(), in)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if result.Allowed() != tc.allow {
			t.Fatalf("%s: allowed=%v, want %v (reason %q, policy %q)",
				tc.name, result.Allowed(), tc.allow, result.Reason(), result.PolicyID())
		}
	}
}
