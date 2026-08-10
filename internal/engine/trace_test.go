package engine_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/policy"
)

// traceDocuments is a policy with a nested condition and a challenge, so a dry
// run has something to report per node and something to report as firing.
const traceDocuments = `
apiVersion: stamp/v1
kind: Schema
entities:
  - name: user
    attributes: {id: string, level: int}
  - name: doc
    attributes: {id: string}
actions: [read]
---
apiVersion: stamp/v1
kind: Policy
id: senior-read
subject: user
resource: doc
actions: [read]
condition:
  all:
    - left: {field: subject.id}
      in: [alice, bob]
    - left: {field: subject.level}
      op: ge
      right: 3
challenges:
  - type: quorum
    threshold: 2
    approvers: {members: [carol, dave]}
`

func loadOne(t *testing.T, documents string) (*policy.Set, *policy.Policy) {
	t.Helper()
	set, err := policy.Load(strings.NewReader(documents))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(set.Policies) != 1 {
		t.Fatalf("want one policy, got %d", len(set.Policies))
	}
	return set, &set.Policies[0]
}

func levelRequest(id string, level int64) engine.Input {
	return engine.Input{
		Action:   "read",
		Subject:  engine.Entity{Type: "user", ID: id, Attributes: map[string]any{"id": id, "level": level}},
		Resource: engine.Entity{Type: "doc", ID: "doc-1", Attributes: map[string]any{"id": "doc-1"}},
	}
}

func TestTraceReportsMatchPerConditionResultsAndFiringChallenges(t *testing.T) {
	t.Parallel()
	set, p := loadOne(t, traceDocuments)

	trace, err := engine.Trace(t.Context(), &set.Schema, p, levelRequest("alice", 5), nil)
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	if !trace.Matched || !trace.Holds {
		t.Fatalf("matched=%v holds=%v", trace.Matched, trace.Holds)
	}
	// A challenge-bearing policy is never an allow on this path, and the dry
	// run says so with the same reason a served request would have got.
	if trace.Decision != engine.Deny || trace.Reason != engine.ReasonRequiresDecision {
		t.Fatalf("verdict: %s / %s", trace.Decision, trace.Reason)
	}
	if len(trace.Challenges) != 1 || trace.Challenges[0].ChallengeType() != policy.ChallengeQuorum {
		t.Fatalf("challenges: %+v", trace.Challenges)
	}

	want := map[string]bool{"/condition": true, "/condition/all/0": true, "/condition/all/1": true}
	if len(trace.Nodes) != len(want) {
		t.Fatalf("nodes: %+v", trace.Nodes)
	}
	for _, node := range trace.Nodes {
		expected, known := want[node.Pointer]
		if !known {
			t.Fatalf("unexpected node pointer %q", node.Pointer)
		}
		if node.Result == nil || *node.Result != expected {
			t.Fatalf("node %q: result %v, want %v", node.Pointer, node.Result, expected)
		}
	}
}

func TestTraceSeparatesTheFailingRow(t *testing.T) {
	t.Parallel()
	set, p := loadOne(t, traceDocuments)

	// On the allowlist, but not senior enough: the root is false and the
	// author can see which of the two rows produced it.
	trace, err := engine.Trace(t.Context(), &set.Schema, p, levelRequest("alice", 1), nil)
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	if !trace.Matched || trace.Holds {
		t.Fatalf("matched=%v holds=%v", trace.Matched, trace.Holds)
	}
	if trace.Reason != engine.ReasonConditionNotMet {
		t.Fatalf("reason: %s", trace.Reason)
	}
	if len(trace.Challenges) != 0 {
		t.Fatalf("a policy whose condition failed must fire no challenge: %+v", trace.Challenges)
	}
	results := map[string]bool{}
	for _, node := range trace.Nodes {
		if node.Result == nil {
			t.Fatalf("node %q could not be evaluated: %s", node.Pointer, node.Error)
		}
		results[node.Pointer] = *node.Result
	}
	if !results["/condition/all/0"] || results["/condition/all/1"] || results["/condition"] {
		t.Fatalf("per-row results: %+v", results)
	}
}

func TestTraceReportsANonMatchWithoutJudging(t *testing.T) {
	t.Parallel()
	set, p := loadOne(t, traceDocuments)

	in := levelRequest("alice", 5)
	in.Action = "publish"
	trace, err := engine.Trace(t.Context(), &set.Schema, p, in, nil)
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	if trace.Matched {
		t.Fatal("a policy that does not govern the action reported a match")
	}
	if trace.Reason != engine.ReasonNoMatchingPolicy {
		t.Fatalf("reason: %s", trace.Reason)
	}
}

// stubResolver answers a fixed set of calls and counts the batches it was asked
// for, so a test can assert that a dry run resolves facts the way a served
// request does: once, before evaluation.
type stubResolver struct {
	values  map[string]any
	batches atomic.Int64
	calls   atomic.Int64
}

func (r *stubResolver) ResolveSources(_ context.Context, calls []engine.SourceCall) (*engine.Facts, error) {
	r.batches.Add(1)
	facts := engine.NewFacts()
	for _, call := range calls {
		r.calls.Add(1)
		value, ok := r.values[call.String()]
		if !ok {
			return nil, errors.New("stub resolver has no value for " + call.String())
		}
		facts.Set(call, value)
	}
	return facts, nil
}

const factDocuments = `
apiVersion: stamp/v1
kind: Schema
entities:
  - name: user
    attributes: {id: string}
  - name: doc
    attributes: {id: string}
actions: [read]
sources:
  - name: members
    kind: http
    params:
      - group: string
    returns: list<string>
---
apiVersion: stamp/v1
kind: Policy
id: group-read
subject: user
resource: doc
actions: [read]
condition:
  any:
    - left: {field: subject.id}
      in: {source: members, args: [readers]}
    - left: {field: subject.id}
      in: {source: members, args: [admins]}
`

func TestTraceResolvesFactsInOneBatch(t *testing.T) {
	t.Parallel()
	set, p := loadOne(t, factDocuments)
	resolver := &stubResolver{values: map[string]any{
		`members(s:"readers")`: []any{"alice"},
		`members(s:"admins")`:  []any{"root"},
	}}

	trace, err := engine.Trace(t.Context(), &set.Schema, p, readRequest("alice"), resolver)
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	if !trace.Holds {
		t.Fatalf("condition did not hold: %+v", trace.Nodes)
	}
	// One batch for the whole dry run, including the per-node replays: the
	// explanation must not re-fetch facts the verdict was computed from.
	if got := resolver.batches.Load(); got != 1 {
		t.Fatalf("fact batches: want 1, got %d", got)
	}
	if got := resolver.calls.Load(); got != 2 {
		t.Fatalf("fact calls: want 2, got %d", got)
	}
	if len(trace.SourceCalls) != 2 {
		t.Fatalf("reported source calls: %+v", trace.SourceCalls)
	}
}

func TestTraceFailsClosedWithoutAResolver(t *testing.T) {
	t.Parallel()
	set, p := loadOne(t, factDocuments)
	if _, err := engine.Trace(t.Context(), &set.Schema, p, readRequest("alice"), nil); err == nil {
		t.Fatal("a condition reaching a fact source was traced with no resolver configured")
	}
}
