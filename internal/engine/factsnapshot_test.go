package engine

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/d0lim/stamp/internal/policy"
)

// riskCondition reads one fact source, so an evaluation of it resolves exactly
// one call. It is a function rather than a value because normalization rewrites
// a condition tree in place.
func riskCondition() policy.Node {
	return policy.Compare{
		Left: policy.Source("risk", policy.Field(policy.RoleResource, "owner")), Op: policy.OpLt, Right: policy.Int(50),
	}
}

// A decide result carries the facts its own evaluation resolved. This is what
// lets a decision freeze the evidence it rested on instead of being handed a
// second set that resembles it.
func TestDecideResultCarriesResolvedFacts(t *testing.T) {
	ctx := context.Background()
	call := SourceCall{Name: "risk", Args: []any{"u1"}}

	for _, tc := range []struct {
		name   string
		policy policy.Policy
		want   Decision
	}{
		{"allow", ungated("p", riskCondition()), Allow},
		{"challenge", gated("p", riskCondition()), Challenge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &staticResolver{values: map[string]any{`risk(s:"u1")`: int64(10)}}
			snap := newTestSnapshot(t, tc.policy)
			res, err := NewDecideEvaluator(snap, WithSourceResolver(resolver)).Evaluate(ctx, baseInput())
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if res.Decision() != tc.want {
				t.Fatalf("decision = %s, want %s", res.Decision(), tc.want)
			}
			facts := res.Facts()
			if facts.Len() != 1 {
				t.Fatalf("snapshot holds %d facts, want 1", facts.Len())
			}
			v, ok := facts.Value(call)
			if !ok {
				t.Fatalf("snapshot has no value for %s; it holds %v", call, facts.Keys())
			}
			if v != int64(10) {
				t.Errorf("snapshot value = %v, want the resolved 10", v)
			}
			raw, err := json.Marshal(facts)
			if err != nil {
				t.Fatalf("marshal snapshot: %v", err)
			}
			if got, want := string(raw), `{"risk(s:\"u1\")":10}`; got != want {
				t.Errorf("marshalled snapshot = %s, want %s", got, want)
			}
		})
	}
}

// A condition that did not hold still produced evidence, and that evidence is
// what explains the deny. A no-matching-policy deny is the opposite case: it is
// returned before any fact is fetched, so its snapshot is empty rather than
// wrong.
func TestDecideSnapshotForDenies(t *testing.T) {
	ctx := context.Background()
	resolver := &staticResolver{values: map[string]any{`risk(s:"u1")`: int64(90)}}
	snap := newTestSnapshot(t, ungated("p", riskCondition()))
	res, err := NewDecideEvaluator(snap, WithSourceResolver(resolver)).Evaluate(ctx, baseInput())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.Reason() != ReasonConditionNotMet {
		t.Fatalf("reason = %s, want %s", res.Reason(), ReasonConditionNotMet)
	}
	if res.Facts().Len() != 1 {
		t.Errorf("a condition-not-met deny carries %d facts, want the one it read", res.Facts().Len())
	}

	empty := NewDecideEvaluator(newTestSnapshot(t)).Evaluate
	unmatched, err := empty(ctx, baseInput())
	if err != nil {
		t.Fatalf("evaluate against an empty set: %v", err)
	}
	if unmatched.Reason() != ReasonNoMatchingPolicy {
		t.Fatalf("reason = %s, want %s", unmatched.Reason(), ReasonNoMatchingPolicy)
	}
	if unmatched.Facts().Len() != 0 {
		t.Errorf("a no-matching-policy deny carries %d facts, want none", unmatched.Facts().Len())
	}
	raw, err := json.Marshal(unmatched.Facts())
	if err != nil {
		t.Fatalf("marshal empty snapshot: %v", err)
	}
	if string(raw) != "{}" {
		t.Errorf("empty snapshot marshalled to %s, want {}", raw)
	}
}

// The snapshot is a copy. A resolver that keeps hold of the table it returned
// must not be able to edit a decision's evidence after the decision was made —
// the approval binding hash is computed over this value, and evidence that can
// change afterwards is not evidence.
func TestFactSnapshotIsNotAliasedToTheResolversTable(t *testing.T) {
	ctx := context.Background()
	call := SourceCall{Name: "risk", Args: []any{"u1"}}

	var handed *Facts
	resolver := resolverFunc(func(_ context.Context, calls []SourceCall) (*Facts, error) {
		handed = NewFacts()
		for _, c := range calls {
			handed.Set(c, int64(10))
		}
		return handed, nil
	})
	snap := newTestSnapshot(t, ungated("p", riskCondition()))
	res, err := NewDecideEvaluator(snap, WithSourceResolver(resolver)).Evaluate(ctx, baseInput())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	handed.Set(call, int64(999))
	if v, _ := res.Facts().Value(call); v != int64(10) {
		t.Errorf("snapshot value = %v after the resolver edited its table, want the resolved 10", v)
	}
}

// The snapshot names the calls the evaluation asked for, not whatever the
// resolver felt like returning. A decision records the evidence its conditions
// could reach.
func TestFactSnapshotIgnoresUnrequestedValues(t *testing.T) {
	ctx := context.Background()
	resolver := resolverFunc(func(_ context.Context, calls []SourceCall) (*Facts, error) {
		facts := NewFacts()
		for _, c := range calls {
			facts.Set(c, int64(10))
		}
		facts.Set(SourceCall{Name: "risk", Args: []any{"someone-else"}}, int64(1))
		return facts, nil
	})
	snap := newTestSnapshot(t, ungated("p", riskCondition()))
	res, err := NewDecideEvaluator(snap, WithSourceResolver(resolver)).Evaluate(ctx, baseInput())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got := res.Facts().Keys(); len(got) != 1 || got[0] != `risk(s:"u1")` {
		t.Errorf("snapshot keys = %v, want only the call the condition made", got)
	}
}
