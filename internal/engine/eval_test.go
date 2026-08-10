package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/policy"
)

// checkCondition evaluates a one-policy snapshot and reports the check result.
func checkCondition(t *testing.T, cond policy.Node, in Input, opts ...Option) (CheckResult, error) {
	t.Helper()
	snap := newTestSnapshot(t, ungated("p", cond))
	return NewCheckEvaluator(snap, opts...).Evaluate(context.Background(), in)
}

// TestNodeTypesEvaluate walks every node type the AST admits and every operator
// each one accepts, so that a change to the compile layer cannot quietly alter
// what one of them means.
func TestNodeTypesEvaluate(t *testing.T) {
	t.Parallel()

	subject := func(attr string, v any) Input {
		in := baseInput()
		in.Subject.Attributes[attr] = v
		return in
	}

	tests := []struct {
		name string
		cond policy.Node
		in   Input
		want bool
	}{
		{"no condition is always true", nil, baseInput(), true},

		{"compare eq int true", policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpEq, Right: policy.Int(3)}, baseInput(), true},
		{"compare eq int false", policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpEq, Right: policy.Int(4)}, baseInput(), false},
		{"compare ne int", policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpNe, Right: policy.Int(4)}, baseInput(), true},
		{"compare lt int", policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpLt, Right: policy.Int(4)}, baseInput(), true},
		{"compare le int at boundary", policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpLe, Right: policy.Int(3)}, baseInput(), true},
		{"compare gt int", policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpGt, Right: policy.Int(3)}, baseInput(), false},
		{"compare ge int at boundary", policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpGe, Right: policy.Int(3)}, baseInput(), true},

		{"compare bool", policy.Compare{Left: policy.Field(policy.RoleSubject, "admin"), Op: policy.OpEq, Right: policy.Bool(false)}, baseInput(), true},
		{"compare string", policy.Compare{Left: policy.Field(policy.RoleSubject, "dept"), Op: policy.OpEq, Right: policy.String("eng")}, baseInput(), true},
		{"compare double", policy.Compare{Left: policy.Field(policy.RoleSubject, "score"), Op: policy.OpGt, Right: policy.Double(1.0)}, baseInput(), true},
		{"compare timestamp", policy.Compare{
			Left: policy.Field(policy.RoleSubject, "joined"), Op: policy.OpLt,
			Right: policy.Timestamp(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)),
		}, baseInput(), true},
		{"compare duration", policy.Compare{
			Left: policy.Field(policy.RoleSubject, "tenure"), Op: policy.OpGe, Right: policy.Duration(24 * time.Hour),
		}, baseInput(), true},

		{"compare across two roles", policy.Compare{
			Left: policy.Field(policy.RoleResource, "owner"), Op: policy.OpEq, Right: policy.Field(policy.RoleSubject, "dept"),
		}, subject("dept", "u1"), true},

		{"member in literal list", policy.In(policy.Field(policy.RoleSubject, "dept"), policy.List(policy.TypeString, "eng", "ops")), baseInput(), true},
		{"member in literal list misses", policy.In(policy.Field(policy.RoleSubject, "dept"), policy.List(policy.TypeString, "ops")), baseInput(), false},
		{"member not in literal list", policy.NotIn(policy.Field(policy.RoleSubject, "dept"), policy.List(policy.TypeString, "ops")), baseInput(), true},
		{"member in field list", policy.In(policy.Field(policy.RoleResource, "owner"), policy.Field(policy.RoleSubject, "tags")), subject("tags", []string{"u1"}), true},
		{"member in empty literal list", policy.In(policy.Field(policy.RoleSubject, "dept"), policy.List(policy.TypeString)), baseInput(), false},

		{"logic all true", policy.All(
			policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpEq, Right: policy.Int(3)},
			policy.Compare{Left: policy.Field(policy.RoleSubject, "dept"), Op: policy.OpEq, Right: policy.String("eng")},
		), baseInput(), true},
		{"logic all with one false", policy.All(
			policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpEq, Right: policy.Int(3)},
			policy.Compare{Left: policy.Field(policy.RoleSubject, "dept"), Op: policy.OpEq, Right: policy.String("hr")},
		), baseInput(), false},
		{"logic any with one true", policy.Any(
			policy.Compare{Left: policy.Field(policy.RoleSubject, "dept"), Op: policy.OpEq, Right: policy.String("hr")},
			policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpEq, Right: policy.Int(3)},
		), baseInput(), true},
		{"logic any all false", policy.Any(
			policy.Compare{Left: policy.Field(policy.RoleSubject, "dept"), Op: policy.OpEq, Right: policy.String("hr")},
			policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpEq, Right: policy.Int(9)},
		), baseInput(), false},
		{"logic not", policy.Not(
			policy.Compare{Left: policy.Field(policy.RoleSubject, "dept"), Op: policy.OpEq, Right: policy.String("hr")},
		), baseInput(), true},
		{"logic nested", policy.All(
			policy.Any(
				policy.Compare{Left: policy.Field(policy.RoleSubject, "dept"), Op: policy.OpEq, Right: policy.String("hr")},
				policy.Not(policy.Compare{Left: policy.Field(policy.RoleSubject, "admin"), Op: policy.OpEq, Right: policy.Bool(true)}),
			),
			policy.Compare{Left: policy.Field(policy.RoleContext, "hour"), Op: policy.OpLt, Right: policy.Int(18)},
		), baseInput(), true},
		{"logic all folds many operands", policy.All(
			policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpGe, Right: policy.Int(0)},
			policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpGe, Right: policy.Int(1)},
			policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpGe, Right: policy.Int(2)},
			policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpGe, Right: policy.Int(3)},
			policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpLe, Right: policy.Int(3)},
		), baseInput(), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := checkCondition(t, tc.cond, tc.in)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if res.Allowed() != tc.want {
				t.Fatalf("allowed = %v (%s/%s), want %v", res.Allowed(), res.Decision(), res.Reason(), tc.want)
			}
			if !tc.want && res.Reason() != ReasonConditionNotMet {
				t.Fatalf("reason = %q, want %q", res.Reason(), ReasonConditionNotMet)
			}
		})
	}
}

// TestSourceNodesEvaluate covers the one call-shaped node: a declared fact
// source, in both the list and the scalar position.
func TestSourceNodesEvaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cond   policy.Node
		values map[string]any
		want   bool
	}{
		{
			name:   "source list contains the subject department",
			cond:   policy.In(policy.Field(policy.RoleSubject, "dept"), policy.Source("groups", policy.Field(policy.RoleSubject, "dept"))),
			values: map[string]any{`groups(s:"eng")`: []string{"eng", "ops"}},
			want:   true,
		},
		{
			name:   "source list does not contain it",
			cond:   policy.In(policy.Field(policy.RoleSubject, "dept"), policy.Source("groups", policy.Field(policy.RoleSubject, "dept"))),
			values: map[string]any{`groups(s:"eng")`: []string{"ops"}},
			want:   false,
		},
		{
			name:   "scalar source compares against a literal",
			cond:   policy.Compare{Left: policy.Source("risk", policy.Field(policy.RoleResource, "owner")), Op: policy.OpLt, Right: policy.Int(50)},
			values: map[string]any{`risk(s:"u1")`: int64(10)},
			want:   true,
		},
		{
			name:   "scalar source with a literal argument",
			cond:   policy.Compare{Left: policy.Source("risk", policy.String("fixed")), Op: policy.OpGe, Right: policy.Int(50)},
			values: map[string]any{`risk(s:"fixed")`: int64(90)},
			want:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &staticResolver{values: tc.values}
			res, err := checkCondition(t, tc.cond, baseInput(), WithSourceResolver(resolver))
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if res.Allowed() != tc.want {
				t.Fatalf("allowed = %v, want %v", res.Allowed(), tc.want)
			}
			if resolver.batches != 1 {
				t.Fatalf("resolver was called %d times, want exactly one batch", resolver.batches)
			}
		})
	}
}

// TestFactsAreResolvedInOneDeduplicatedBatch pins the contract the fact plane
// gets: every call the matched policies can reach, once, before evaluation.
func TestFactsAreResolvedInOneDeduplicatedBatch(t *testing.T) {
	t.Parallel()
	shared := policy.In(policy.Field(policy.RoleSubject, "dept"), policy.Source("groups", policy.Field(policy.RoleSubject, "dept")))
	snap := newTestSnapshot(t,
		ungated("p-a", shared),
		ungated("p-b", policy.All(shared, policy.Compare{
			Left: policy.Source("risk", policy.Field(policy.RoleResource, "owner")), Op: policy.OpLt, Right: policy.Int(50),
		})),
	)
	resolver := &staticResolver{values: map[string]any{
		`groups(s:"eng")`: []string{"eng"},
		`risk(s:"u1")`:    int64(1),
	}}
	res, err := NewCheckEvaluator(snap, WithSourceResolver(resolver)).Evaluate(context.Background(), baseInput())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !res.Allowed() {
		t.Fatalf("result = %s/%s, want allow", res.Decision(), res.Reason())
	}
	if resolver.batches != 1 {
		t.Fatalf("resolver saw %d batches, want 1", resolver.batches)
	}
	if resolver.calls != 2 {
		t.Fatalf("resolver saw %d calls, want 2 after deduplication", resolver.calls)
	}
}

// TestFactFailuresFailClosed covers the three ways fact resolution can come up
// short. None of them may be mistaken for a condition that did not hold.
func TestFactFailuresFailClosed(t *testing.T) {
	t.Parallel()
	// Built per subtest rather than shared: Normalize rewrites the tree in place.
	cond := func() policy.Node {
		return policy.In(policy.Field(policy.RoleSubject, "dept"), policy.Source("groups", policy.Field(policy.RoleSubject, "dept")))
	}

	t.Run("no resolver configured", func(t *testing.T) {
		t.Parallel()
		_, err := checkCondition(t, cond(), baseInput())
		if !errors.Is(err, ErrUnresolvedFact) {
			t.Fatalf("err = %v, want %v", err, ErrUnresolvedFact)
		}
	})

	t.Run("resolver omits the call", func(t *testing.T) {
		t.Parallel()
		_, err := checkCondition(t, cond(), baseInput(), WithSourceResolver(&staticResolver{}))
		if !errors.Is(err, ErrUnresolvedFact) {
			t.Fatalf("err = %v, want %v", err, ErrUnresolvedFact)
		}
		if !strings.Contains(err.Error(), `groups(s:"eng")`) {
			t.Fatalf("err = %v, want it to name the unresolved call", err)
		}
	})

	t.Run("resolver fails", func(t *testing.T) {
		t.Parallel()
		sentinel := errors.New("upstream unavailable")
		resolver := resolverFunc(func(context.Context, []SourceCall) (*Facts, error) { return nil, sentinel })
		_, err := checkCondition(t, cond(), baseInput(), WithSourceResolver(resolver))
		if !errors.Is(err, sentinel) {
			t.Fatalf("err = %v, want it to wrap %v", err, sentinel)
		}
	})

	t.Run("resolver returns the wrong type", func(t *testing.T) {
		t.Parallel()
		resolver := &staticResolver{values: map[string]any{`groups(s:"eng")`: 42}}
		_, err := checkCondition(t, cond(), baseInput(), WithSourceResolver(resolver))
		if err == nil {
			t.Fatal("a fact source that returned an int for a list<string> was accepted")
		}
	})
}

// TestUndeclaredInputAttributeIsADeterministicError is the input-hygiene
// scenario. cel-go ignores activation entries it does not know, so an attribute
// the schema never declared would otherwise pass through in silence.
func TestUndeclaredInputAttributeIsADeterministicError(t *testing.T) {
	t.Parallel()
	snap := newTestSnapshot(t, ungated("p", nil))
	eval := NewCheckEvaluator(snap)

	in := baseInput()
	in.Subject.Attributes["zebra"] = 1
	in.Subject.Attributes["apple"] = 2

	var messages []string
	for range 16 {
		_, err := eval.Evaluate(context.Background(), in)
		if err == nil {
			t.Fatal("an undeclared attribute was accepted")
		}
		if !errors.Is(err, ErrUndeclaredAttribute) {
			t.Fatalf("err = %v, want %v", err, ErrUndeclaredAttribute)
		}
		messages = append(messages, err.Error())
	}
	for i, m := range messages {
		if m != messages[0] {
			t.Fatalf("run %d reported %q, run 0 reported %q: the error is not deterministic", i, m, messages[0])
		}
	}
	if !strings.Contains(messages[0], "apple, zebra") {
		t.Fatalf("err = %q, want the undeclared names listed in sorted order", messages[0])
	}
}

// TestInputValueErrors covers the rest of the input contract: an entity type the
// schema does not declare, a value of the wrong Go type, and a declared
// attribute the request left out.
func TestInputValueErrors(t *testing.T) {
	t.Parallel()

	t.Run("undeclared entity type", func(t *testing.T) {
		t.Parallel()
		snap := newTestSnapshot(t, ungated("p", nil))
		in := baseInput()
		in.Subject.Type = "user"
		in.Subject.Attributes["dept"] = "eng"
		snap.schema.Entities = nil
		if _, err := NewCheckEvaluator(snap).Evaluate(context.Background(), in); err == nil {
			t.Fatal("an undeclared entity type was accepted")
		}
	})

	t.Run("wrong Go type for a declared attribute", func(t *testing.T) {
		t.Parallel()
		in := baseInput()
		in.Subject.Attributes["level"] = "three"
		_, err := checkCondition(t, nil, in)
		if err == nil || !strings.Contains(err.Error(), "subject.level") {
			t.Fatalf("err = %v, want it to name subject.level", err)
		}
	})

	t.Run("a float is not an int", func(t *testing.T) {
		t.Parallel()
		in := baseInput()
		in.Subject.Attributes["level"] = 3.0
		if _, err := checkCondition(t, nil, in); err == nil {
			t.Fatal("a float64 was accepted for an int attribute")
		}
	})

	t.Run("widened Go integers are accepted", func(t *testing.T) {
		t.Parallel()
		in := baseInput()
		in.Subject.Attributes["level"] = 3
		res, err := checkCondition(t, policy.Compare{
			Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpEq, Right: policy.Int(3),
		}, in)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if !res.Allowed() {
			t.Fatal("an int attribute value was not read as an int")
		}
	})

	t.Run("a missing attribute fails only the policies that read it", func(t *testing.T) {
		t.Parallel()
		in := baseInput()
		delete(in.Subject.Attributes, "level")

		if _, err := checkCondition(t, nil, in); err != nil {
			t.Fatalf("a policy that does not read the attribute failed: %v", err)
		}
		_, err := checkCondition(t, policy.Compare{
			Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpEq, Right: policy.Int(3),
		}, in)
		if err == nil || !strings.Contains(err.Error(), "subject.level") {
			t.Fatalf("err = %v, want it to name subject.level", err)
		}
	})
}

// TestDecidePathOutcomes covers what the decision path does that the check path
// cannot.
func TestDecidePathOutcomes(t *testing.T) {
	t.Parallel()

	t.Run("a gated policy yields its challenges", func(t *testing.T) {
		t.Parallel()
		snap := newTestSnapshot(t, gated("p-gated", nil,
			policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{"urn:acr:mfa"}},
			policy.Delay{Duration: time.Hour},
		))
		res, err := NewDecideEvaluator(snap).Evaluate(context.Background(), baseInput())
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if res.Decision() != Challenge || res.Reason() != ReasonChallengeRequired {
			t.Fatalf("result = %s/%s, want challenge/%s", res.Decision(), res.Reason(), ReasonChallengeRequired)
		}
		if res.Allowed() {
			t.Fatal("a challenge result reported itself as an allow")
		}
		if got := len(res.Challenges()); got != 2 {
			t.Fatalf("got %d challenges, want 2", got)
		}
		if got := len(res.Gates()); got != 1 || res.Gates()[0].Policy().ID != "p-gated" {
			t.Fatalf("gates = %+v, want the one gated policy", res.Gates())
		}
	})

	t.Run("challenges from every applicable gated policy", func(t *testing.T) {
		t.Parallel()
		snap := newTestSnapshot(t,
			gated("p-one", nil, policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{"urn:acr:mfa"}}),
			gated("p-two", nil, policy.Delay{Duration: time.Hour}),
			ungated("p-open", nil),
		)
		res, err := NewDecideEvaluator(snap).Evaluate(context.Background(), baseInput())
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if res.Decision() != Challenge {
			t.Fatalf("decision = %s, want challenge", res.Decision())
		}
		if got := len(res.Challenges()); got != 2 {
			t.Fatalf("got %d challenges, want both policies' challenges", got)
		}
	})

	t.Run("an ungated policy allows", func(t *testing.T) {
		t.Parallel()
		snap := newTestSnapshot(t, ungated("p-open", nil))
		res, err := NewDecideEvaluator(snap).Evaluate(context.Background(), baseInput())
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if !res.Allowed() || res.PolicyID() != "p-open" {
			t.Fatalf("result = %s/%s/%s, want allow by p-open", res.Decision(), res.Reason(), res.PolicyID())
		}
	})

	t.Run("no condition holds", func(t *testing.T) {
		t.Parallel()
		snap := newTestSnapshot(t, gated("p-gated", policy.Compare{
			Left: policy.Field(policy.RoleSubject, "dept"), Op: policy.OpEq, Right: policy.String("hr"),
		}))
		res, err := NewDecideEvaluator(snap).Evaluate(context.Background(), baseInput())
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if res.Decision() != Deny || res.Reason() != ReasonConditionNotMet {
			t.Fatalf("result = %s/%s, want deny/%s", res.Decision(), res.Reason(), ReasonConditionNotMet)
		}
	})
}

// TestClassify records the one place RequiresDecision is consulted.
func TestClassify(t *testing.T) {
	t.Parallel()
	open := ungated("p-open", nil)
	if _, ok := Classify(&open).(Checkable); !ok {
		t.Fatalf("a policy with no challenge classified as %T", Classify(&open))
	}
	locked := gated("p-gated", nil)
	if _, ok := Classify(&locked).(Gated); !ok {
		t.Fatalf("a policy with a challenge classified as %T", Classify(&locked))
	}
	if _, ok := Classify(nil).(Gated); !ok {
		t.Fatal("a nil policy did not classify as Gated")
	}
	if got := Classify(nil).(Gated).Challenges(); got != nil {
		t.Fatalf("a nil policy reported challenges %v", got)
	}
}

// TestSnapshotRequiresVersions guards the cache key: an empty version would let
// two revisions share one compiled program.
func TestSnapshotRequiresVersions(t *testing.T) {
	t.Parallel()
	set := newTestSet(t, ungated("p", nil))
	if _, err := NewSnapshot("", set.Schema, nil); err == nil {
		t.Fatal("an empty schema version was accepted")
	}
	_, err := NewSnapshot("schema@1", set.Schema, []PolicyVersion{{Policy: set.Policies[0]}})
	if err == nil {
		t.Fatal("an empty policy version was accepted")
	}
}

// TestSourceCallKeysDistinguishTypes guards the fact cache key against a string
// "1" and an int 1 collapsing into one entry.
func TestSourceCallKeysDistinguishTypes(t *testing.T) {
	t.Parallel()
	keys := map[string]string{}
	calls := []SourceCall{
		{Name: "s", Args: []any{"1"}},
		{Name: "s", Args: []any{int64(1)}},
		{Name: "s", Args: []any{1.0}},
		{Name: "s", Args: []any{true}},
		{Name: "s", Args: []any{[]any{"1"}}},
		{Name: "s", Args: []any{time.Unix(1, 0).UTC()}},
		{Name: "s", Args: []any{time.Second}},
		{Name: "s", Args: nil},
	}
	for _, c := range calls {
		if prev, dup := keys[c.key()]; dup {
			t.Fatalf("%s and %s share the key %q", c, prev, c.key())
		}
		keys[c.key()] = c.String()
	}
	if got := fmt.Sprint(SourceCall{Name: "groups", Args: []any{"eng"}}); got != `groups(s:"eng")` {
		t.Fatalf("String() = %q", got)
	}
}
