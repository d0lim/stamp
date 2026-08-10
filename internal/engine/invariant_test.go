package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/policy"
)

// factCombinations enumerates request attribute values. The condition under
// test reads every one of them, so the product covers both the case where a
// challenge-bearing policy applies and the case where it does not.
func factCombinations() []Input {
	depts := []string{"eng", "hr"}
	levels := []int64{0, 3, 9}
	admins := []bool{false, true}
	amounts := []int64{1, 10, 1000}
	owners := []string{"u1", "u2"}
	hours := []int64{1, 9, 23}

	var out []Input
	for _, dept := range depts {
		for _, level := range levels {
			for _, admin := range admins {
				for _, amount := range amounts {
					for _, owner := range owners {
						for _, hour := range hours {
							in := baseInput()
							in.Subject.Attributes["dept"] = dept
							in.Subject.Attributes["level"] = level
							in.Subject.Attributes["admin"] = admin
							in.Resource.Attributes["amount"] = amount
							in.Resource.Attributes["owner"] = owner
							in.Context.Attributes["hour"] = hour
							out = append(out, in)
						}
					}
				}
			}
		}
	}
	return out
}

// wideCondition reads every attribute the combinations vary, so that across the
// product it is sometimes true and sometimes false.
func wideCondition() policy.Node {
	return policy.Any(
		policy.Compare{Left: policy.Field(policy.RoleSubject, "admin"), Op: policy.OpEq, Right: policy.Bool(true)},
		policy.All(
			policy.Compare{Left: policy.Field(policy.RoleSubject, "dept"), Op: policy.OpEq, Right: policy.String("eng")},
			policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpGe, Right: policy.Int(3)},
			policy.Compare{Left: policy.Field(policy.RoleResource, "amount"), Op: policy.OpLt, Right: policy.Int(1000)},
			policy.Compare{Left: policy.Field(policy.RoleContext, "hour"), Op: policy.OpLe, Right: policy.Int(18)},
			policy.In(policy.Field(policy.RoleResource, "owner"), policy.List(policy.TypeString, "u1")),
		),
	)
}

// TestCheckNeverAllowsChallengeBearingPolicy is invariant one (R30). A policy
// that carries a challenge cannot be satisfied by the stateless check path, and
// no combination of request facts may produce an allow from one.
func TestCheckNeverAllowsChallengeBearingPolicy(t *testing.T) {
	t.Parallel()

	t.Run("only gated policies", func(t *testing.T) {
		t.Parallel()
		snap := newTestSnapshot(t,
			gated("p-gated-wide", wideCondition()),
			gated("p-gated-open", nil, policy.Quorum{Threshold: 2, Approvers: policy.ApproverSet{Members: []string{"a", "b"}}}),
		)
		eval := NewCheckEvaluator(snap)
		for i, in := range factCombinations() {
			res, err := eval.Evaluate(context.Background(), in)
			if err != nil {
				t.Fatalf("combination %d: %v", i, err)
			}
			if res.Allowed() {
				t.Fatalf("combination %d: check allowed a challenge-bearing policy: %+v (input %+v)", i, res, in.Subject.Attributes)
			}
			if res.Reason() != ReasonRequiresDecision {
				t.Fatalf("combination %d: reason = %q, want %q", i, res.Reason(), ReasonRequiresDecision)
			}
		}
	})

	t.Run("gated policy alongside an always-allowing one", func(t *testing.T) {
		t.Parallel()
		snap := newTestSnapshot(t,
			ungated("p-open", nil),
			gated("p-gated-wide", wideCondition()),
		)
		eval := NewCheckEvaluator(snap)
		gatedProgram := programFor(t, snap, "p-gated-wide")
		for i, in := range factCombinations() {
			binding, err := bind(&snap.schema, in)
			if err != nil {
				t.Fatalf("combination %d: bind: %v", i, err)
			}
			gatedApplies, err := gatedProgram.Evaluate(context.Background(), binding, nil)
			if err != nil {
				t.Fatalf("combination %d: %v", i, err)
			}
			res, err := eval.Evaluate(context.Background(), in)
			if err != nil {
				t.Fatalf("combination %d: %v", i, err)
			}
			if gatedApplies && res.Allowed() {
				t.Fatalf("combination %d: an applicable challenge-bearing policy was overridden by an allow: %+v", i, res)
			}
			if !gatedApplies && !res.Allowed() {
				t.Fatalf("combination %d: the ungated policy should have allowed: %+v", i, res)
			}
		}
	})

	t.Run("every challenge kind", func(t *testing.T) {
		t.Parallel()
		challenges := []policy.Challenge{
			policy.Quorum{Threshold: 2, Approvers: policy.ApproverSet{Members: []string{"a", "b"}}},
			policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{"urn:acr:mfa"}},
			policy.Delay{Duration: time.Hour},
			policy.External{Target: "ticketing"},
		}
		for _, ch := range challenges {
			t.Run(string(ch.ChallengeType()), func(t *testing.T) {
				snap := newTestSnapshot(t, gated("p-gated", nil, ch))
				res, err := NewCheckEvaluator(snap).Evaluate(context.Background(), baseInput())
				if err != nil {
					t.Fatalf("evaluate: %v", err)
				}
				if res.Allowed() {
					t.Fatalf("check allowed a policy carrying a %s challenge", ch.ChallengeType())
				}
			})
		}
	})
}

// programFor compiles one policy of a snapshot directly, so a test can ask
// whether its condition held independently of how the evaluator combined it.
func programFor(t *testing.T, snap *Snapshot, id string) *Program {
	t.Helper()
	for _, e := range snap.entries {
		if e.candidate.Policy().ID == id {
			prg, err := NewCache().Compile(e.version, &snap.schema, e.candidate.Policy())
			if err != nil {
				t.Fatalf("compile %q: %v", id, err)
			}
			return prg
		}
	}
	t.Fatalf("snapshot has no policy %q", id)
	return nil
}

// allOptionCombinations returns every option this package exposes, in every
// combination. Adding an Option means adding it here — the point of the test is
// that no configuration reaches the no-matching-policy outcome, and an option
// that is never applied cannot demonstrate that.
func allOptionCombinations() [][]Option {
	singles := []struct {
		name string
		opt  Option
	}{
		{"cache", WithCache(NewCache())},
		{"nil-cache", WithCache(nil)},
		{"resolver", WithSourceResolver(&staticResolver{})},
		{"nil-resolver", WithSourceResolver(nil)},
	}
	combos := [][]Option{nil}
	for i := range singles {
		combos = append(combos, []Option{singles[i].opt})
		for j := range singles {
			combos = append(combos, []Option{singles[i].opt, singles[j].opt})
		}
	}
	return combos
}

// TestNoMatchingPolicyDenies is invariant two (R53). A request no policy matches
// is denied on both paths, with a fixed reason, and no configuration flips it.
func TestNoMatchingPolicyDenies(t *testing.T) {
	t.Parallel()

	empty := func(t *testing.T) *Snapshot { return newTestSnapshot(t) }
	populated := func(t *testing.T) *Snapshot {
		return newTestSnapshot(t, ungated("p-open", nil), gated("p-gated", nil))
	}

	unmatched := []struct {
		name  string
		snap  func(*testing.T) *Snapshot
		input func() Input
	}{
		{"empty policy set", empty, baseInput},
		{"undeclared action", populated, func() Input {
			in := baseInput()
			in.Action = "write"
			return in
		}},
		{"other subject type", populated, func() Input {
			in := baseInput()
			in.Subject.Type = "doc"
			return in
		}},
		{"other resource type", populated, func() Input {
			in := baseInput()
			in.Resource.Type = "user"
			return in
		}},
		{"unbound context", populated, func() Input {
			in := baseInput()
			in.Context = Entity{}
			return in
		}},
	}

	for _, tc := range unmatched {
		t.Run(tc.name, func(t *testing.T) {
			for i, opts := range allOptionCombinations() {
				snap := tc.snap(t)
				in := tc.input()

				check, err := NewCheckEvaluator(snap, opts...).Evaluate(context.Background(), in)
				if err != nil {
					t.Fatalf("options %d: check: %v", i, err)
				}
				if check.Decision() != Deny || check.Reason() != ReasonNoMatchingPolicy {
					t.Fatalf("options %d: check = %s/%s, want deny/%s", i, check.Decision(), check.Reason(), ReasonNoMatchingPolicy)
				}

				decide, err := NewDecideEvaluator(snap, opts...).Evaluate(context.Background(), in)
				if err != nil {
					t.Fatalf("options %d: decide: %v", i, err)
				}
				if decide.Decision() != Deny || decide.Reason() != ReasonNoMatchingPolicy {
					t.Fatalf("options %d: decide = %s/%s, want deny/%s", i, decide.Decision(), decide.Reason(), ReasonNoMatchingPolicy)
				}
			}
		})
	}
}

// TestNoMatchingPolicyDeniesBeforeAnyFactCall pins the ordering the invariant
// depends on: nothing configurable — not a resolver, not an input error — runs
// before the no-matching-policy answer.
func TestNoMatchingPolicyDeniesBeforeAnyFactCall(t *testing.T) {
	t.Parallel()
	snap := newTestSnapshot(t, ungated("p-open", nil))
	resolver := resolverFunc(func(context.Context, []SourceCall) (*Facts, error) {
		return nil, fmt.Errorf("resolver must not be reached")
	})
	in := baseInput()
	in.Action = "write"
	in.Subject.Attributes["not_a_declared_attribute"] = 1

	res, err := NewCheckEvaluator(snap, WithSourceResolver(resolver)).Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res.Decision() != Deny || res.Reason() != ReasonNoMatchingPolicy {
		t.Fatalf("check = %s/%s, want deny/%s", res.Decision(), res.Reason(), ReasonNoMatchingPolicy)
	}
}

// TestZeroResultsDeny records that the zero value of both result types denies,
// so a result nobody filled in cannot be mistaken for an allow.
func TestZeroResultsDeny(t *testing.T) {
	t.Parallel()
	if (CheckResult{}).Allowed() {
		t.Fatal("the zero CheckResult allows")
	}
	if (DecideResult{}).Allowed() {
		t.Fatal("the zero DecideResult allows")
	}
	if Decision(0) != Deny {
		t.Fatal("the zero Decision is not Deny")
	}
}
