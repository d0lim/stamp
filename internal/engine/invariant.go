package engine

import (
	"encoding/json"
	"sort"

	"github.com/d0lim/stamp/internal/policy"
)

// Decision is the outcome of an evaluation.
type Decision uint8

// The decisions. Deny is the zero value deliberately: a result that no code path
// filled in denies, so forgetting to set one is a closed failure rather than an
// open one.
const (
	Deny Decision = iota
	Allow
	Challenge
)

// String renders a decision as the token the API surfaces use.
func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Challenge:
		return "challenge"
	default:
		return "deny"
	}
}

// Reason is the machine-readable ground for a decision. Reasons are stable: an
// API surface maps them to its own wording and an operator alerts on them, so
// neither is parsing English.
type Reason string

// The reasons an evaluation can give.
const (
	// ReasonNoMatchingPolicy is the fixed ground for a request that no policy
	// applies to. It is not configurable.
	ReasonNoMatchingPolicy Reason = "no_matching_policy"
	// ReasonRequiresDecision is the ground the check path gives for a policy
	// that carries challenges.
	ReasonRequiresDecision Reason = "requires_decision"
	// ReasonConditionNotMet is the ground for a request that matched policies
	// but satisfied none of their conditions.
	ReasonConditionNotMet Reason = "condition_not_met"
	// ReasonPolicyMatched is the ground for an allow.
	ReasonPolicyMatched Reason = "policy_matched"
	// ReasonChallengeRequired is the ground the decision path gives when
	// challenges have to be issued.
	ReasonChallengeRequired Reason = "challenge_required"
)

// Candidate is a policy that has been sorted by whether the stateless check
// path is allowed to satisfy it.
//
// The interface is closed — the unexported method admits only the two
// implementations below — and Classify is the only way to obtain either. That
// closure is what carries the first evaluator invariant: producing an allow on
// the check path requires a Checkable, a challenge-bearing policy classifies as
// Gated, and no conversion exists between them. The invariant is therefore a
// property of which types exist rather than of whether some branch remembered
// to test RequiresDecision.
type Candidate interface {
	// Policy returns the classified policy.
	Policy() *policy.Policy
	candidate()
}

// Checkable is a policy that carries no challenge, and so is the only kind of
// policy the stateless check path may allow.
//
// The field is unexported and Classify is the only constructor, so a value of
// this type is evidence that RequiresDecision was false at classification time.
type Checkable struct{ p *policy.Policy }

// Policy returns the classified policy.
func (c Checkable) Policy() *policy.Policy { return c.p }

func (Checkable) candidate() {}

// Gated is a policy that carries at least one challenge. It can only be
// resolved by the decision path, which issues its challenges and waits.
type Gated struct{ p *policy.Policy }

// Policy returns the classified policy.
func (g Gated) Policy() *policy.Policy { return g.p }

// Challenges returns the challenges the policy attaches.
func (g Gated) Challenges() []policy.Challenge {
	if g.p == nil {
		return nil
	}
	return g.p.Challenges
}

func (Gated) candidate() {}

// Classify sorts a policy into the two candidate types.
//
// It is total: every policy is one or the other, so there is no error to ignore
// and no third state to forget. RequiresDecision is asked here and nowhere else,
// which keeps the evaluator from re-deriving what "has challenges" means. A nil
// policy classifies as Gated, so even a programming error fails closed.
func Classify(p *policy.Policy) Candidate {
	if p == nil || p.RequiresDecision() {
		return Gated{p: p}
	}
	return Checkable{p: p}
}

// CheckResult is the outcome of the stateless check path.
//
// Its fields are unexported and it has no exported constructor, so no caller can
// assemble an allowing result of its own. Inside the package the only function
// that produces one is allowCheck, whose argument type is the load-bearing part
// of the signature.
type CheckResult struct {
	decision Decision
	reason   Reason
	policyID string
}

// Decision reports the outcome.
func (r CheckResult) Decision() Decision { return r.decision }

// Allowed reports whether the outcome is an allow.
func (r CheckResult) Allowed() bool { return r.decision == Allow }

// Reason reports the ground for the outcome.
func (r CheckResult) Reason() Reason { return r.reason }

// PolicyID reports the policy the outcome is attributed to, empty when none is.
func (r CheckResult) PolicyID() string { return r.policyID }

// allowCheck is the only allowing CheckResult in the package, and it takes a
// Checkable rather than a policy. A Gated value cannot be passed here and cannot
// be converted into one, so "a policy carrying challenges is allowed on the
// check path" is not an expressible program.
func allowCheck(c Checkable) CheckResult {
	return CheckResult{decision: Allow, reason: ReasonPolicyMatched, policyID: c.p.ID}
}

// checkRequiresDecision is the check path's answer to a Gated policy. It is the
// only thing the check path can do with one.
func checkRequiresDecision(g Gated) CheckResult {
	id := ""
	if g.p != nil {
		id = g.p.ID
	}
	return CheckResult{decision: Deny, reason: ReasonRequiresDecision, policyID: id}
}

// checkNoMatchingPolicy is the check path's answer to a request no policy
// matches. It takes no arguments on purpose: there is nothing — no policy, no
// option, no deployment setting — that could change what it returns.
func checkNoMatchingPolicy() CheckResult {
	return CheckResult{decision: Deny, reason: ReasonNoMatchingPolicy}
}

// checkConditionNotMet is the check path's answer when policies matched but no
// condition held.
func checkConditionNotMet() CheckResult {
	return CheckResult{decision: Deny, reason: ReasonConditionNotMet}
}

// FactSnapshot is the set of fact values one evaluation resolved, frozen.
//
// It exists because a decision has to record the facts it rested on, and
// "rested on" has to be provable rather than asserted. The evaluator resolves
// every reachable source in one batch before any condition runs, so that batch
// is exactly the evidence the outcome was computed from; this type carries it
// out to the caller instead of leaving the caller to assemble a second set that
// merely resembles it.
//
// It is immutable. The map is unexported, copied on construction, and has no
// setter, so a snapshot cannot be edited after the evaluation that produced it.
// That matters because the approval binding hash is computed over this value: a
// snapshot that could be edited afterwards would make the hash a claim rather
// than a commitment. The values themselves come from the fact plane and must be
// treated as read-only.
type FactSnapshot struct {
	values map[string]any
}

// newFactSnapshot freezes what one evaluation resolved.
//
// It is built from the calls the evaluation asked for rather than from the
// table the resolver handed back, for two reasons. The snapshot is then keyed
// by the call as written rather than by the table's internal cache key, so a
// reader can look a value up with the call that produced it. And a resolver
// that returns more than it was asked for contributes nothing extra: the
// evidence a decision records is the evidence its conditions could reach.
//
// It copies, so a resolver that kept a reference to the table it returned
// cannot change a decision's evidence after the fact.
func newFactSnapshot(calls []SourceCall, f *Facts) FactSnapshot {
	if len(calls) == 0 || f == nil {
		return FactSnapshot{}
	}
	values := make(map[string]any, len(calls))
	for _, call := range calls {
		if v, ok := f.Value(call); ok {
			values[snapshotKey(call)] = v
		}
	}
	if len(values) == 0 {
		return FactSnapshot{}
	}
	return FactSnapshot{values: values}
}

// snapshotKey is how a call is named inside a snapshot.
//
// It is the human-readable rendering rather than the internal cache key,
// because a snapshot is written into an audit row and read back by a person
// investigating a decision. Both foldings run the argument values through the
// same type-tagged canonical form, so nothing is given up by preferring the
// readable one.
func snapshotKey(call SourceCall) string { return call.String() }

// Len reports how many source calls the evaluation resolved.
func (s FactSnapshot) Len() int { return len(s.values) }

// Value returns the value a call resolved to during the evaluation.
func (s FactSnapshot) Value(call SourceCall) (any, bool) {
	if s.values == nil {
		return nil, false
	}
	v, ok := s.values[snapshotKey(call)]
	return v, ok
}

// Keys returns the resolved calls, sorted.
func (s FactSnapshot) Keys() []string {
	out := make([]string, 0, len(s.values))
	for k := range s.values {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// MarshalJSON renders the snapshot as a JSON object keyed by call. An empty
// snapshot marshals to an empty object rather than to null: an evaluation that
// resolved no facts resolved no facts, which is a different statement from
// having no snapshot at all.
func (s FactSnapshot) MarshalJSON() ([]byte, error) {
	if s.values == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(s.values)
}

// DecideResult is the outcome of the stateful decision path.
type DecideResult struct {
	decision Decision
	reason   Reason
	policyID string
	gates    []Gated
	facts    FactSnapshot
}

// Decision reports the outcome.
func (r DecideResult) Decision() Decision { return r.decision }

// Allowed reports whether the outcome is an allow.
func (r DecideResult) Allowed() bool { return r.decision == Allow }

// Reason reports the ground for the outcome.
func (r DecideResult) Reason() Reason { return r.reason }

// PolicyID reports the policy the outcome is attributed to, empty when none is.
// When several gated policies apply it is the first of them in snapshot order.
func (r DecideResult) PolicyID() string { return r.policyID }

// Gates returns the gated policies whose challenges have to be satisfied, so a
// caller can attribute each challenge to the policy that demanded it.
func (r DecideResult) Gates() []Gated { return r.gates }

// Facts returns the fact snapshot this evaluation resolved.
//
// It is the value a decision freezes (R7). The caller does not supply it and
// has no way to substitute for it. A result produced before any fact was
// fetched — no policy matched — carries an empty snapshot, which is the honest
// answer rather than a missing one.
func (r DecideResult) Facts() FactSnapshot { return r.facts }

// Challenges returns every challenge that has to be satisfied, flattened across
// the gated policies.
func (r DecideResult) Challenges() []policy.Challenge {
	var out []policy.Challenge
	for _, g := range r.gates {
		out = append(out, g.Challenges()...)
	}
	return out
}

// allowDecide takes a Checkable for the same reason allowCheck does. The
// decision path may end in an allow, but only for a policy that demanded
// nothing; a policy that demanded something ends in Challenge instead.
func allowDecide(c Checkable, facts FactSnapshot) DecideResult {
	return DecideResult{decision: Allow, reason: ReasonPolicyMatched, policyID: c.p.ID, facts: facts}
}

// decideChallenge is the decision path's answer to one or more Gated policies.
func decideChallenge(gates []Gated, facts FactSnapshot) DecideResult {
	id := ""
	if len(gates) > 0 && gates[0].p != nil {
		id = gates[0].p.ID
	}
	return DecideResult{
		decision: Challenge,
		reason:   ReasonChallengeRequired,
		policyID: id,
		gates:    gates,
		facts:    facts,
	}
}

// decideNoMatchingPolicy is the decision path's answer to a request no policy
// matches. Like its check-path twin it takes no arguments.
func decideNoMatchingPolicy() DecideResult {
	return DecideResult{decision: Deny, reason: ReasonNoMatchingPolicy}
}

// decideConditionNotMet is the decision path's answer when policies matched but
// no condition held.
func decideConditionNotMet(facts FactSnapshot) DecideResult {
	return DecideResult{decision: Deny, reason: ReasonConditionNotMet, facts: facts}
}
