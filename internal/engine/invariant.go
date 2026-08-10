package engine

import "github.com/d0lim/stamp/internal/policy"

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

// DecideResult is the outcome of the stateful decision path.
type DecideResult struct {
	decision Decision
	reason   Reason
	policyID string
	gates    []Gated
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
func allowDecide(c Checkable) DecideResult {
	return DecideResult{decision: Allow, reason: ReasonPolicyMatched, policyID: c.p.ID}
}

// decideChallenge is the decision path's answer to one or more Gated policies.
func decideChallenge(gates []Gated) DecideResult {
	id := ""
	if len(gates) > 0 && gates[0].p != nil {
		id = gates[0].p.ID
	}
	return DecideResult{decision: Challenge, reason: ReasonChallengeRequired, policyID: id, gates: gates}
}

// decideNoMatchingPolicy is the decision path's answer to a request no policy
// matches. Like its check-path twin it takes no arguments.
func decideNoMatchingPolicy() DecideResult {
	return DecideResult{decision: Deny, reason: ReasonNoMatchingPolicy}
}

// decideConditionNotMet is the decision path's answer when policies matched but
// no condition held.
func decideConditionNotMet() DecideResult {
	return DecideResult{decision: Deny, reason: ReasonConditionNotMet}
}
