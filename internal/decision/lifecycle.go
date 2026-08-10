// Package decision owns the decision as a lifecycle object: creating it,
// issuing the challenges a policy demands, moving it between states, returning
// its obligations, and expiring it when its deadline passes.
//
// A decision is not a boolean. It has a state, a set of challenges with
// collection progress, a deadline and an obligation list, and it lives until
// one of those resolves it. Every mutation of that state goes through Next in
// this file — the service, the sweeper and, later, revalidation all call it —
// so the set of legal edges is written down once instead of being re-derived by
// each caller that happens to hold a decision.
//
// The legality of an edge is closed twice over. At compile time, because
// Transition's fields are unexported and it has no exported constructor: the
// only values of the type are the ones declared here, so no caller outside this
// package can invent an edge. At run time, because Next refuses the zero
// Transition, an unrecognized state, and every edge out of a terminal state.
// The compile-time half is what makes the run-time half short.
//
// Two deadline columns are load-bearing and this package respects the split
// the store draws. Every entry-time check — reading a decision, submitting to a
// challenge, applying a transition — asks whether expires_at has passed. Only
// the sweeper reads next_deadline, and only to decide which rows to wake up
// for. A challenge timer landing in next_deadline must never make a decision
// read as expired.
package decision

import (
	"errors"
	"fmt"

	"github.com/d0lim/stamp/internal/store"
)

// Errors the lifecycle returns as sentinels, so a caller can branch on the
// condition rather than on message text.
var (
	// ErrIllegalTransition reports an edge that is not in the transition
	// table: almost always a second attempt to resolve a decision that some
	// other path already resolved.
	ErrIllegalTransition = errors.New("decision: illegal state transition")

	// ErrUnknownTransition reports a Transition value that this package did not
	// declare — in practice the zero value, which is the only one a caller
	// outside the package can produce.
	ErrUnknownTransition = errors.New("decision: unknown transition")

	// ErrUnknownState reports a state that is not one of the five the store
	// admits. It is a fail-closed answer to a row that should not exist.
	ErrUnknownState = errors.New("decision: unknown decision state")
)

// Trigger names what caused a transition. It is recorded in the audit row, so
// an operator reading the log can tell an expiry apart from a rejection without
// inferring it from the resulting state — denied by a failed challenge and
// denied by revalidation land on the same state and are not the same event.
type Trigger string

// The triggers, one per edge in the transition table.
const (
	// TriggerChallengesSatisfied fires when the last outstanding challenge on a
	// decision is satisfied.
	TriggerChallengesSatisfied Trigger = "challenges_satisfied"

	// TriggerChallengeFailed fires when a challenge fails or times out: a
	// rejection, or a deadline the sweeper found unmet.
	TriggerChallengeFailed Trigger = "challenge_failed"

	// TriggerRevalidation fires when a policy revision re-evaluates a pending
	// decision and its condition no longer holds. U9 owns the re-evaluation;
	// the edge is declared here because the table is the single place edges are
	// declared.
	TriggerRevalidation Trigger = "revalidation"

	// TriggerExpiry fires when the decision's own deadline passes.
	TriggerExpiry Trigger = "expiry"

	// TriggerCancellation fires when a caller entitled to cancel does so during
	// a delay challenge.
	TriggerCancellation Trigger = "cancellation"
)

// Transition is one legal edge of the lifecycle.
//
// Its fields are unexported and it has no exported constructor, so the values
// declared in this file are the only ones that exist. A caller outside the
// package can hold a Transition and pass it to Next; it cannot build one that
// says something the table does not.
type Transition struct {
	trigger Trigger
	to      store.DecisionState
}

// Trigger reports what causes this transition.
func (t Transition) Trigger() Trigger { return t.trigger }

// To reports the state this transition moves a decision to.
func (t Transition) To() store.DecisionState { return t.to }

// String renders the transition for logs and error messages.
func (t Transition) String() string {
	if t.trigger == "" {
		return "decision.Transition(zero)"
	}
	return fmt.Sprintf("%s->%s", t.trigger, t.to)
}

// The transition table. Each value is an edge out of pending; there are no
// edges out of any other state, which is what "terminal" means here.
var (
	// Satisfy resolves a decision whose challenges are all satisfied.
	Satisfy = Transition{trigger: TriggerChallengesSatisfied, to: store.DecisionAllowed}

	// Fail resolves a decision whose challenge failed, was rejected, or ran out
	// of time.
	Fail = Transition{trigger: TriggerChallengeFailed, to: store.DecisionDenied}

	// Revalidate resolves a decision whose condition stopped holding under a
	// newly effective policy revision.
	Revalidate = Transition{trigger: TriggerRevalidation, to: store.DecisionDenied}

	// Expire resolves a decision whose own deadline passed.
	Expire = Transition{trigger: TriggerExpiry, to: store.DecisionExpired}

	// Cancel resolves a decision cancelled during a delay.
	Cancel = Transition{trigger: TriggerCancellation, to: store.DecisionCancelled}
)

// Transitions returns every declared edge. Tests enumerate the table through
// it, so an edge added without a table entry fails a test rather than shipping.
func Transitions() []Transition {
	return []Transition{Satisfy, Fail, Revalidate, Expire, Cancel}
}

// States returns every decision state, pending first.
func States() []store.DecisionState {
	return []store.DecisionState{
		store.DecisionPending,
		store.DecisionAllowed,
		store.DecisionDenied,
		store.DecisionExpired,
		store.DecisionCancelled,
	}
}

// Next reports the state a decision moves to, or refuses the move.
//
// This is the only function in the system that answers the question. A caller
// that wants to resolve a decision asks here first and writes the answer; a
// caller that skipped it would be writing a state the table never authorised.
//
// The refusal of an edge out of a terminal state is not defensive
// bookkeeping — it is how two sweepers racing the same expired decision end up
// resolving it once. The second one asks Next, is told the decision has already
// moved, and stops.
func Next(from store.DecisionState, t Transition) (store.DecisionState, error) {
	if !knownState(from) {
		return "", fmt.Errorf("%w: %q", ErrUnknownState, from)
	}
	if !knownTransition(t) {
		return "", fmt.Errorf("%w: %s", ErrUnknownTransition, t)
	}
	if from != store.DecisionPending {
		return "", fmt.Errorf("%w: %q is terminal, cannot apply %s", ErrIllegalTransition, from, t)
	}
	return t.to, nil
}

func knownState(s store.DecisionState) bool {
	for _, known := range States() {
		if s == known {
			return true
		}
	}
	return false
}

func knownTransition(t Transition) bool {
	for _, known := range Transitions() {
		if t == known {
			return true
		}
	}
	return false
}
