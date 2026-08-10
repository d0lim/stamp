package decision_test

import (
	"errors"
	"testing"

	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/store"
)

// The transition table is fixed here rather than derived from the
// implementation. Every state times every transition is enumerated below, so a
// new edge cannot be added to the lifecycle without this table being edited —
// which is the point: an illegal transition that nobody wrote down is the one
// that quietly resolves an expired decision to allowed.
//
// Only a pending decision moves. Every terminal state is terminal for every
// transition, including the transition that produced it.
func legalTransitions() map[store.DecisionState]map[decision.Trigger]store.DecisionState {
	return map[store.DecisionState]map[decision.Trigger]store.DecisionState{
		store.DecisionPending: {
			decision.TriggerChallengesSatisfied: store.DecisionAllowed,
			decision.TriggerChallengeFailed:     store.DecisionDenied,
			decision.TriggerRevalidation:        store.DecisionDenied,
			decision.TriggerExpiry:              store.DecisionExpired,
			decision.TriggerCancellation:        store.DecisionCancelled,
		},
		store.DecisionAllowed:   {},
		store.DecisionDenied:    {},
		store.DecisionExpired:   {},
		store.DecisionCancelled: {},
	}
}

func TestTransitionTableIsExhaustive(t *testing.T) {
	table := legalTransitions()

	states := decision.States()
	if len(states) != len(table) {
		t.Fatalf("decision.States() has %d states, the table has %d: the table must cover every state",
			len(states), len(table))
	}
	for _, from := range states {
		if _, ok := table[from]; !ok {
			t.Fatalf("state %q is not in the transition table", from)
		}
	}

	transitions := decision.Transitions()
	if len(transitions) == 0 {
		t.Fatal("decision.Transitions() is empty")
	}
	seen := map[decision.Trigger]bool{}
	for _, tr := range transitions {
		if seen[tr.Trigger()] {
			t.Errorf("trigger %q is declared by two transitions", tr.Trigger())
		}
		seen[tr.Trigger()] = true
	}
	for trigger := range table[store.DecisionPending] {
		if !seen[trigger] {
			t.Errorf("trigger %q is in the table but no transition declares it", trigger)
		}
	}
}

func TestEveryStateTimesEveryTransition(t *testing.T) {
	table := legalTransitions()

	for _, from := range decision.States() {
		for _, tr := range decision.Transitions() {
			want, legal := table[from][tr.Trigger()]

			got, err := decision.Next(from, tr)
			switch {
			case legal && err != nil:
				t.Errorf("Next(%q, %q) = error %v, want %q", from, tr.Trigger(), err, want)
			case legal && got != want:
				t.Errorf("Next(%q, %q) = %q, want %q", from, tr.Trigger(), got, want)
			case !legal && err == nil:
				t.Errorf("Next(%q, %q) = %q, want an illegal-transition error", from, tr.Trigger(), got)
			case !legal && !errors.Is(err, decision.ErrIllegalTransition):
				t.Errorf("Next(%q, %q) = error %v, want ErrIllegalTransition", from, tr.Trigger(), err)
			case !legal && got != "":
				t.Errorf("Next(%q, %q) returned state %q alongside its error, want the zero state",
					from, tr.Trigger(), got)
			}
		}
	}
}

// A terminal decision never moves again, so the transition that produced it is
// refused as loudly as any other. This is called out separately because it is
// the case a hand-written switch gets wrong: resolving an already-resolved
// decision reads like a harmless no-op right up until two sweepers do it.
func TestTerminalStatesAreTerminalForTheirOwnTransition(t *testing.T) {
	for _, tr := range decision.Transitions() {
		to, err := decision.Next(store.DecisionPending, tr)
		if err != nil {
			t.Fatalf("Next(pending, %q): %v", tr.Trigger(), err)
		}
		if _, err := decision.Next(to, tr); !errors.Is(err, decision.ErrIllegalTransition) {
			t.Errorf("Next(%q, %q) = %v, want ErrIllegalTransition", to, tr.Trigger(), err)
		}
	}
}

// The zero Transition is the one value a caller outside this package can
// construct, since Transition's fields are unexported and there is no exported
// constructor. It must be refused at runtime, or "compile-time closed" would be
// true only of callers who never declared a variable.
func TestZeroTransitionIsRefused(t *testing.T) {
	var zero decision.Transition
	if _, err := decision.Next(store.DecisionPending, zero); !errors.Is(err, decision.ErrUnknownTransition) {
		t.Errorf("Next(pending, zero) = %v, want ErrUnknownTransition", err)
	}
}

func TestUnknownStateIsRefused(t *testing.T) {
	if _, err := decision.Next(store.DecisionState("resolved"), decision.Expire); !errors.Is(err, decision.ErrUnknownState) {
		t.Errorf("Next(\"resolved\", expire) = %v, want ErrUnknownState", err)
	}
}

// Each exported transition names the target the table says it names. A
// transition whose declared target drifted from the table would still pass the
// pairwise test above, because that test reads the target from the transition.
func TestTransitionTargets(t *testing.T) {
	want := map[decision.Trigger]store.DecisionState{
		decision.TriggerChallengesSatisfied: store.DecisionAllowed,
		decision.TriggerChallengeFailed:     store.DecisionDenied,
		decision.TriggerRevalidation:        store.DecisionDenied,
		decision.TriggerExpiry:              store.DecisionExpired,
		decision.TriggerCancellation:        store.DecisionCancelled,
	}
	for _, tr := range decision.Transitions() {
		if got := tr.To(); got != want[tr.Trigger()] {
			t.Errorf("transition %q targets %q, want %q", tr.Trigger(), got, want[tr.Trigger()])
		}
	}
	for _, tr := range []decision.Transition{
		decision.Satisfy, decision.Fail, decision.Revalidate, decision.Expire, decision.Cancel,
	} {
		if tr.To() != want[tr.Trigger()] {
			t.Errorf("exported transition %q targets %q, want %q", tr.Trigger(), tr.To(), want[tr.Trigger()])
		}
	}
}
