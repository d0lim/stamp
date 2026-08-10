package challenge_test

import (
	"context"
	"errors"
	"testing"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/policy"
)

type stub struct{ kind policy.ChallengeType }

func (s stub) Kind() policy.ChallengeType { return s.kind }

func (stub) Issue(context.Context, challenge.IssueRequest) (challenge.IssueResult, error) {
	return challenge.IssueResult{State: challenge.StatePending}, nil
}

func (stub) Submit(context.Context, challenge.SubmitRequest) (challenge.SubmitResult, error) {
	return challenge.SubmitResult{}, challenge.ErrNotSubmittable
}

func (stub) Status(context.Context, challenge.StatusRequest) (challenge.Status, error) {
	return challenge.Status{State: challenge.StatePending}, nil
}

func TestRegistryLookup(t *testing.T) {
	r, err := challenge.NewRegistry(stub{kind: policy.ChallengeQuorum}, stub{kind: policy.ChallengeDelay})
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	if _, err := r.Handler(policy.ChallengeQuorum); err != nil {
		t.Errorf("quorum lookup: %v", err)
	}
	if _, err := r.Handler(policy.ChallengeMFA); !errors.Is(err, challenge.ErrNoHandler) {
		t.Errorf("mfa lookup = %v, want ErrNoHandler", err)
	}
	if got := r.Kinds(); len(got) != 2 || got[0] != policy.ChallengeQuorum || got[1] != policy.ChallengeDelay {
		t.Errorf("kinds = %v, want [quorum delay] in declaration order", got)
	}
}

// A kind with no handler must fail closed. A nil registry is the wiring mistake
// that would otherwise turn every challenge into "nothing to satisfy".
func TestNilRegistryFailsClosed(t *testing.T) {
	var r *challenge.Registry
	if _, err := r.Handler(policy.ChallengeQuorum); !errors.Is(err, challenge.ErrNoHandler) {
		t.Errorf("lookup on a nil registry = %v, want ErrNoHandler", err)
	}
	if got := r.Kinds(); got != nil {
		t.Errorf("kinds on a nil registry = %v, want none", got)
	}
}

// A second handler for a kind is refused rather than accepted as a
// replacement: a silently overridden challenge handler is a control that
// stopped running.
func TestDuplicateAndInvalidRegistrations(t *testing.T) {
	if _, err := challenge.NewRegistry(
		stub{kind: policy.ChallengeQuorum}, stub{kind: policy.ChallengeQuorum},
	); !errors.Is(err, challenge.ErrDuplicateHandler) {
		t.Errorf("duplicate registration = %v, want ErrDuplicateHandler", err)
	}
	if _, err := challenge.NewRegistry(stub{kind: "carrier-pigeon"}); err == nil {
		t.Error("a handler for an undeclared kind was registered")
	}
	r := &challenge.Registry{}
	if err := r.Register(nil); err == nil {
		t.Error("a nil handler was registered")
	}
}

func TestStateClassification(t *testing.T) {
	cases := []struct {
		state    challenge.State
		valid    bool
		terminal bool
	}{
		{challenge.StatePending, true, false},
		{challenge.StateSatisfied, true, true},
		{challenge.StateFailed, true, true},
		{challenge.StateCancelled, true, true},
		{challenge.State(""), false, false},
		{challenge.State("approved"), false, false},
	}
	for _, tc := range cases {
		if got := tc.state.Valid(); got != tc.valid {
			t.Errorf("State(%q).Valid() = %v, want %v", tc.state, got, tc.valid)
		}
		if got := tc.state.Terminal(); got != tc.terminal {
			t.Errorf("State(%q).Terminal() = %v, want %v", tc.state, got, tc.terminal)
		}
	}
}

func TestInstanceString(t *testing.T) {
	in := challenge.Instance{DecisionID: "d-1", Ordinal: 2, Kind: policy.ChallengeQuorum}
	if got, want := in.String(), "d-1#2(quorum)"; got != want {
		t.Errorf("Instance.String() = %q, want %q", got, want)
	}
}
