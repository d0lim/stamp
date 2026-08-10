package challenge_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// The delay tests are about one inversion and one authority.
//
// The inversion is that an elapsed timer means satisfied here and failed
// everywhere else, which is the reason the contract routes elapsed deadlines
// through Status instead of through a callback. Every test that reads a delay
// after its release instant asserts satisfied and asserts *not* failed, because
// the failure mode this unit has to rule out is the sweeper closing a wait as
// if it had run out of time.
//
// The authority is the cancel set, which is resolved by the same code the
// quorum resolves approvers with. The three modes are tested through the
// handler rather than through that shared function, because what matters is
// that a delay reaches it at all.

// delayContext is the frozen decision a delay hangs off. No database is
// involved: a delay writes nothing but its own detail.
func delayContext() challenge.DecisionContext {
	return challenge.DecisionContext{
		DecisionID:   "3f1b0f2a-0000-4000-8000-0000000000d1",
		CallerID:     "workload:https://idp.test#payments",
		SubjectID:    "alice",
		ResourceID:   "acct-1",
		Action:       "transfer",
		PolicyID:     "high-value-transfer",
		Request:      json.RawMessage(`{"action":"transfer"}`),
		FactSnapshot: json.RawMessage(`{}`),
		Obligations:  json.RawMessage(`[]`),
		CreatedAt:    testNow,
		ExpiresAt:    testNow.Add(time.Hour),
	}
}

func delayInstance() challenge.Instance {
	return challenge.Instance{DecisionID: delayContext().DecisionID, Ordinal: 0, Kind: policy.ChallengeDelay}
}

// issueDelay opens one delay and returns the detail as the store would hand it
// back: encoded, because that is what Submit and Status actually receive.
func issueDelay(t *testing.T, h *challenge.Delay, spec policy.Delay) (challenge.IssueResult, json.RawMessage) {
	t.Helper()
	issued, err := h.Issue(context.Background(), challenge.IssueRequest{
		Instance: delayInstance(),
		Spec:     spec,
		Decision: delayContext(),
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("issue delay: %v", err)
	}
	raw, err := json.Marshal(issued.Detail)
	if err != nil {
		t.Fatalf("encode delay detail: %v", err)
	}
	return issued, raw
}

func TestDelayIssueFreezesTheReleaseInstantAndSetsItsOwnTimer(t *testing.T) {
	t.Parallel()
	h := challenge.NewDelay(challenge.DelayConfig{})

	if h.Kind() != policy.ChallengeDelay {
		t.Fatalf("Kind() = %q, want %q", h.Kind(), policy.ChallengeDelay)
	}

	issued, raw := issueDelay(t, h, policy.Delay{Duration: 30 * time.Minute})
	if issued.State != challenge.StatePending {
		t.Fatalf("issued state = %q, want pending", issued.State)
	}
	if issued.Deadline == nil {
		t.Fatal("a delay must return its own timer, and returned none")
	}
	want := testNow.Add(30 * time.Minute)
	if !issued.Deadline.Equal(want) {
		t.Fatalf("deadline = %s, want %s", issued.Deadline, want)
	}

	var detail challenge.DelayDetail
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if !detail.ReleaseAt.Equal(want) {
		t.Fatalf("detail release_at = %s, want %s", detail.ReleaseAt, want)
	}
	if detail.Duration != "30m0s" {
		t.Fatalf("detail duration = %q, want %q", detail.Duration, "30m0s")
	}
	if detail.CancellableBy != nil {
		t.Fatalf("a delay with no cancel authority froze one: %+v", detail.CancellableBy)
	}
}

func TestDelayIssueRefusesADeclarationItCannotServe(t *testing.T) {
	t.Parallel()
	h := challenge.NewDelay(challenge.DelayConfig{})

	cases := map[string]policy.Challenge{
		"another kind":  policy.Quorum{Threshold: 1, Approvers: policy.ApproverSet{Members: []string{"bob"}}},
		"zero duration": policy.Delay{},
		"negative":      policy.Delay{Duration: -time.Minute},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := h.Issue(context.Background(), challenge.IssueRequest{
				Instance: delayInstance(),
				Spec:     spec,
				Decision: delayContext(),
				Now:      testNow,
			})
			if !errors.Is(err, challenge.ErrUnsupportedSpec) {
				t.Fatalf("err = %v, want ErrUnsupportedSpec", err)
			}
		})
	}
}

// TestDelayElapsedTimeReportsSatisfiedAndNeverFailed is the load-bearing test
// of this unit. The sweeper asks Status with the sweep instant and persists the
// answer, so this is the whole of "an elapsed delay satisfies its challenge".
func TestDelayElapsedTimeReportsSatisfiedAndNeverFailed(t *testing.T) {
	t.Parallel()
	h := challenge.NewDelay(challenge.DelayConfig{})
	issued, raw := issueDelay(t, h, policy.Delay{Duration: time.Hour})
	release := *issued.Deadline

	cases := []struct {
		name string
		now  time.Time
		want challenge.State
	}{
		{"one instant in", testNow.Add(time.Nanosecond), challenge.StatePending},
		{"a minute short", release.Add(-time.Minute), challenge.StatePending},
		{"exactly at release", release, challenge.StateSatisfied},
		{"a sweep late", release.Add(11 * time.Second), challenge.StateSatisfied},
		{"a day late", release.Add(24 * time.Hour), challenge.StateSatisfied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := h.Status(context.Background(), challenge.StatusRequest{
				Instance: delayInstance(),
				Decision: delayContext(),
				Detail:   raw,
				Stored:   challenge.StatePending,
				Deadline: &release,
				Now:      tc.now,
			})
			if err != nil {
				t.Fatalf("status: %v", err)
			}
			if got.State != tc.want {
				t.Fatalf("state at %s = %q, want %q", tc.now, got.State, tc.want)
			}
			if got.State == challenge.StateFailed {
				t.Fatal("an elapsed delay reported failed: a wait that finished is met, not timed out")
			}
			if got.Deadline == nil || !got.Deadline.Equal(release) {
				t.Fatalf("status deadline = %v, want %s", got.Deadline, release)
			}
		})
	}
}

func TestDelayStatusNeverWalksBackATerminalState(t *testing.T) {
	t.Parallel()
	h := challenge.NewDelay(challenge.DelayConfig{})
	issued, raw := issueDelay(t, h, policy.Delay{Duration: time.Hour})

	for _, stored := range []challenge.State{challenge.StateFailed, challenge.StateCancelled} {
		got, err := h.Status(context.Background(), challenge.StatusRequest{
			Instance: delayInstance(),
			Decision: delayContext(),
			Detail:   raw,
			Stored:   stored,
			Deadline: issued.Deadline,
			// Well past the release instant: time alone must not resurrect a
			// wait that was already closed.
			Now: issued.Deadline.Add(time.Hour),
		})
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if got.State != stored {
			t.Fatalf("stored %q became %q", stored, got.State)
		}
	}
}

func TestDelayWithoutACancelAuthorityTakesNoSubmissions(t *testing.T) {
	t.Parallel()
	h := challenge.NewDelay(challenge.DelayConfig{})
	_, raw := issueDelay(t, h, policy.Delay{Duration: time.Hour})
	idp := newMockIdP(t)

	_, err := h.Submit(context.Background(), challenge.SubmitRequest{
		Instance:  delayInstance(),
		Decision:  delayContext(),
		Detail:    raw,
		Submitter: idp.user(t, "carol", nil),
		Payload:   challenge.DelayCancelPayload(),
		Now:       testNow.Add(time.Minute),
	})
	if !errors.Is(err, challenge.ErrNotSubmittable) {
		t.Fatalf("err = %v, want ErrNotSubmittable", err)
	}
}

// TestDelayCancellationResolvesInEveryMode walks R18's three resolutions. The
// authorised identity cancels and the challenge fails, which is what the
// lifecycle turns into a denied decision; everybody else is refused with
// ErrNotTarget, which is what the lifecycle audits.
func TestDelayCancellationResolvesInEveryMode(t *testing.T) {
	t.Parallel()
	idp := newMockIdP(t)

	cases := []struct {
		name       string
		set        policy.ApproverSet
		groups     challenge.GroupResolver
		authorised *identity.Subject
		refused    *identity.Subject
		wantMode   challenge.ResolutionMode
	}{
		{
			name:       "members",
			set:        policy.ApproverSet{Members: []string{"carol", "dave"}},
			authorised: idp.user(t, "carol", nil),
			refused:    idp.user(t, "mallory", nil),
			wantMode:   challenge.ResolveMembers,
		},
		{
			name:       "claim",
			set:        policy.ApproverSet{Claim: "duty_officer"},
			authorised: idp.user(t, "erin", map[string]any{"duty_officer": true}),
			refused:    idp.user(t, "mallory", map[string]any{"duty_officer": false}),
			wantMode:   challenge.ResolveClaim,
		},
		{
			name:       "source",
			set:        policy.ApproverSet{Source: &policy.SourceRef{Name: "oncall"}},
			groups:     stubGroups{members: []string{"frank"}},
			authorised: idp.user(t, "frank", nil),
			refused:    idp.user(t, "mallory", nil),
			wantMode:   challenge.ResolveGroupSource,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := challenge.NewDelay(challenge.DelayConfig{Groups: tc.groups})
			set := tc.set
			_, raw := issueDelay(t, h, policy.Delay{Duration: time.Hour, CancellableBy: &set})

			var detail challenge.DelayDetail
			if err := json.Unmarshal(raw, &detail); err != nil {
				t.Fatalf("decode detail: %v", err)
			}
			if detail.CancellableBy == nil || detail.CancellableBy.Mode != tc.wantMode {
				t.Fatalf("frozen authority = %+v, want mode %q", detail.CancellableBy, tc.wantMode)
			}

			cancel := func(who *identity.Subject) (challenge.SubmitResult, error) {
				return h.Submit(context.Background(), challenge.SubmitRequest{
					Instance:  delayInstance(),
					Decision:  delayContext(),
					Detail:    raw,
					Submitter: who,
					Payload:   challenge.DelayCancelPayload(),
					Now:       testNow.Add(time.Minute),
				})
			}

			out, err := cancel(tc.authorised)
			if err != nil {
				t.Fatalf("authorised cancel: %v", err)
			}
			if out.State != challenge.StateFailed {
				t.Fatalf("cancelled delay is %q, want failed so the decision denies", out.State)
			}
			cancelled, ok := out.Detail.(challenge.DelayDetail)
			if !ok {
				t.Fatalf("cancel returned detail of type %T", out.Detail)
			}
			if cancelled.CancelledBy != tc.authorised.CallerID() {
				t.Fatalf("cancelled_by = %q, want %q", cancelled.CancelledBy, tc.authorised.CallerID())
			}
			if cancelled.CancelledAt == nil {
				t.Fatal("a cancellation recorded no instant")
			}

			// A cancelled delay stays cancelled even once its timer runs out:
			// the recorded cancellation is read back before the clock is.
			raw2, err := json.Marshal(cancelled)
			if err != nil {
				t.Fatalf("encode cancelled detail: %v", err)
			}
			after, err := h.Status(context.Background(), challenge.StatusRequest{
				Instance: delayInstance(),
				Decision: delayContext(),
				Detail:   raw2,
				Stored:   challenge.StatePending,
				Now:      testNow.Add(2 * time.Hour),
			})
			if err != nil {
				t.Fatalf("status after cancel: %v", err)
			}
			if after.State != challenge.StateFailed {
				t.Fatalf("a cancelled delay read back as %q once its timer elapsed", after.State)
			}

			if _, err := cancel(tc.refused); !errors.Is(err, challenge.ErrNotTarget) {
				t.Fatalf("outsider cancel err = %v, want ErrNotTarget", err)
			}
		})
	}
}

// TestDelayRefusesCancellationsFromCredentialsThatCannotHoldAuthority states
// D21's rule in the code path: a workload credential and an absent credential
// are refused by the handler, not only by the route it happens to be mounted
// on.
func TestDelayRefusesCancellationsFromCredentialsThatCannotHoldAuthority(t *testing.T) {
	t.Parallel()
	idp := newMockIdP(t)
	h := challenge.NewDelay(challenge.DelayConfig{})
	set := policy.ApproverSet{Members: []string{"carol"}}
	_, raw := issueDelay(t, h, policy.Delay{Duration: time.Hour, CancellableBy: &set})

	for name, who := range map[string]*identity.Subject{
		"a workload":       idp.workload(t, "pep-1"),
		"nobody at all":    nil,
		"a different user": idp.user(t, "mallory", nil),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := h.Submit(context.Background(), challenge.SubmitRequest{
				Instance:  delayInstance(),
				Decision:  delayContext(),
				Detail:    raw,
				Submitter: who,
				Payload:   challenge.DelayCancelPayload(),
				Now:       testNow.Add(time.Minute),
			})
			if !errors.Is(err, challenge.ErrNotTarget) {
				t.Fatalf("err = %v, want ErrNotTarget", err)
			}
		})
	}
}

// TestDelayRefusesAnythingButAnExplicitCancellation matters because the
// approval endpoint treats an empty body as consent. A body that says nothing
// must never cancel a wait, or the two surfaces would disagree about what
// silence means.
func TestDelayRefusesAnythingButAnExplicitCancellation(t *testing.T) {
	t.Parallel()
	idp := newMockIdP(t)
	h := challenge.NewDelay(challenge.DelayConfig{})
	set := policy.ApproverSet{Members: []string{"carol"}}
	_, raw := issueDelay(t, h, policy.Delay{Duration: time.Hour, CancellableBy: &set})

	for name, payload := range map[string]string{
		"an empty body":     "",
		"an empty object":   `{}`,
		"an approval":       `{"action":"approve"}`,
		"an unknown member": `{"action":"cancel","approver":"mallory"}`,
		"not an object":     `"cancel"`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var body json.RawMessage
			if payload != "" {
				body = json.RawMessage(payload)
			}
			_, err := h.Submit(context.Background(), challenge.SubmitRequest{
				Instance:  delayInstance(),
				Decision:  delayContext(),
				Detail:    raw,
				Submitter: idp.user(t, "carol", nil),
				Payload:   body,
				Now:       testNow.Add(time.Minute),
			})
			if !errors.Is(err, challenge.ErrInvalidPayload) {
				t.Fatalf("err = %v, want ErrInvalidPayload", err)
			}
		})
	}
}

// TestDelayIsTargetGrantsTheCancellerTheRead is R40: a decision may be read by
// the caller who created it or by somebody it is waiting on. A canceller who
// cannot see what they are cancelling cannot exercise the authority.
func TestDelayIsTargetGrantsTheCancellerTheRead(t *testing.T) {
	t.Parallel()
	idp := newMockIdP(t)
	h := challenge.NewDelay(challenge.DelayConfig{})

	set := policy.ApproverSet{Members: []string{"carol"}}
	_, cancellable := issueDelay(t, h, policy.Delay{Duration: time.Hour, CancellableBy: &set})
	_, plain := issueDelay(t, h, policy.Delay{Duration: time.Hour})

	isTarget := func(detail json.RawMessage, who *identity.Subject) bool {
		t.Helper()
		ok, err := h.IsTarget(context.Background(), challenge.TargetRequest{
			Instance: delayInstance(),
			Decision: delayContext(),
			Detail:   detail,
			Subject:  who,
		})
		if err != nil {
			t.Fatalf("is target: %v", err)
		}
		return ok
	}

	if !isTarget(cancellable, idp.user(t, "carol", nil)) {
		t.Fatal("the canceller is not a target of the delay they may cancel")
	}
	if isTarget(cancellable, idp.user(t, "mallory", nil)) {
		t.Fatal("an outsider is a target of a delay they may not cancel")
	}
	if isTarget(plain, idp.user(t, "carol", nil)) {
		t.Fatal("a delay nobody may cancel has a target")
	}
}

func TestDelayGroupAuthorityWithoutAResolverIsRefusedAtIssue(t *testing.T) {
	t.Parallel()
	h := challenge.NewDelay(challenge.DelayConfig{})
	set := policy.ApproverSet{Source: &policy.SourceRef{Name: "oncall"}}

	_, err := h.Issue(context.Background(), challenge.IssueRequest{
		Instance: delayInstance(),
		Spec:     policy.Delay{Duration: time.Hour, CancellableBy: &set},
		Decision: delayContext(),
		Now:      testNow,
	})
	if !errors.Is(err, challenge.ErrGroupSourceUnsupported) {
		t.Fatalf("err = %v, want ErrGroupSourceUnsupported", err)
	}
	if !errors.Is(err, challenge.ErrUnsupportedSpec) {
		t.Fatalf("err = %v, want it to also be ErrUnsupportedSpec", err)
	}
}

// TestDelayTimerDoesNotBringForwardTheDecisionsExpiry is the scheduler-column
// property from this unit's side. U4 proves the column split; this proves that
// a delay's timer, written through the same path a decision creation writes it,
// lands in next_deadline as a challenge deadline and leaves expires_at alone.
func TestDelayTimerDoesNotBringForwardTheDecisionsExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openStore(t, func() time.Time { return testNow })
	w := claimWriter(t, s, "delay-1")
	policyVersion := seedPolicy(t, s, "delayed-transfer")

	h := challenge.NewDelay(challenge.DelayConfig{})
	issued, _ := issueDelay(t, h, policy.Delay{Duration: 5 * time.Minute})

	id, err := store.NewDecisionID()
	if err != nil {
		t.Fatalf("new decision id: %v", err)
	}
	expiresAt := testNow.Add(time.Hour)
	created, err := w.CreateDecision(ctx, store.NewDecision{
		ID:            id,
		CallerID:      "workload:https://idp.test#payments",
		PolicyID:      "delayed-transfer",
		PolicyVersion: policyVersion,
		SubjectID:     "alice",
		ResourceID:    "acct-1",
		Action:        "transfer",
		Request:       json.RawMessage(`{"action":"transfer"}`),
		FactSnapshot:  json.RawMessage(`{}`),
		Obligations:   json.RawMessage(`[]`),
		ExpiresAt:     expiresAt,
		Challenges: []store.NewChallenge{{
			Ordinal:  0,
			Kind:     policy.ChallengeDelay,
			Deadline: issued.Deadline,
			Detail:   issued.Detail,
		}},
	})
	if err != nil {
		t.Fatalf("create decision: %v", err)
	}

	if created.NextDeadlineKind != store.DeadlineChallenge {
		t.Fatalf("next_deadline_kind = %q, want %q", created.NextDeadlineKind, store.DeadlineChallenge)
	}
	if created.NextDeadline == nil || !created.NextDeadline.Equal(*issued.Deadline) {
		t.Fatalf("next_deadline = %v, want the delay timer %s", created.NextDeadline, issued.Deadline)
	}
	if !created.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("expires_at = %s, want %s: a delay timer must not move the decision's expiry",
			created.ExpiresAt, expiresAt)
	}

	// Ten minutes in the delay has elapsed and the decision has not. The entry
	// check reads expires_at only, so the decision is still active and the
	// delay is satisfied — a single clock reading, two different answers.
	after := testNow.Add(10 * time.Minute)
	if created.Expired(after) {
		t.Fatal("a decision with an elapsed delay timer read as expired")
	}
	if _, err := store.ActiveDecisionTx(ctx, s.Pool(), id, after); err != nil {
		t.Fatalf("active decision ten minutes in: %v", err)
	}

	progress, err := store.ChallengeProgressFor(ctx, s.Pool(), id)
	if err != nil {
		t.Fatalf("read challenge progress: %v", err)
	}
	got, err := h.Status(ctx, challenge.StatusRequest{
		Instance: challenge.Instance{DecisionID: id, Ordinal: 0, Kind: policy.ChallengeDelay},
		Detail:   progress[0].Detail,
		Stored:   challenge.StatePending,
		Deadline: progress[0].Deadline,
		Now:      after,
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if got.State != challenge.StateSatisfied {
		t.Fatalf("state ten minutes into a five minute delay = %q, want satisfied", got.State)
	}
}

// stubGroups stands in for U13's IdP group source. It is the seam, not the
// implementation: what is tested here is that a delay reaches it.
type stubGroups struct {
	members []string
	err     error
}

func (g stubGroups) ResolveApprovers(_ context.Context, _ policy.SourceRef, _ challenge.DecisionContext) ([]string, error) {
	return g.members, g.err
}
