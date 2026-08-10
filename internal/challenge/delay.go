package challenge

// delay.go implements R3's delay challenge: a wait that a designated authority
// may cut short by cancelling.
//
// Three things in here are load-bearing beyond "sleep for a while".
//
// An elapsed timer means satisfied. Every other challenge kind reads a passed
// deadline as a failure, and this one reads it as the requirement being met.
// That inversion is the reason U7's contract answers elapsed timers through
// [Delay.Status] rather than through a "your deadline fired" callback: a
// callback would have had to be told which of the two answers to give, and the
// only party that knows is the handler. So this file sets a deadline at issue
// and then answers for it, and the sweeper's job is only to ask at the right
// time.
//
// The delay writes nothing but its own detail. There is no delay table and no
// row per wait: the release instant is frozen in Detail at issue, the challenge
// row carries it again as the scheduler's timer, and Status is a pure function
// of the two plus the clock. A wait that needed a background job to end would
// be a second source of truth for when it ended.
//
// Cancellation authority is the approver set, resolved by the same code the
// quorum resolves approvers with. Reusing [isTarget] rather than restating the
// membership rule is deliberate — R18's three resolutions have one meaning, and
// two implementations of "is this identity in the set" is one more than a
// security control should have.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
)

// DelayActionCancel is the only action a delay accepts.
//
// It is spelled out in the submission body rather than implied by an empty one.
// The approval surface treats an empty body as consent, and a wait must not be
// cancellable by a request that says nothing — an accidental POST is a denied
// decision, and the difference between "I approve" and "I withdraw this" is too
// large to leave to a convention about blank bodies.
const DelayActionCancel = "cancel"

// CancelAuthority is a frozen approver set: who may cancel a wait, resolved at
// issue and recorded in the challenge's detail.
//
// It carries the same three resolutions [QuorumDetail] carries, without the
// threshold and without the binding hash. A cancellation is not an approval of
// anything — there is no material to review and no quorum to reach — so R31's
// hash has nothing to bind here.
type CancelAuthority struct {
	// Mode is which resolution produced the set.
	Mode ResolutionMode `json:"mode"`
	// Members is the resolved list, deduplicated and sorted, for the explicit
	// and group-resolved modes.
	Members []string `json:"members,omitempty"`
	// Claim is the claim a canceller's token must assert, for the claim mode.
	Claim string `json:"claim,omitempty"`
	// Source names the group source a resolved set came from, for the audit
	// trail; the resolved names are in Members.
	Source string `json:"source,omitempty"`
}

// admits answers whether an identity holds this authority.
//
// It defers to the quorum's membership rule by handing it the same shape,
// which is what keeps one meaning for each of R18's modes. Every fail-closed
// property that rule has — a workload credential is not a person, an unreadable
// claim is not an assertion, an absent credential is not a member — holds here
// without being restated.
func (a CancelAuthority) admits(s *identity.Subject) (bool, error) {
	return isTarget(QuorumDetail{
		Mode:    a.Mode,
		Members: a.Members,
		Claim:   a.Claim,
		Source:  a.Source,
	}, s)
}

// DelayDetail is what a delay challenge persists on its challenge row.
//
// ReleaseAt is the authority on when the wait ends, not the challenge row's
// deadline column. They are written from the same value, and freezing it here
// as well is what lets Status recompute the answer from what the handler
// persisted — which is the contract's requirement, and which also means a
// revision that rewrites the row's timer cannot silently move a wait that was
// already running.
type DelayDetail struct {
	// Duration is the declared wait, recorded for the audit trail and for a
	// console that wants to say "two hours" rather than a pair of instants.
	Duration string `json:"duration"`
	// ReleaseAt is the instant the wait is over and the challenge is met.
	ReleaseAt time.Time `json:"release_at"`
	// CancellableBy is the frozen cancellation authority, or nil for a wait
	// nobody may cancel.
	CancellableBy *CancelAuthority `json:"cancellable_by,omitempty"`
	// CancelledBy is the caller identifier of whoever cancelled, and
	// CancelledAt when. Both are empty until a cancellation is recorded.
	CancelledBy string     `json:"cancelled_by,omitempty"`
	CancelledAt *time.Time `json:"cancelled_at,omitempty"`
}

// DelaySubmission is the body of a cancellation.
type DelaySubmission struct {
	// Action is [DelayActionCancel]. There is no other action, and there is no
	// default: see the constant.
	Action string `json:"action"`
}

// DelayCancelPayload returns the submission body that cancels a delay.
//
// The console surface builds its submission from this rather than forwarding
// whatever the browser sent, so the endpoint's path is the whole of what the
// caller is asking for. A fresh slice each call: a package-level buffer handed
// out to callers is a buffer somebody eventually writes into.
func DelayCancelPayload() json.RawMessage {
	return json.RawMessage(`{"action":"` + DelayActionCancel + `"}`)
}

// DelayConfig configures a [Delay].
type DelayConfig struct {
	// Groups resolves an IdP-group cancellation authority. Nil in v1, exactly
	// as for the quorum: a policy that reaches for one is refused at issue
	// rather than opening a wait whose cancellation nobody could exercise.
	Groups GroupResolver
}

// Delay is the timed-wait handler.
type Delay struct {
	groups GroupResolver
}

// Compile-time proof that the handler serves the whole contract, including the
// optional read rule.
var (
	_ Handler  = (*Delay)(nil)
	_ Targeter = (*Delay)(nil)
)

// NewDelay builds the delay handler.
//
// It cannot fail: a delay owns no store, no client and no credential. What can
// fail is a declaration, and that is refused at [Delay.Issue] where the
// declaration is.
func NewDelay(cfg DelayConfig) *Delay { return &Delay{groups: cfg.Groups} }

// Kind implements [Handler].
func (d *Delay) Kind() policy.ChallengeType { return policy.ChallengeDelay }

// Issue freezes the release instant and the cancellation authority, and returns
// the wait as its own timer.
//
// The deadline it returns is the whole mechanism: it lands in the scheduler's
// next_deadline column as a challenge deadline, the sweeper claims the decision
// when it arrives, and the settle path asks Status what it meant. It is not the
// decision's expiry and must not be confused with it — the lifecycle extends a
// decision that would otherwise expire mid-wait, which is the only interaction
// between the two.
func (d *Delay) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	spec, ok := req.Spec.(policy.Delay)
	if !ok {
		return IssueResult{}, fmt.Errorf("%w: %T is not a delay", ErrUnsupportedSpec, req.Spec)
	}
	if spec.Duration <= 0 {
		return IssueResult{}, fmt.Errorf("%w: a delay of %s is not a wait", ErrUnsupportedSpec, spec.Duration)
	}

	release := req.Now.UTC().Add(spec.Duration)
	detail := DelayDetail{Duration: spec.Duration.String(), ReleaseAt: release}
	if spec.CancellableBy != nil {
		authority, err := d.resolveAuthority(ctx, *spec.CancellableBy, req.Decision)
		if err != nil {
			return IssueResult{}, err
		}
		detail.CancellableBy = &authority
	}
	return IssueResult{State: StatePending, Detail: detail, Deadline: &release}, nil
}

// resolveAuthority turns a declaration into the frozen cancellation set.
//
// It mirrors the quorum's resolution because R18 is one rule, and it resolves
// at issue for the same reason: the set a decision was opened under is part of
// the terms of that decision, and a group whose membership changes mid-wait
// must not silently change who could stop it.
func (d *Delay) resolveAuthority(ctx context.Context, set policy.ApproverSet, dec DecisionContext) (CancelAuthority, error) {
	switch {
	case set.Source != nil:
		if d.groups == nil {
			return CancelAuthority{}, fmt.Errorf("%w: %w: source %q",
				ErrUnsupportedSpec, ErrGroupSourceUnsupported, set.Source.Name)
		}
		members, err := d.groups.ResolveApprovers(ctx, *set.Source, dec)
		if err != nil {
			return CancelAuthority{}, fmt.Errorf("challenge: resolve cancellation group %q: %w", set.Source.Name, err)
		}
		return CancelAuthority{
			Mode:    ResolveGroupSource,
			Source:  set.Source.Name,
			Members: normalizeMembers(members),
		}, nil
	case set.Claim != "":
		return CancelAuthority{Mode: ResolveClaim, Claim: set.Claim}, nil
	default:
		members := normalizeMembers(set.Members)
		if len(members) == 0 {
			return CancelAuthority{}, fmt.Errorf(
				"%w: a cancellation authority resolves from members, a claim, or a source", ErrUnsupportedSpec)
		}
		return CancelAuthority{Mode: ResolveMembers, Members: members}, nil
	}
}

// Submit records a cancellation.
//
// A cancelled wait is failed rather than cancelled. [StateCancelled] means the
// challenge went down with its decision, and this is the opposite: the decision
// is still live and this challenge is the reason it will resolve to deny. Both
// states deny, so the choice costs nothing at runtime and keeps the stored
// state readable as what actually happened.
//
// Nothing here checks the clock. The lifecycle refuses a submission against a
// challenge whose own deadline has passed before a handler sees it, so a
// cancellation that arrives after the wait ended is already turned away — and
// checking again here would be a second deadline rule to keep in step with the
// first.
func (d *Delay) Submit(_ context.Context, req SubmitRequest) (SubmitResult, error) {
	detail, err := decodeDelayDetail(req.Detail)
	if err != nil {
		return SubmitResult{}, err
	}
	if detail.CancellableBy == nil {
		return SubmitResult{}, fmt.Errorf("%w: %s is a wait nobody may cancel", ErrNotSubmittable, req.Instance)
	}
	if _, err := decodeDelaySubmission(req.Payload); err != nil {
		return SubmitResult{}, err
	}

	// The canceller is the token's subject, on the same terms as an approver:
	// no identity is read out of the body, and a workload credential is not a
	// person who can hold this authority.
	canceller, err := approverID(req.Submitter)
	if err != nil {
		return SubmitResult{}, err
	}
	admitted, err := detail.CancellableBy.admits(req.Submitter)
	if err != nil {
		return SubmitResult{}, err
	}
	if !admitted {
		return SubmitResult{}, fmt.Errorf("%w: %q may not cancel %s", ErrNotTarget, canceller, req.Instance)
	}

	at := req.Now.UTC()
	detail.CancelledBy = req.Submitter.CallerID()
	detail.CancelledAt = &at
	return SubmitResult{State: StateFailed, Detail: detail}, nil
}

// Status answers where a wait stands as of req.Now, and is where the inversion
// lives: a release instant that has arrived is satisfied.
//
// The order of the two branches matters. A cancellation recorded during the
// wait wins over the wait finishing, because the sweeper may not run until
// after the release instant and a cancellation that evaporated because the
// cleanup job was late would be an authority that only sometimes holds.
//
// A stored terminal state is never walked back, for the reason it is never
// walked back anywhere: a challenge that went down with its decision does not
// come back because time passed.
func (d *Delay) Status(_ context.Context, req StatusRequest) (Status, error) {
	detail, err := decodeDelayDetail(req.Detail)
	if err != nil {
		return Status{}, err
	}
	release := detail.ReleaseAt
	state := req.Stored
	if !state.Terminal() {
		switch {
		case detail.CancelledAt != nil:
			state = StateFailed
		case !req.Now.Before(release):
			state = StateSatisfied
		default:
			state = StatePending
		}
	}
	return Status{State: state, Deadline: &release}, nil
}

// IsTarget implements [Targeter]: a decision may be read by whoever may stop
// it.
//
// Somebody holding a cancellation authority they cannot see the grounds for
// holds nothing they can exercise, so the read follows the authority. A wait
// nobody may cancel has no targets, and grants nobody a read.
func (d *Delay) IsTarget(_ context.Context, req TargetRequest) (bool, error) {
	detail, err := decodeDelayDetail(req.Detail)
	if err != nil {
		return false, err
	}
	if detail.CancellableBy == nil {
		return false, nil
	}
	return detail.CancellableBy.admits(req.Subject)
}

// ---------------------------------------------------------------------------
// decoding
// ---------------------------------------------------------------------------

func decodeDelayDetail(raw json.RawMessage) (DelayDetail, error) {
	var detail DelayDetail
	if err := json.Unmarshal(raw, &detail); err != nil {
		return DelayDetail{}, fmt.Errorf("%w: delay detail: %w", ErrInvalidPayload, err)
	}
	if detail.ReleaseAt.IsZero() {
		return DelayDetail{}, fmt.Errorf("%w: delay detail names no release instant", ErrInvalidPayload)
	}
	return detail, nil
}

// decodeDelaySubmission reads a cancellation body.
//
// Unknown members are refused, as they are for an approval: the member a client
// is most likely to invent is somebody else's identity, and an ignored one is a
// client that believes it can cancel on another person's behalf.
func decodeDelaySubmission(raw json.RawMessage) (DelaySubmission, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return DelaySubmission{}, fmt.Errorf("%w: a cancellation must say so: expected {\"action\":%q}",
			ErrInvalidPayload, DelayActionCancel)
	}
	var body DelaySubmission
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		return DelaySubmission{}, fmt.Errorf("%w: cancellation submission: %w", ErrInvalidPayload, err)
	}
	if strings.ToLower(strings.TrimSpace(body.Action)) != DelayActionCancel {
		return DelaySubmission{}, fmt.Errorf("%w: a delay takes the action %q, got %q",
			ErrInvalidPayload, DelayActionCancel, body.Action)
	}
	body.Action = DelayActionCancel
	return body, nil
}
