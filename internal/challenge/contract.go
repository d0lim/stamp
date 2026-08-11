// Package challenge defines the contract every challenge kind implements, and
// nothing else.
//
// A challenge is the part of a decision that cannot be answered by evaluating a
// policy: a quorum that has to be collected, a step-up the subject has to
// complete, a delay that has to elapse, an external system that has to answer.
// The decision lifecycle owns when those are opened and what their outcome does
// to the decision; this package owns the shape of the conversation between the
// two.
//
// # The contract is three verbs
//
// Issue opens a challenge and returns the detail to persist and the timer to
// wake up for. Submit takes evidence from a caller and reports the resulting
// progress. Status reports where a challenge stands as of a given instant.
// There is no fourth verb, and in particular there is no "the deadline fired,
// what now" verb: the sweeper asks Status with the current time and a delay
// answers satisfied while a quorum answers pending. Time-dependent challenges
// are exactly the ones a separate elapsed-callback would have gotten wrong,
// because a delay elapsing means the challenge is met and a quorum's deadline
// elapsing means it is not.
//
// # Handlers persist their own detail, not their specification
//
// Issue receives the policy's declaration and returns Detail, which the
// lifecycle stores on the challenge row and hands back verbatim to Submit and
// Status. A handler that needs its threshold or its approver set later puts
// them in Detail. That freezes the terms a challenge was opened under alongside
// the fact snapshot and the policy version, and it keeps this package free of
// any need to serialize the policy AST.
//
// # Submit must be recomputable
//
// The approval row a handler writes and the challenge state the lifecycle
// writes are two statements, not one. A handler must therefore treat Submit as
// idempotent — a duplicate submission counts once — and Status must be able to
// recompute progress from what the handler persisted, because a crash between
// the two statements leaves the evidence written and the state not yet updated.
//
// # Versioning
//
// This is a public contract under semantic versioning: U20 implements quorum
// against it and U10, U11 add mfa, delay and external later. Adding a method to
// Handler, changing a method's signature, or changing the meaning of a State is
// a major change. Adding a field to a request or result struct, or adding an
// optional interface like Targeter, is a minor one.
package challenge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
)

// ContractVersion is the semantic version of the interfaces in this file. It is
// bumped when the contract changes, not when a handler does.
const ContractVersion = "1.2.0"

// Errors handlers and the registry return as sentinels. A handler may wrap them
// with detail; callers branch with errors.Is.
var (
	// ErrNoHandler reports that no handler is registered for a challenge kind.
	// It is fail-closed: a decision whose challenge has no handler cannot be
	// satisfied, and must not be treated as satisfied by default.
	ErrNoHandler = errors.New("challenge: no handler for kind")

	// ErrDuplicateHandler reports two handlers registered for one kind.
	ErrDuplicateHandler = errors.New("challenge: kind already has a handler")

	// ErrNotSubmittable reports a Submit against a challenge that collects
	// nothing — a delay has no evidence to take.
	ErrNotSubmittable = errors.New("challenge: challenge takes no submissions")

	// ErrNotTarget reports a submission from an identity the challenge does not
	// accept: an approver outside the resolved set, a step-up completed by
	// somebody other than the subject.
	ErrNotTarget = errors.New("challenge: submitter is not a target of this challenge")

	// ErrInvalidPayload reports a submission the handler could not read.
	ErrInvalidPayload = errors.New("challenge: invalid submission payload")

	// ErrUnsupportedSpec reports a declaration a handler cannot serve — the
	// direct MFA mode in v1, for instance.
	ErrUnsupportedSpec = errors.New("challenge: unsupported challenge specification")

	// ErrNotRedeemable reports a Redeem against a challenge kind that has no
	// transport of its own to redeem — a quorum is answered by people posting to
	// the approval endpoint, not by a redirect coming back.
	ErrNotRedeemable = errors.New("challenge: challenge has no redirect to redeem")

	// ErrRedemptionRefused reports a callback the challenge would not redeem: a
	// `state` that is not the one it minted, an authorization code the IdP would
	// not exchange, a challenge whose completion is already spent. It is
	// deliberately one sentinel for the whole family — see [Redeemer].
	ErrRedemptionRefused = errors.New("challenge: the callback was not redeemed")
)

// State is one challenge's progress state.
//
// The four values correspond exactly to the states the store persists. They are
// declared here rather than imported so that the contract a handler implements
// does not drag in the persistence layer; the lifecycle translates.
type State string

// The challenge progress states.
const (
	// StatePending means the challenge is open and unmet.
	StatePending State = "pending"
	// StateSatisfied means the challenge's requirement is met.
	StateSatisfied State = "satisfied"
	// StateFailed means the challenge can no longer be met: rejected, timed
	// out, or refused by the system it delegates to.
	StateFailed State = "failed"
	// StateCancelled means the challenge was withdrawn along with its decision.
	StateCancelled State = "cancelled"
)

// Valid reports whether s is one of the declared states.
func (s State) Valid() bool {
	switch s {
	case StatePending, StateSatisfied, StateFailed, StateCancelled:
		return true
	default:
		return false
	}
}

// Terminal reports whether the challenge can still change on its own.
func (s State) Terminal() bool { return s.Valid() && s != StatePending }

// Instance identifies one challenge on one decision.
//
// Ordinal is the challenge's position in the decision's flattened challenge
// list and is the key the store rows are written under, so it is stable for the
// life of the decision.
type Instance struct {
	DecisionID string
	Ordinal    int
	Kind       policy.ChallengeType
}

// String renders the instance for logs and error messages.
func (i Instance) String() string {
	return fmt.Sprintf("%s#%d(%s)", i.DecisionID, i.Ordinal, i.Kind)
}

// DecisionContext is the frozen content of the decision a challenge is attached
// to.
//
// It is what an approval screen renders and what a binding hash is computed
// over, so the fields are the stored ones — the request and the fact snapshot
// as they were frozen at creation, not as they read now. Handlers must not
// re-fetch any of it.
type DecisionContext struct {
	DecisionID   string
	CallerID     string
	SubjectID    string
	ResourceID   string
	Action       string
	PolicyID     string
	Request      json.RawMessage
	FactSnapshot json.RawMessage
	Obligations  json.RawMessage
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// IssueRequest opens one challenge.
type IssueRequest struct {
	// Instance names the challenge being opened.
	Instance Instance
	// Spec is the policy's declaration of this challenge.
	Spec policy.Challenge
	// Decision is the decision the challenge hangs off.
	Decision DecisionContext
	// Now is the issuing instant, supplied rather than read so that behaviour
	// is testable without sleeping.
	Now time.Time
}

// IssueResult is what opening a challenge produced.
type IssueResult struct {
	// State is the challenge's state immediately after issue. It is normally
	// StatePending; a handler may return StateSatisfied for a requirement that
	// is already met, and StateFailed for one that can never be met.
	State State
	// Detail is persisted on the challenge row and handed back verbatim to
	// Submit and Status. It must be JSON-encodable.
	Detail any
	// Deadline is this challenge's own timer, or nil for a challenge that only
	// ends when the decision does. It is never the decision's expiry: the
	// lifecycle folds the two together itself, and a handler that returned the
	// decision's expiry here would make an unmet challenge look like a timer.
	Deadline *time.Time
}

// SubmitRequest carries evidence toward a challenge.
type SubmitRequest struct {
	// Instance names the challenge.
	Instance Instance
	// Decision is the decision's frozen content.
	Decision DecisionContext
	// Detail is what Issue persisted, as stored.
	Detail json.RawMessage
	// Submitter is the authenticated caller. It is never nil: the lifecycle
	// refuses unauthenticated submissions before reaching a handler.
	Submitter *identity.Subject
	// Payload is the handler-specific body of the submission.
	Payload json.RawMessage
	// Now is the submission instant.
	Now time.Time
}

// SubmitResult reports where the challenge stands after a submission.
type SubmitResult struct {
	// State is the challenge's state after the submission.
	State State
	// Have and Need report collection progress — two of three approvals is
	// Have 1, Need 2 after the first. Handlers with nothing to count leave them
	// zero.
	Have int
	Need int
	// Detail replaces the stored detail when non-nil, and leaves it unchanged
	// when nil.
	Detail any
}

// StatusRequest asks where a challenge stands.
type StatusRequest struct {
	// Instance names the challenge.
	Instance Instance
	// Decision is the decision's frozen content.
	Decision DecisionContext
	// Detail is what the challenge row holds.
	Detail json.RawMessage
	// Stored is the state the challenge row holds. A handler may report a
	// different state — a delay whose deadline has passed reports satisfied
	// while the row still says pending — and the lifecycle persists the answer.
	Stored State
	// Deadline is the challenge's stored timer, if it has one.
	Deadline *time.Time
	// Now is the instant the question is asked as of. The sweeper passes the
	// sweep time here, which is how an elapsed timer is resolved without a
	// separate callback.
	Now time.Time
}

// Status is a challenge's progress as of an instant.
type Status struct {
	// State is the challenge's state as of StatusRequest.Now.
	State State
	// Have and Need report collection progress, as in SubmitResult.
	Have int
	Need int
	// Deadline is the challenge's timer, if it has one.
	Deadline *time.Time
	// Detail replaces the stored detail when non-nil.
	Detail any
}

// Handler serves one challenge kind.
//
// A handler owns its own persistence beyond the challenge row — the quorum
// handler writes approval rows — and owns nothing about the decision itself. It
// never resolves a decision, never writes a decision state, and never decides
// that the decision as a whole is satisfied; it answers only for its own
// challenge, and the lifecycle combines the answers.
type Handler interface {
	// Kind reports the challenge kind this handler serves.
	Kind() policy.ChallengeType

	// Issue opens a challenge. It runs while the decision is being created, so
	// it must be fast and must not block on a human.
	Issue(ctx context.Context, req IssueRequest) (IssueResult, error)

	// Submit takes evidence toward the challenge. A handler that collects
	// nothing returns ErrNotSubmittable. A submission from an identity the
	// challenge does not accept returns ErrNotTarget, and the lifecycle audits
	// the refusal.
	Submit(ctx context.Context, req SubmitRequest) (SubmitResult, error)

	// Status reports where the challenge stands as of req.Now. It must be a
	// read: the lifecycle calls it on every decision read and on every sweep,
	// including for challenges that are already terminal.
	Status(ctx context.Context, req StatusRequest) (Status, error)
}

// TargetRequest asks whether an identity is a target of a challenge.
type TargetRequest struct {
	Instance Instance
	Decision DecisionContext
	Detail   json.RawMessage
	Subject  *identity.Subject
}

// Targeter reports whether an identity is one of a challenge's targets.
//
// It is optional, and separate from Handler so that adding it did not make the
// contract four verbs. The lifecycle asks it for one question only: R40's rule
// that a decision may be read by the caller who created it or by a target
// approver, and by nobody else. A handler that does not implement it has no
// targets, so it grants no read access — which is the fail-closed answer.
type Targeter interface {
	IsTarget(ctx context.Context, req TargetRequest) (bool, error)
}

// ViewRequest asks a challenge what a caller may be told about it.
type ViewRequest struct {
	Instance Instance
	Decision DecisionContext
	Detail   json.RawMessage
	Now      time.Time
}

// View is the part of a challenge in progress that may leave the deployment.
//
// It is a whitelist and not a projection of [StatusRequest.Detail]. That detail
// is storage: a delegated MFA challenge keeps a correlator and a nonce there, an
// external one keeps a shared secret's fingerprint, and a caller is owed none of
// it. A field appears here because somebody decided it may travel, and a stored
// value reaches a caller only by a handler copying it into a field by name.
//
// Empty is the answer for a challenge with nothing to publish, which is most of
// them: a quorum is completed by other people, a delay by waiting.
type View struct {
	// AuthorizationURL is where the subject's browser must be sent for the
	// challenge to be completed. Empty when the challenge is not completed by
	// sending anybody anywhere — a CIBA push, a quorum, a delay.
	AuthorizationURL string `json:"authorization_url,omitempty"`
}

// Viewer reports the publishable part of a challenge in progress.
//
// It is optional, and separate from Handler for the reason [Targeter] is:
// adding it must not make the contract four verbs, and a kind that has nothing
// to say should not have to say so. The lifecycle asks it one question — R2's
// rule that a decision object exposes enough for a caller to act on it, which
// for a challenge answered in a browser means the destination.
//
// A handler that does not implement it publishes nothing, which is both the
// fail-closed answer and the right one for every kind that has no destination.
// The lifecycle must not read a stored detail itself: it cannot tell a
// correlator from a URL without knowing the kind, and knowing the kind is what
// this seam exists to avoid.
type Viewer interface {
	View(ctx context.Context, req ViewRequest) (View, error)
}

// RedeemRequest carries a challenge's own redirect back to the handler that
// sent it.
type RedeemRequest struct {
	Instance Instance
	Decision DecisionContext
	Detail   json.RawMessage
	// Params is the callback's query, as received. It is the transport's own
	// vocabulary — `code` and `state` for a step-up — so the surface passes it
	// through rather than naming fields it would then have to keep in step with
	// whichever transports exist.
	Params map[string]string
	Now    time.Time
}

// Redemption is what a redeemed callback turned into.
//
// It is not a submission. A callback carries a credential the deployment has
// not verified yet, and verifying credentials is the identity package's job on
// the surface that received it — so a redemption hands back the raw credential
// and the body that will accompany it, and the surface completes the round by
// calling Submit with the caller that credential proved.
type Redemption struct {
	// Credential is the raw token the redirect was worth, for the surface to
	// verify. A redemption that produced none is a redemption that proved
	// nothing, and the surface refuses it the way it refuses one that will not
	// verify.
	Credential string
	// Payload is the submission body to send back through Submit.
	Payload json.RawMessage
}

// Redeemer turns a challenge's own redirect into the makings of a submission.
//
// It is optional, and separate from Handler for the reason [Targeter] and
// [Viewer] are: the contract stays at three verbs. Only a kind that sent
// somebody somewhere has a redirect to redeem, and a handler that does not
// implement this has none — which is why the lifecycle answers
// [ErrNotRedeemable] rather than inventing a default.
//
// Every refusal is [ErrRedemptionRefused] with the reason wrapped for the audit
// trail and never for the response. The party arriving here followed a link; it
// is not a caller the deployment has authenticated, and the difference between
// "that state is wrong" and "that code is spent" is a difference an operator
// needs and a stranger does not.
type Redeemer interface {
	Redeem(ctx context.Context, req RedeemRequest) (Redemption, error)
}

// Registry maps challenge kinds to their handlers.
//
// It is built at wiring time and read concurrently afterward, so registration
// happens before the first lookup and never after. There is no unregister.
type Registry struct {
	handlers map[policy.ChallengeType]Handler
}

// NewRegistry returns a registry holding the given handlers.
func NewRegistry(handlers ...Handler) (*Registry, error) {
	r := &Registry{handlers: make(map[policy.ChallengeType]Handler, len(handlers))}
	for _, h := range handlers {
		if err := r.Register(h); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Register adds a handler. A second handler for a kind is an error rather than
// a replacement: a silently overridden challenge handler is a security control
// that stopped running.
func (r *Registry) Register(h Handler) error {
	if h == nil {
		return errors.New("challenge: cannot register a nil handler")
	}
	kind := h.Kind()
	if !kind.Valid() {
		return fmt.Errorf("challenge: handler declares unknown kind %q", kind)
	}
	if r.handlers == nil {
		r.handlers = make(map[policy.ChallengeType]Handler)
	}
	if _, dup := r.handlers[kind]; dup {
		return fmt.Errorf("%w: %q", ErrDuplicateHandler, kind)
	}
	r.handlers[kind] = h
	return nil
}

// Handler returns the handler for a kind, or ErrNoHandler.
func (r *Registry) Handler(kind policy.ChallengeType) (Handler, error) {
	if r != nil {
		if h, ok := r.handlers[kind]; ok {
			return h, nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrNoHandler, kind)
}

// Kinds reports which challenge kinds have a handler, in declaration order.
func (r *Registry) Kinds() []policy.ChallengeType {
	if r == nil {
		return nil
	}
	var out []policy.ChallengeType
	for _, kind := range policy.ChallengeTypes() {
		if _, ok := r.handlers[kind]; ok {
			out = append(out, kind)
		}
	}
	return out
}
