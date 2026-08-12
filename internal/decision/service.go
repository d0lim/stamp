package decision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// Errors the service returns as sentinels.
var (
	// ErrUnauthenticated reports a call that carried no verified caller. Every
	// entry point refuses before evaluating anything: R40's rule is that the
	// PEP surface rejects unauthenticated requests ahead of evaluation, not
	// that it evaluates and then declines to answer.
	ErrUnauthenticated = errors.New("decision: caller is not authenticated")

	// ErrNotAuthorized reports a caller who may not see or act on a decision:
	// R40 limits a decision to the caller who created it and the approvers it
	// targets.
	ErrNotAuthorized = errors.New("decision: caller may not access this decision")

	// ErrNotPending reports an action on a decision that has already resolved.
	ErrNotPending = errors.New("decision: decision is no longer pending")

	// ErrNoSuchChallenge reports a submission against an ordinal the decision
	// does not have.
	ErrNoSuchChallenge = errors.New("decision: decision has no such challenge")

	// ErrIdempotencyKeyReused reports a caller that sent a key it has already
	// used, for a request that is not the one the key names.
	//
	// It is a distinct sentinel and not a variant of ErrConflict because it is
	// the only conflict on this surface that is the *caller's* mistake and is
	// safe to tell the caller about: the lookup behind it is scoped to the
	// caller's own keys, so the answer says nothing about anybody else's traffic
	// and opens no oracle (R40).
	//
	// Returning the first decision instead — which is what this path did before
	// the fingerprint existed — is the failure that makes this sentinel
	// necessary. A PEP that reuses `job-91` for a different subject, resource or
	// action got back `201 allowed` for an authorization this engine never
	// evaluated, and decision.Result carries no subject, resource or action, so
	// nothing in the answer let the PEP notice the substitution. There is no
	// safe way to answer a key that names a different request; the only honest
	// answer is that the key is spent.
	ErrIdempotencyKeyReused = errors.New("decision: idempotency key was already used for a different request")
)

// Audit kinds this package appends. The store's set is open; these names are
// stable because an operator alerts on them.
const (
	// AuditKindDecisionRefused records a decide that produced no decision
	// object: a deny with no policy to pin a row to, a refusal under the
	// outstanding-decision cap, or a decide whose challenge issuance was shed.
	// R43 requires the refusal itself to be audited, and a refusal that leaves
	// no trace is indistinguishable from a request that was never made.
	//
	// The third case is the one worth naming, because it is the whole of what a
	// shed decide leaves behind. It is an entry saying a limit fired, not a
	// decision saying a person was refused — which is the distinction the shed
	// path was getting wrong when it wrote a denied decision row instead.
	AuditKindDecisionRefused = "decision.refused"

	// AuditKindAccessRefused records a read or a submission refused because the
	// caller is neither the creator nor a target.
	AuditKindAccessRefused = "decision.access.refused"
)

// Reasons this package adds to the evaluator's set.
const (
	// ReasonOutstandingCap is the ground for a decide refused because the
	// subject already holds the configured number of unresolved decisions.
	ReasonOutstandingCap engine.Reason = "outstanding_cap"

	// ReasonRateLimited is the ground for a decide refused because the caller or
	// the subject was over its rate (R43).
	//
	// It lives here rather than where it is produced. The refusal is raised at
	// the HTTP surface, ahead of this service — that is the point of it, since a
	// limit applied after the evaluation has not protected the evaluation — but
	// the vocabulary a decide answer speaks belongs to the package that owns the
	// answer. A PEP reading `reason` must be able to find every value it can
	// receive in one list, and R43 is explicit that a refusal under a limit is a
	// deny: a status code would say the request failed, when what happened is
	// that the request was judged and the judgment was no.
	ReasonRateLimited engine.Reason = "rate_limited"

	// ReasonChallengeSatisfied is the ground for a decision that resolved
	// because its challenges were met.
	ReasonChallengeSatisfied engine.Reason = "challenge_satisfied"

	// ReasonChallengeFailed is the ground for a decision denied by a failed or
	// timed-out challenge.
	ReasonChallengeFailed engine.Reason = "challenge_failed"

	// ReasonChallengeRateLimited is the ground for a decide denied because a
	// challenge it needed was never opened: the issuance was shed by a challenge
	// issue budget (R43).
	//
	// It has parity with ReasonOutstandingCap above, and for the same reason
	// that one is not folded into the policy's vocabulary: what happened is a
	// limit this deployment applied, not a judgement anybody made about the
	// request. Without it the answer reads `challenge_failed`, which is also
	// what a rejected step-up reads — so an operator watching denies could not
	// tell "the subject refused the prompt" from "we never sent the prompt", and
	// those call for opposite responses. One is final; the other clears when the
	// window does.
	//
	// **It carries a decision identifier on one path and not the other, and the
	// difference is not cosmetic.** On the decide path there is no row: Decide
	// reads the shed bit at issue and refuses through refuseShed before anything
	// is written, because a decision row here is a terminal deny on the history
	// of a person nobody asked anything — which is what this path used to write,
	// once per legitimate authorization, for as long as somebody else held that
	// person's issue budget empty. On the revalidation path (R31) the decision
	// already exists and its challenge is re-issued into a row that is already
	// there, so the ground resolves onto it as any other failure would. A client
	// branches on the presence of `id`, never on the reason, exactly as it must
	// for every other answer this surface gives.
	//
	// It is deliberately not `rate_limited`. That value is the decide surface's
	// own caller and subject budgets, refused before the lifecycle was entered;
	// this one is a challenge handler's issue budget, refused on the way to an
	// IdP or a webhook. They are configured separately and an operator raising
	// one has not raised the other.
	ReasonChallengeRateLimited engine.Reason = "challenge_rate_limited"

	// ReasonExpired is the ground for a decision the sweeper expired.
	ReasonExpired engine.Reason = "expired"
)

// Defaults for the knobs a deployment does not set.
const (
	// DefaultTTL is how long a decision stays open when neither the caller nor
	// the operator says otherwise.
	DefaultTTL = 15 * time.Minute

	// DefaultMaxOutstanding bounds how many unresolved decisions one subject
	// may hold at once (R43). It is a cap rather than a rate limit because the
	// cost being bounded is state that persists, not work that is done.
	DefaultMaxOutstanding = 32
)

// Obligation is one duty returned with a decision. Enforcing it is the calling
// service's job; v1 returns it and records it (R8).
type Obligation struct {
	Type       string         `json:"type"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// ObligationRequest asks which obligations a decision carries.
type ObligationRequest struct {
	// Input is the evaluated request.
	Input engine.Input
	// PolicyID is the policy the outcome is attributed to.
	PolicyID string
	// Gates are the gated policies that demanded challenges, empty for an
	// immediate allow.
	Gates []engine.Gated
}

// ObligationSource produces the obligations attached to a decision.
//
// It is a seam rather than a field read off the policy because the policy
// schema has no obligation declaration yet — v1's authoring path does not write
// one. When it grows one, the default implementation reads it and every caller
// of this package keeps working.
type ObligationSource interface {
	ObligationsFor(ctx context.Context, req ObligationRequest) ([]Obligation, error)
}

// ObligationSourceFunc adapts a function to ObligationSource.
type ObligationSourceFunc func(ctx context.Context, req ObligationRequest) ([]Obligation, error)

// ObligationsFor calls f.
func (f ObligationSourceFunc) ObligationsFor(ctx context.Context, req ObligationRequest) ([]Obligation, error) {
	return f(ctx, req)
}

// PolicyVersionFunc reports the stored version a decision pins its policy to.
//
// It is a seam because the evaluator's snapshot and the store's current
// effective set can disagree — a revision that landed between the snapshot
// being built and this decide being served. A caller that holds the snapshot's
// versions passes them here; the default reads the store's effective version,
// which is right whenever the snapshot is current.
type PolicyVersionFunc func(ctx context.Context, policyID string) (int64, error)

// Config configures a Service.
type Config struct {
	// Store is the persistence handle. Required.
	Store *store.Store

	// Audit is the claimed audit writer this service appends through. Required:
	// a decision that is not audited is not a decision this system will admit
	// to having made.
	Audit *store.AuditWriter

	// Evaluator is the decision-path evaluator. Required. It is deliberately
	// the decide evaluator and not the check one — the two invariants live in
	// that type, and a service that took a plain function could be handed one
	// that bypasses them.
	Evaluator *engine.DecideEvaluator

	// Challenges maps challenge kinds to handlers. A kind with no handler fails
	// closed: the decision cannot be created rather than being created with a
	// challenge nobody will ever satisfy.
	Challenges *challenge.Registry

	// Obligations produces the obligation list. Nil means no obligations.
	Obligations ObligationSource

	// PolicyVersion pins the policy version a decision records. Nil reads the
	// store's effective version.
	PolicyVersion PolicyVersionFunc

	// TTL is the default decision lifetime. Zero uses DefaultTTL.
	TTL time.Duration

	// MaxOutstanding caps unresolved decisions per subject. Zero uses
	// DefaultMaxOutstanding; a negative value removes the cap, which an
	// operator has to write down on purpose.
	MaxOutstanding int

	// Now is the clock. Nil uses the store's.
	Now func() time.Time
}

// Service creates decisions, drives their challenges and resolves them.
type Service struct {
	store          *store.Store
	audit          *store.AuditWriter
	eval           *engine.DecideEvaluator
	challenges     *challenge.Registry
	obligations    ObligationSource
	policyVersion  PolicyVersionFunc
	ttl            time.Duration
	maxOutstanding int
	now            func() time.Time
}

// New builds a Service.
func New(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("decision: a store is required")
	}
	if cfg.Audit == nil {
		return nil, errors.New("decision: an audit writer is required")
	}
	if cfg.Evaluator == nil {
		return nil, errors.New("decision: a decide evaluator is required")
	}
	s := &Service{
		store:          cfg.Store,
		audit:          cfg.Audit,
		eval:           cfg.Evaluator,
		challenges:     cfg.Challenges,
		obligations:    cfg.Obligations,
		policyVersion:  cfg.PolicyVersion,
		ttl:            cfg.TTL,
		maxOutstanding: cfg.MaxOutstanding,
		now:            cfg.Now,
	}
	if s.ttl <= 0 {
		s.ttl = DefaultTTL
	}
	if s.maxOutstanding == 0 {
		s.maxOutstanding = DefaultMaxOutstanding
	}
	if s.now == nil {
		s.now = cfg.Store.Now
	}
	if s.policyVersion == nil {
		s.policyVersion = func(ctx context.Context, policyID string) (int64, error) {
			rec, err := store.EffectivePolicy(ctx, cfg.Store.Pool(), policyID)
			if err != nil {
				return 0, fmt.Errorf("decision: pin policy %q: %w", policyID, err)
			}
			return rec.Version, nil
		}
	}
	return s, nil
}

// Now reports the service clock.
func (s *Service) Now() time.Time { return s.now().UTC() }

// ChallengeView is one challenge's progress in a decision response.
//
// Everything here is either kind-agnostic or published by the handler through
// [challenge.Viewer]. Nothing is read out of the challenge row directly: this
// package cannot tell a stored URL from a stored secret without knowing the
// kind, and it does not know the kind on purpose (KTD1).
type ChallengeView struct {
	Ordinal  int                  `json:"ordinal"`
	Kind     policy.ChallengeType `json:"kind"`
	State    challenge.State      `json:"state"`
	Have     int                  `json:"have"`
	Need     int                  `json:"need"`
	Deadline *time.Time           `json:"deadline,omitempty"`
	// AuthorizationURL is where the subject must be sent to complete this
	// challenge, for the kinds completed in a browser. Absent otherwise, so a
	// quorum, a delay and an external challenge serialize as they always did.
	AuthorizationURL string `json:"authorization_url,omitempty"`
}

// Result is a decision as a caller sees it (R2): the state, the challenges and
// their collection progress, the deadline, and the obligations.
type Result struct {
	ID            string              `json:"id,omitempty"`
	State         store.DecisionState `json:"state"`
	Outcome       engine.Decision     `json:"-"`
	Reason        engine.Reason       `json:"reason"`
	PolicyID      string              `json:"policy_id,omitempty"`
	PolicyVersion int64               `json:"policy_version,omitempty"`
	Obligations   []Obligation        `json:"obligations"`
	Challenges    []ChallengeView     `json:"challenges,omitempty"`
	CreatedAt     time.Time           `json:"created_at,omitzero"`
	ExpiresAt     time.Time           `json:"expires_at,omitzero"`
	ResolvedAt    *time.Time          `json:"resolved_at,omitempty"`

	// RetryAfter is how long until the budget that shed this request has room
	// again, and zero for every answer that was not shed.
	//
	// It is not serialized, for the reason Outcome is not: the body of a decide
	// answer is the decision, and a number about this instance's token bucket is
	// not part of it. It travels so that the HTTP surface can render the header
	// — the surface knows its own budgets and does not know a challenge
	// handler's, and the handler that shed the issuance is the only thing that
	// does.
	RetryAfter time.Duration `json:"-"`
}

// Allowed reports whether the decision has resolved to allow. A pending
// decision is not an allow, which is the distinction a boolean answer cannot
// carry and the reason decisions are objects.
func (r Result) Allowed() bool { return r.State == store.DecisionAllowed }

// Pending reports whether the decision is still collecting.
func (r Result) Pending() bool { return r.State == store.DecisionPending }

// Request is one decide call.
type Request struct {
	// Caller is the authenticated caller. Required.
	Caller *identity.Subject

	// Input is the access request to evaluate.
	Input engine.Input

	// There is deliberately no fact snapshot field here. R7 requires the
	// decision to freeze the facts the evaluation rested on, and a snapshot the
	// caller passed alongside the request is not that — it is a second set that
	// resembles it. The evaluator hands its resolved batch back on the result,
	// and Decide reads it from there, so the two cannot diverge and no caller
	// has to be trusted to keep them together.

	// TTL overrides the service default for this decision. Zero uses it.
	TTL time.Duration

	// IdempotencyKey names this decide attempt, so that a retry of it returns
	// the decision the first attempt created instead of creating a second one.
	// Empty means the caller is not retrying anything and every call is a new
	// decision, which is what every caller did before this field existed.
	IdempotencyKey string
}

// Decide evaluates a request and creates the decision object it calls for
// (R2).
//
// Three outcomes leave three different traces. A challenge outcome creates a
// pending decision with its challenges opened. An allow creates a decision and
// resolves it in the same call, so that an allow that needed nothing is still
// an auditable object with its policy version, facts and obligations frozen. A
// deny creates no row — a deny that no policy matched has no policy version to
// pin a row to, and inventing one would put a decision in the table that no
// policy authorised — and is recorded as an audit entry instead.
func (s *Service) Decide(ctx context.Context, req Request) (Result, error) {
	if req.Caller == nil {
		return Result{}, ErrUnauthenticated
	}
	now := s.Now()

	// The lookup stands here — ahead of the cap, ahead of the evaluation, ahead
	// of the challenge issuance — and that placement is the whole unit (KTD5).
	//
	// This function mints the identifier, issues every challenge and only then
	// writes the row, so the IdP call and the outbound webhook both happen before
	// the database has heard of the decision. A key enforced only as a uniqueness
	// constraint at insert time would therefore push a second step-up at the
	// subject on every retry and refuse afterwards: the caller would be protected
	// from a duplicate row and the person would not be protected from anything.
	//
	// It is ahead of the outstanding cap for a second reason. A decision counts
	// against its own subject's cap while it is open, so a retry arriving at a
	// full cap would be refused by the very decision it is asking after.
	fingerprint := requestFingerprint(req.Input)
	if req.IdempotencyKey != "" {
		existing, err := store.DecisionByIdempotencyKey(ctx, s.store.Pool(),
			req.Caller.CallerID(), req.IdempotencyKey)
		switch {
		case err == nil:
			if !sameRequest(existing, fingerprint) {
				return Result{}, keyReused(req, existing)
			}
			// Answered through advance rather than through a bare read, so that
			// a retry sees the decision as it stands now — a delay that has since
			// elapsed, a quorum that has since been met — which is what the first
			// call would have reported had it arrived at this instant.
			return s.advance(ctx, existing.ID, now)
		case !errors.Is(err, store.ErrNotFound):
			return Result{}, err
		}
	}

	if s.maxOutstanding > 0 {
		outstanding, err := s.countOutstanding(ctx, req.Input.Subject.ID, now)
		if err != nil {
			return Result{}, err
		}
		if outstanding >= s.maxOutstanding {
			return s.refuse(ctx, req, ReasonOutstandingCap, map[string]any{
				"outstanding": outstanding,
				"cap":         s.maxOutstanding,
			})
		}
	}

	evaluated, err := s.eval.Evaluate(ctx, req.Input)
	if err != nil {
		return Result{}, fmt.Errorf("decision: evaluate: %w", err)
	}
	if evaluated.Decision() == engine.Deny {
		return s.refuse(ctx, req, evaluated.Reason(), map[string]any{
			"policy_id": evaluated.PolicyID(),
		})
	}

	obligations, err := s.obligationsFor(ctx, req, evaluated)
	if err != nil {
		return Result{}, err
	}

	policyID := evaluated.PolicyID()
	version, err := s.policyVersion(ctx, policyID)
	if err != nil {
		return Result{}, err
	}

	// The identifier is generated before the challenges are issued because a
	// handler is told which decision it is issuing against — a correlator or a
	// binding message that names the decision cannot be built after the fact.
	id, err := store.NewDecisionID()
	if err != nil {
		return Result{}, err
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = s.ttl
	}
	expiresAt := now.Add(ttl)

	// The evidence, taken from the evaluation rather than from the caller. This
	// is the value the approval binding hash is computed over and the value a
	// revision re-evaluates against, so it has to be the batch that decided
	// whether the policy applied at all.
	factSnapshot := evaluated.Facts()
	obligationsJSON, err := json.Marshal(obligations)
	if err != nil {
		return Result{}, fmt.Errorf("decision: encode obligations: %w", err)
	}

	specs := flatten(evaluated.Gates())
	issueCtx := challenge.DecisionContext{
		DecisionID:   id,
		CallerID:     req.Caller.CallerID(),
		SubjectID:    req.Input.Subject.ID,
		ResourceID:   req.Input.Resource.ID,
		Action:       req.Input.Action,
		PolicyID:     policyID,
		Obligations:  obligationsJSON,
		FactSnapshot: mustJSON(factSnapshot),
		Request:      mustJSON(requestPayload(req.Input)),
		CreatedAt:    now,
		ExpiresAt:    expiresAt,
	}

	opened := make([]store.NewChallenge, 0, len(specs))
	for ordinal, spec := range specs {
		handler, herr := s.challenges.Handler(spec.ChallengeType())
		if herr != nil {
			return Result{}, fmt.Errorf("decision: open challenge %d of %s: %w", ordinal, id, herr)
		}
		instance := challenge.Instance{DecisionID: id, Ordinal: ordinal, Kind: spec.ChallengeType()}
		issued, ierr := handler.Issue(ctx, challenge.IssueRequest{
			Instance: instance,
			Spec:     spec,
			Decision: issueCtx,
			Now:      now,
		})
		if ierr != nil {
			return Result{}, fmt.Errorf("decision: issue %s: %w", instance, ierr)
		}
		if !issued.State.Valid() {
			return Result{}, fmt.Errorf("decision: handler for %s returned state %q", instance, issued.State)
		}
		// A shed issuance ends the decide here, with no decision object at all.
		//
		// **It used to end as a terminal deny on the subject's record.** The shed
		// challenge was stored failed, `failed > 0` resolved the decision through
		// s.resolve(..., Fail, ...), and the person nobody had been asked about
		// was left holding a decision that says `denied / challenge_rate_limited`
		// on their history — for every legitimate authorization they needed while
		// somebody else held their issue budget empty. A limit that shed traffic
		// was writing judgements about people.
		//
		// So it takes the shape api.Decisions.refuseRate takes for the surface's
		// own budget, and the shape s.refuse already takes for the outstanding
		// cap: a deny with a ground that says a limit fired, no row, and a
		// Retry-After. The three refusals now differ only in which limit they
		// name, which is the difference a caller has to act on.
		//
		// **What is stranded, said out loud.** A challenge at a lower ordinal may
		// already have opened — a webhook posted, a prompt sent — and no decision
		// row will exist to record that it did. That residue is unavoidable in
		// this direction: a handler owns its own budget, so nothing here can know
		// a later issuance will be shed before the earlier ones have run. The
		// audit entry names how many opened, which is the trace that keeps it
		// from being invisible; the alternative — keeping the row so the opened
		// challenge has somewhere to hang — is the terminal deny this is
		// removing, and a decision nobody can satisfy is worse than a webhook
		// nobody answers.
		//
		// The state is checked alongside the bit rather than trusted from it.
		// Shed is only meaningful on a failed issue — the contract says so where
		// it is declared — and a handler that set it on a challenge it actually
		// opened would, without this, have that challenge thrown away here along
		// with the decision that was going to carry it. Reading both means the
		// worst a handler bug can do is leave the old behaviour in place.
		if issued.Shed && issued.State == challenge.StateFailed {
			return s.refuseShed(ctx, req, issued.RetryAfter, map[string]any{
				"challenge_ordinal": ordinal,
				"challenge_kind":    string(spec.ChallengeType()),
				"opened_before_it":  len(opened),
			})
		}
		// A decision has to outlive the challenges it opened. A delay longer
		// than the default lifetime would otherwise be structurally
		// unsatisfiable: the decision would expire while its own timer was
		// still running.
		if issued.Deadline != nil && issued.Deadline.After(expiresAt) {
			expiresAt = issued.Deadline.UTC()
			issueCtx.ExpiresAt = expiresAt
		}
		opened = append(opened, store.NewChallenge{
			Ordinal:  ordinal,
			Kind:     spec.ChallengeType(),
			Deadline: issued.Deadline,
			Detail:   issued.Detail,
		})
	}

	created, err := s.audit.CreateDecision(ctx, store.NewDecision{
		ID:             id,
		CallerID:       req.Caller.CallerID(),
		PolicyID:       policyID,
		PolicyVersion:  version,
		SubjectID:      req.Input.Subject.ID,
		ResourceID:     req.Input.Resource.ID,
		Action:         req.Input.Action,
		Request:        requestPayload(req.Input),
		FactSnapshot:   factSnapshot,
		Obligations:    obligations,
		ExpiresAt:      expiresAt,
		Challenges:     opened,
		IdempotencyKey: req.IdempotencyKey,
		// Frozen in the same row and the same transaction as the key it
		// qualifies. A fingerprint stored anywhere else is a fingerprint that
		// can be absent for a key that is present, which is exactly the state
		// the lookup above cannot answer safely.
		IdempotencyFingerprint: fingerprintFor(req.IdempotencyKey, fingerprint),
	})
	// A conflict on a keyed create means another attempt under the same key
	// landed while this one was issuing its challenges. The two callers are the
	// same caller retrying, so the loser answers with the winner's decision
	// rather than reporting a conflict to somebody who did nothing wrong.
	//
	// The challenges this attempt opened are already open, and that is the
	// residue the unique index cannot remove — it is a backstop, and it can only
	// act after the pushes it would have wanted to prevent. Bounding the damage
	// to a genuine race is what it is for; the lookup at the top is what keeps a
	// retry from being one.
	//
	// The winner is held to the same fingerprint the lookup holds it to. Two
	// concurrent attempts under one key that name *different* requests are not a
	// retry racing itself, they are the substitution the fingerprint exists to
	// refuse, arriving through the one window where the lookup could not see it.
	if req.IdempotencyKey != "" && errors.Is(err, store.ErrConflict) {
		winner, lookupErr := store.DecisionByIdempotencyKey(ctx, s.store.Pool(),
			req.Caller.CallerID(), req.IdempotencyKey)
		if lookupErr != nil {
			return Result{}, err
		}
		if !sameRequest(winner, fingerprint) {
			return Result{}, keyReused(req, winner)
		}
		return s.advance(ctx, winner.ID, now)
	}
	if err != nil {
		return Result{}, err
	}

	// Advance rather than assume: a challenge that issued already satisfied,
	// and a decision with no challenges at all, both resolve here through the
	// same transition function every other path uses.
	return s.advance(ctx, created.ID, now)
}

// Get returns a decision to a caller entitled to see it (R40).
//
// Entitlement is the creator or a target approver, and nothing else. The
// subject of the decision is deliberately not on the list: the person a
// decision is about is frequently the person it is protecting against.
func (s *Service) Get(ctx context.Context, caller *identity.Subject, id string) (Result, error) {
	if caller == nil {
		return Result{}, ErrUnauthenticated
	}
	now := s.Now()
	d, err := store.GetDecision(ctx, s.store.Pool(), id)
	if err != nil {
		return Result{}, err
	}
	progress, err := store.ChallengeProgressFor(ctx, s.store.Pool(), id)
	if err != nil {
		return Result{}, err
	}
	allowed, err := s.mayAccess(ctx, caller, d, progress)
	if err != nil {
		return Result{}, err
	}
	if !allowed {
		s.auditAccessRefusal(ctx, caller, d, "read")
		return Result{}, ErrNotAuthorized
	}
	return s.view(ctx, d, progress, now)
}

// Submission is one submission of evidence toward a challenge.
type Submission struct {
	// Caller is the authenticated submitter. Required.
	Caller *identity.Subject
	// DecisionID names the decision.
	DecisionID string
	// Ordinal names the challenge within it.
	Ordinal int
	// Payload is the handler-specific body.
	Payload json.RawMessage
}

// Submit hands evidence to a challenge and re-settles the decision.
//
// The deadline is checked on entry, against expires_at and against the
// challenge's own timer, before the handler sees the submission. That is the
// whole reason the sweeper is allowed to be late: an approval that arrives
// after the deadline but before the sweep is refused here, so it cannot satisfy
// a quorum that a background job has not gotten around to closing yet.
//
// # Standing is settled before state, and that ordering is the security property
//
// The two checks are in this order and not the other one. Whether the caller has
// any standing on this decision does not depend on what state the decision is
// in, but the answer a caller *reads* does: "not collecting" and "expired" are
// 409s, "you may not have this" and "there is no such decision" are one 404
// (#38), so asking the state first hands a caller with no standing a 404 while
// the decision is pending and a 409 the moment it resolves. That is the
// existence oracle R40 forbids, with the resolution time thrown in, and it
// survived the fix to the error table because the error table never saw it — the
// only authorization signal on this path came from the challenge handler, which
// ran after the state check had already answered.
//
// The 409s are kept for callers who do have standing, and that is deliberate
// rather than an oversight: an approver being waited on has to be able to tell
// "you are too late" from "there is nothing here", and folding their answer into
// the stranger's 404 would degrade the person this endpoint exists for in order
// to protect against a person who is now getting one answer either way.
func (s *Service) Submit(ctx context.Context, sub Submission) (Result, error) {
	if sub.Caller == nil {
		return Result{}, ErrUnauthenticated
	}
	now := s.Now()

	d, progress, err := s.decisionWithProgress(ctx, sub.DecisionID)
	if err != nil {
		return Result{}, err
	}
	// Resolving which challenge was named is not judging its state: an ordinal
	// the decision does not have is refused with the same 404 a decision that
	// does not exist is, so doing it here — where the caller's standing has not
	// been established yet — tells a stranger nothing a missing decision would
	// not have told them, and the standing rule below needs the kind.
	target, err := challengeAt(d, progress, sub.Ordinal)
	if err != nil {
		return Result{}, err
	}

	allowed, err := s.mayActOn(ctx, sub.Caller, d, progress, target)
	if err != nil {
		return Result{}, err
	}
	if !allowed {
		s.auditAccessRefusal(ctx, sub.Caller, d, "submit")
		return Result{}, ErrNotAuthorized
	}

	if err := stillCollecting(d, target, now); err != nil {
		return Result{}, err
	}

	handler, err := s.challenges.Handler(target.Kind)
	if err != nil {
		return Result{}, err
	}
	instance := challenge.Instance{DecisionID: d.ID, Ordinal: target.Ordinal, Kind: target.Kind}
	out, err := handler.Submit(ctx, challenge.SubmitRequest{
		Instance:  instance,
		Decision:  contextOf(d),
		Detail:    target.Detail,
		Submitter: sub.Caller,
		Payload:   sub.Payload,
		Now:       now,
	})
	if err != nil {
		if errors.Is(err, challenge.ErrNotTarget) {
			s.auditAccessRefusal(ctx, sub.Caller, d, "submit")
		}
		return Result{}, fmt.Errorf("decision: submit to %s: %w", instance, err)
	}
	if !out.State.Valid() {
		return Result{}, fmt.Errorf("decision: handler for %s returned state %q", instance, out.State)
	}

	detail := out.Detail
	if detail == nil {
		detail = target.Detail
	}
	if err := s.audit.SetChallengeState(ctx, d.ID, target.Ordinal,
		storeChallengeState(out.State), detail); err != nil {
		return Result{}, err
	}

	return s.advance(ctx, d.ID, now)
}

// collecting resolves one challenge that is open for evidence as of now.
//
// It is the entry check [Service.Redeem] makes, and [Service.Submit] makes the
// same one in two halves with the standing rule between them (see there). The
// three steps below are shared functions rather than a second copy so that the
// two cannot drift: an authorization code arriving after the decision expired
// must be refused on exactly the terms an approval arriving then is, and a
// second copy of "is this still collecting" is a second copy that can answer
// differently.
//
// Redeem has no standing check to make and is not missing one. The party on that
// path is a browser following an IdP's `Location` header, holding no credential
// at all; what it holds instead is a `state` this server minted for this
// challenge, and the handler is what judges that. Its surface answers one
// uniform 403 for every refusal, so the ordering here leaks nothing there.
func (s *Service) collecting(
	ctx context.Context, decisionID string, ordinal int, now time.Time,
) (store.Decision, store.ChallengeProgress, error) {
	d, progress, err := s.decisionWithProgress(ctx, decisionID)
	if err != nil {
		return store.Decision{}, store.ChallengeProgress{}, err
	}
	target, err := challengeAt(d, progress, ordinal)
	if err != nil {
		return store.Decision{}, store.ChallengeProgress{}, err
	}
	if err := stillCollecting(d, target, now); err != nil {
		return store.Decision{}, store.ChallengeProgress{}, err
	}
	return d, target, nil
}

// decisionWithProgress reads a decision and its challenge rows, judging nothing.
//
// It is separate from the tests that follow it because the caller's standing has
// to be settled against a decision that has been read but not yet judged. Every
// refusal it can produce is store.ErrNotFound, which is the same 404 a caller
// with no standing gets for a decision that does exist.
func (s *Service) decisionWithProgress(
	ctx context.Context, decisionID string,
) (store.Decision, []store.ChallengeProgress, error) {
	d, err := store.GetDecision(ctx, s.store.Pool(), decisionID)
	if err != nil {
		return store.Decision{}, nil, err
	}
	progress, err := store.ChallengeProgressFor(ctx, s.store.Pool(), d.ID)
	if err != nil {
		return store.Decision{}, nil, err
	}
	return d, progress, nil
}

// challengeAt picks the challenge an ordinal names.
func challengeAt(
	d store.Decision, progress []store.ChallengeProgress, ordinal int,
) (store.ChallengeProgress, error) {
	for i := range progress {
		if progress[i].Ordinal == ordinal {
			return progress[i], nil
		}
	}
	return store.ChallengeProgress{},
		fmt.Errorf("decision %q has no challenge %d: %w", d.ID, ordinal, ErrNoSuchChallenge)
}

// stillCollecting is the state half: the decision is open, and so is the
// challenge.
//
// The decision's own deadline is tested through [store.EnsureActive] rather than
// re-read through store.ActiveDecision, so the rule stays in the one place the
// store states it. The clock is the service's, which is the clock the challenge
// timer below is already judged against — an entry check that read the decision's
// deadline off one clock and the challenge's off another could refuse a
// submission for being late and accept the next one.
func stillCollecting(d store.Decision, target store.ChallengeProgress, now time.Time) error {
	if err := store.EnsureActive(d, now); err != nil {
		return err
	}
	if d.State != store.DecisionPending {
		return fmt.Errorf("decision %q is %s: %w", d.ID, d.State, ErrNotPending)
	}
	if challengeState(target.State) != challenge.StatePending {
		return fmt.Errorf("challenge %d of decision %q is %s: %w",
			target.Ordinal, d.ID, target.State, ErrNotPending)
	}
	if target.Deadline != nil && !now.Before(*target.Deadline) {
		return fmt.Errorf("challenge %d of decision %q closed at %s: %w",
			target.Ordinal, d.ID, target.Deadline, store.ErrDecisionExpired)
	}
	return nil
}

// Callback is one transport-level redirect arriving for a challenge.
type Callback struct {
	// DecisionID and Ordinal come from the callback path, which STAMP built
	// itself and therefore knows.
	DecisionID string
	Ordinal    int
	// Params is the callback's query as received.
	Params map[string]string
}

// Redeem turns a challenge's own redirect into the credential and body a
// [Service.Submit] needs.
//
// It authenticates nobody, and that is the shape of the problem rather than a
// gap: the party arriving is a browser following an IdP's `Location` header,
// and the only credential in the exchange is the one the redirect is worth —
// which does not exist until the code has been redeemed. So the round is three
// steps and not one: redeem here, verify the credential on the surface that
// received it, then submit as the caller that credential proved.
//
// The lifecycle does not read the redemption. It routes it: which challenge, is
// it still collecting, does its handler have a redirect to redeem at all. What
// `state` means and whether this one is right belongs to the handler that minted
// it, for the same reason the correlator does.
func (s *Service) Redeem(ctx context.Context, cb Callback) (challenge.Redemption, error) {
	now := s.Now()
	d, target, err := s.collecting(ctx, cb.DecisionID, cb.Ordinal, now)
	if err != nil {
		return challenge.Redemption{}, err
	}
	handler, err := s.challenges.Handler(target.Kind)
	if err != nil {
		return challenge.Redemption{}, err
	}
	instance := challenge.Instance{DecisionID: d.ID, Ordinal: target.Ordinal, Kind: target.Kind}
	redeemer, ok := handler.(challenge.Redeemer)
	if !ok {
		return challenge.Redemption{}, fmt.Errorf("%w: %s", challenge.ErrNotRedeemable, instance)
	}
	out, err := redeemer.Redeem(ctx, challenge.RedeemRequest{
		Instance: instance,
		Decision: contextOf(d),
		Detail:   target.Detail,
		Params:   cb.Params,
		Now:      now,
	})
	if err != nil {
		return challenge.Redemption{}, fmt.Errorf("decision: redeem %s: %w", instance, err)
	}
	return out, nil
}

// advance re-reads a decision, brings every challenge up to date as of now, and
// resolves the decision if the challenges say it is finished.
//
// It is the only place a decision's terminal state is written outside the
// sweeper's expiry path, and both go through Next. A decision whose own
// deadline has passed is left alone: the entry check refuses it, and the
// sweeper writes the expiry. Resolving it here instead would mean a decision
// that expired at noon reads as allowed because an approval landed at 12:00:01
// and the reader happened to be the one who triggered the settle.
func (s *Service) advance(ctx context.Context, id string, now time.Time) (Result, error) {
	d, err := store.GetDecision(ctx, s.store.Pool(), id)
	if err != nil {
		return Result{}, err
	}
	progress, err := store.ChallengeProgressFor(ctx, s.store.Pool(), id)
	if err != nil {
		return Result{}, err
	}
	if d.State != store.DecisionPending {
		return s.view(ctx, d, progress, now)
	}
	if d.Expired(now) {
		return s.view(ctx, d, progress, now)
	}

	changed := false
	satisfied, failed := 0, 0
	// Whether any challenge failed because it was never opened. It is collected
	// from the same Status answers that decide the states, so it cannot disagree
	// with them. A challenge already stored terminal is skipped here and its bit
	// is not read — which cannot lose anything, because a shed challenge is
	// recorded failed by the very pass that observes it, and that pass is the one
	// that resolves the decision. The read path recomputes the ground from every
	// challenge regardless, so a decision read back afterwards still says it.
	//
	// Only a revalidation can put a shed challenge on a row that reaches here.
	// Decide refuses a shed issuance before it writes anything, so a decision
	// that exists was never shed at creation — see the issue loop in Decide.
	shed := false
	for i := range progress {
		p := progress[i]
		if stored := challengeState(p.State); stored.Terminal() {
			if stored == challenge.StateSatisfied {
				satisfied++
			} else {
				failed++
			}
			continue
		}
		st, serr := s.status(ctx, d, p, now)
		if serr != nil {
			return Result{}, serr
		}
		next := st.State
		// A challenge whose own timer has passed and which still reports
		// pending has run out of time. Only the handler can say what an elapsed
		// timer means — a delay reports satisfied here, a quorum does not — so
		// this branch runs after asking, never instead of asking.
		if next == challenge.StatePending && p.Deadline != nil && !now.Before(*p.Deadline) {
			next = challenge.StateFailed
		}
		if next != challenge.StatePending {
			detail := st.Detail
			if detail == nil {
				detail = p.Detail
			}
			if err := s.audit.SetChallengeState(ctx, d.ID, p.Ordinal,
				storeChallengeState(next), detail); err != nil {
				return Result{}, err
			}
			changed = true
		}
		switch next {
		case challenge.StateSatisfied:
			satisfied++
		case challenge.StateFailed, challenge.StateCancelled:
			failed++
			shed = shed || st.Shed
		case challenge.StatePending:
		}
	}

	switch {
	case failed > 0:
		if _, err := s.resolve(ctx, d, Fail, failureReason(shed)); err != nil {
			return Result{}, err
		}
	case satisfied == len(progress):
		if _, err := s.resolve(ctx, d, Satisfy, reasonFor(len(progress))); err != nil {
			return Result{}, err
		}
	default:
		if !changed {
			return s.view(ctx, d, progress, now)
		}
	}

	d, err = store.GetDecision(ctx, s.store.Pool(), id)
	if err != nil {
		return Result{}, err
	}
	progress, err = store.ChallengeProgressFor(ctx, s.store.Pool(), id)
	if err != nil {
		return Result{}, err
	}
	return s.view(ctx, d, progress, now)
}

func reasonFor(challenges int) engine.Reason {
	if challenges == 0 {
		return engine.ReasonPolicyMatched
	}
	return ReasonChallengeSatisfied
}

// failureReason names the ground of a decision its challenges denied.
//
// The distinction is between a challenge that was put to somebody and not met,
// and a challenge that was never put to anybody because a limit refused to open
// it. Both leave the decision denied and only the ground says which, so the
// ground is the whole difference between "this was refused" and "ask again".
//
// **The shed branch is not dead, and it is not the decide path's.** Decide reads
// challenge.IssueResult.Shed at issue and refuses without writing a row at all,
// so no decision this function sees was shed on the way in. What reaches here is
// the revalidation path (R31): a decision that already exists has its challenge
// re-issued after a policy revision, that re-issue is shed, and the row it is
// written into is already somebody's. The row exists, so the ground has to be
// right on it — an operator reading that decision back is owed the same
// distinction as one reading a decide answer.
func failureReason(shed bool) engine.Reason {
	if shed {
		return ReasonChallengeRateLimited
	}
	return ReasonChallengeFailed
}

// resolve applies a transition and writes it.
//
// Every terminal write in this package comes through here, so the legality
// check and the persistence are never separated. A store conflict means another
// path resolved the decision first; it is reported as a refused transition
// rather than as an error, because "somebody else got there" is the expected
// outcome of two sweepers meeting, not a fault.
func (s *Service) resolve(ctx context.Context, d store.Decision, t Transition, reason engine.Reason) (bool, error) {
	next, err := Next(d.State, t)
	if err != nil {
		return false, err
	}
	_, err = s.audit.ResolveDecision(ctx, d.ID, next, nil, string(t.Trigger())+":"+string(reason))
	if errors.Is(err, store.ErrConflict) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// status asks a handler where a challenge stands as of now.
func (s *Service) status(ctx context.Context, d store.Decision, p store.ChallengeProgress, now time.Time) (challenge.Status, error) {
	handler, err := s.challenges.Handler(p.Kind)
	if err != nil {
		return challenge.Status{}, err
	}
	st, err := handler.Status(ctx, challenge.StatusRequest{
		Instance: challenge.Instance{DecisionID: d.ID, Ordinal: p.Ordinal, Kind: p.Kind},
		Decision: contextOf(d),
		Detail:   p.Detail,
		Stored:   challengeState(p.State),
		Deadline: p.Deadline,
		Now:      now,
	})
	if err != nil {
		return challenge.Status{}, fmt.Errorf("decision: status of challenge %d of %s: %w", p.Ordinal, d.ID, err)
	}
	if !st.State.Valid() {
		return challenge.Status{}, fmt.Errorf("decision: handler for %s returned state %q", p.Kind, st.State)
	}
	return st, nil
}

// publish asks a handler what a caller may be told about a challenge.
//
// [challenge.Viewer] is optional, so the type assertion failing is an answer and
// not a fault: a quorum, a delay and an external callback each have nothing to
// publish, and a decision that mixes them with one that does still assembles.
// A handler that answers with an error does not, for the reason status does not:
// the detail it could not read is the same row, and half a view of a challenge
// is worse than a refused read of the decision.
func (s *Service) publish(ctx context.Context, d store.Decision, p store.ChallengeProgress, now time.Time) (challenge.View, error) {
	handler, err := s.challenges.Handler(p.Kind)
	if err != nil {
		return challenge.View{}, err
	}
	viewer, ok := handler.(challenge.Viewer)
	if !ok {
		return challenge.View{}, nil
	}
	v, err := viewer.View(ctx, challenge.ViewRequest{
		Instance: challenge.Instance{DecisionID: d.ID, Ordinal: p.Ordinal, Kind: p.Kind},
		Decision: contextOf(d),
		Detail:   p.Detail,
		Now:      now,
	})
	if err != nil {
		return challenge.View{}, fmt.Errorf("decision: view of challenge %d of %s: %w", p.Ordinal, d.ID, err)
	}
	return v, nil
}

// view assembles the response a caller sees.
func (s *Service) view(ctx context.Context, d store.Decision, progress []store.ChallengeProgress, now time.Time) (Result, error) {
	obligations, err := decodeObligations(d.Obligations)
	if err != nil {
		return Result{}, err
	}
	out := Result{
		ID:            d.ID,
		State:         d.State,
		PolicyID:      d.PolicyID,
		PolicyVersion: d.PolicyVersion,
		Obligations:   obligations,
		CreatedAt:     d.CreatedAt,
		ExpiresAt:     d.ExpiresAt,
		ResolvedAt:    d.ResolvedAt,
	}
	switch d.State {
	case store.DecisionPending:
		out.Outcome = engine.Challenge
		out.Reason = engine.ReasonChallengeRequired
	case store.DecisionAllowed:
		out.Outcome = engine.Allow
		out.Reason = reasonFor(len(progress))
	case store.DecisionExpired:
		out.Outcome = engine.Deny
		out.Reason = ReasonExpired
	case store.DecisionDenied, store.DecisionCancelled:
		out.Outcome = engine.Deny
		out.Reason = ReasonChallengeFailed
	}
	shed := false
	for _, p := range progress {
		view := ChallengeView{
			Ordinal:  p.Ordinal,
			Kind:     p.Kind,
			State:    challengeState(p.State),
			Deadline: p.Deadline,
		}
		st, err := s.status(ctx, d, p, now)
		if err != nil {
			return Result{}, err
		}
		if st.Shed {
			shed = true
		}
		view.Have, view.Need = st.Have, st.Need
		published, err := s.publish(ctx, d, p, now)
		if err != nil {
			return Result{}, err
		}
		view.AuthorizationURL = published.AuthorizationURL
		// The stored state is what the response reports. A handler's live
		// reading is used for progress counts, but promoting a challenge to
		// satisfied is a write, and a read path must not perform one.
		out.Challenges = append(out.Challenges, view)
	}
	// The ground of a denied decision is recomputed here rather than remembered,
	// because nothing on the row remembers it: the state is written, the reason
	// is derived. Deriving it from the same Status answers the resolution used
	// is what keeps a decision reading the same afterwards as it did in the
	// response that created it.
	if out.Reason == ReasonChallengeFailed {
		out.Reason = failureReason(shed)
	}
	return out, nil
}

// mayAccess answers R40's read rule: the creator, or a target of one of the
// decision's challenges.
func (s *Service) mayAccess(ctx context.Context, caller *identity.Subject, d store.Decision, progress []store.ChallengeProgress) (bool, error) {
	if caller.CallerID() == d.CallerID {
		return true, nil
	}
	for _, p := range progress {
		handler, err := s.challenges.Handler(p.Kind)
		if err != nil {
			// A challenge whose handler is gone cannot vouch for anybody.
			continue
		}
		targeter, ok := handler.(challenge.Targeter)
		if !ok {
			continue
		}
		is, err := targeter.IsTarget(ctx, challenge.TargetRequest{
			Instance: challenge.Instance{DecisionID: d.ID, Ordinal: p.Ordinal, Kind: p.Kind},
			Decision: contextOf(d),
			Detail:   p.Detail,
			Subject:  caller,
		})
		if err != nil {
			return false, fmt.Errorf("decision: resolve targets of challenge %d of %s: %w", p.Ordinal, d.ID, err)
		}
		if is {
			return true, nil
		}
	}
	return false, nil
}

// mayActOn answers whether a submitter is allowed to learn anything about this
// decision beyond "no such decision".
//
// It is R40's read rule plus one case the read rule has no room for. A caller
// who may read the decision — its creator, or a target of any of its challenges
// — obviously may be told why their submission was refused. The case underneath
// is a challenge kind whose handler names no targets at all: an external
// challenge's counterparty is a system STAMP called out to, it holds no identity
// this service could compare against anything, and what it holds instead is a
// signature over a nonce this server minted, which only the handler can check.
// Refusing it here would not close an oracle, it would break the challenge kind
// — every callback would be turned away before the handler ever saw the
// credential that authenticates it.
//
// That fallback is narrowed to non-people. The counterparty of a handler with no
// targets arrives as a workload on the callback listener, whose refusals are one
// uniform 403; an end-user credential is never that counterparty, and admitting
// one would hand the console's callers back the state oracle for every decision
// gated on an external challenge.
//
// A kind this build has no handler for is nobody's to act on. The 501 that says
// so is preserved for a caller with standing through some other challenge, and
// withheld from everyone else — a build that cannot load a handler cannot
// identify that handler's targets either, so "no such decision" is the only
// answer it can give without guessing.
func (s *Service) mayActOn(
	ctx context.Context, caller *identity.Subject,
	d store.Decision, progress []store.ChallengeProgress, target store.ChallengeProgress,
) (bool, error) {
	allowed, err := s.mayAccess(ctx, caller, d, progress)
	if err != nil || allowed {
		return allowed, err
	}
	handler, err := s.challenges.Handler(target.Kind)
	if err != nil {
		return false, nil //nolint:nilerr // an unknown kind is not a failure to answer, it is the answer
	}
	if _, named := handler.(challenge.Targeter); named {
		return false, nil
	}
	return caller.Kind != identity.SubjectUser, nil
}

// refuse records a decide that produced no decision object and returns the deny
// the caller sees.
func (s *Service) refuse(ctx context.Context, req Request, reason engine.Reason, detail map[string]any) (Result, error) {
	payload := map[string]any{
		"caller_id":   req.Caller.CallerID(),
		"subject_id":  req.Input.Subject.ID,
		"resource_id": req.Input.Resource.ID,
		"action":      req.Input.Action,
		"reason":      string(reason),
	}
	for k, v := range detail {
		payload[k] = v
	}
	if _, err := s.audit.Append(ctx, store.AuditEntry{
		Kind:    AuditKindDecisionRefused,
		Subject: req.Input.Subject.ID,
		Payload: payload,
	}); err != nil {
		return Result{}, err
	}
	return Result{
		State:       store.DecisionDenied,
		Outcome:     engine.Deny,
		Reason:      reason,
		Obligations: []Obligation{},
	}, nil
}

// refuseShed is [Service.refuse] for a decide whose challenge issuance was shed,
// with the wait the handler asked for attached.
//
// It is a wrapper and not a parameter on refuse because every other refusal this
// service makes is one a caller must not be invited to repeat. An outstanding
// cap clears when another decision closes, not when a timer expires, and a
// policy deny never clears at all — handing either of them a Retry-After would
// tell a PEP to come back and be refused identically, at a cadence this
// deployment chose. Only a shed request has an answer to that question, so only
// this path can carry one.
func (s *Service) refuseShed(ctx context.Context, req Request,
	retryAfter time.Duration, detail map[string]any,
) (Result, error) {
	if detail == nil {
		detail = map[string]any{}
	}
	detail["retry_after_seconds"] = int(math.Ceil(retryAfter.Seconds()))
	out, err := s.refuse(ctx, req, ReasonChallengeRateLimited, detail)
	if err != nil {
		return Result{}, err
	}
	out.RetryAfter = retryAfter
	return out, nil
}

// auditAccessRefusal records a caller turned away from a decision. The error it
// would return is more useful than the one appending could fail with, so a
// failure to audit is reported and the refusal stands.
func (s *Service) auditAccessRefusal(ctx context.Context, caller *identity.Subject, d store.Decision, op string) {
	_, _ = s.audit.Append(ctx, store.AuditEntry{
		Kind:    AuditKindAccessRefused,
		Subject: d.ID,
		Payload: map[string]any{
			"caller_id":   caller.CallerID(),
			"operation":   op,
			"decision_id": d.ID,
		},
	})
}

// countOutstanding counts a subject's unresolved, unexpired decisions (R43).
//
// The expiry test is on expires_at, so a decision that is over but not yet
// swept does not hold a slot. Counting on next_deadline instead would let a
// delay timer look like an outstanding decision that had already ended.
func (s *Service) countOutstanding(ctx context.Context, subjectID string, now time.Time) (int, error) {
	var n int
	err := s.store.Pool().QueryRow(ctx, `
		SELECT count(*) FROM decisions
		WHERE subject_id = $1 AND state = 'pending' AND expires_at > $2`,
		subjectID, now).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("decision: count outstanding decisions of %q: %w", subjectID, err)
	}
	return n, nil
}

func (s *Service) obligationsFor(ctx context.Context, req Request, evaluated engine.DecideResult) ([]Obligation, error) {
	if s.obligations == nil {
		return []Obligation{}, nil
	}
	out, err := s.obligations.ObligationsFor(ctx, ObligationRequest{
		Input:    req.Input,
		PolicyID: evaluated.PolicyID(),
		Gates:    evaluated.Gates(),
	})
	if err != nil {
		return nil, fmt.Errorf("decision: resolve obligations: %w", err)
	}
	if out == nil {
		out = []Obligation{}
	}
	return out, nil
}

// flatten lists a decision's challenges in the order their ordinals are
// assigned: gate order, then declaration order within a gate. Two policies that
// both demand a quorum produce two challenges, and both have to be satisfied.
func flatten(gates []engine.Gated) []policy.Challenge {
	var out []policy.Challenge
	for _, g := range gates {
		out = append(out, g.Challenges()...)
	}
	return out
}

// challengeState and storeChallengeState translate between the contract's
// progress states and the store's. The two sets are identical by construction
// and the translation is deliberately explicit: the challenge contract is under
// semver and must not depend on the persistence layer, so a future divergence
// has to be resolved here rather than by a silent string conversion at a dozen
// call sites.
func challengeState(s store.ChallengeState) challenge.State { return challenge.State(s) }

func storeChallengeState(s challenge.State) store.ChallengeState { return store.ChallengeState(s) }

func contextOf(d store.Decision) challenge.DecisionContext {
	return challenge.DecisionContext{
		DecisionID:   d.ID,
		CallerID:     d.CallerID,
		SubjectID:    d.SubjectID,
		ResourceID:   d.ResourceID,
		Action:       d.Action,
		PolicyID:     d.PolicyID,
		Request:      d.Request,
		FactSnapshot: d.FactSnapshot,
		Obligations:  d.Obligations,
		CreatedAt:    d.CreatedAt,
		ExpiresAt:    d.ExpiresAt,
	}
}

// requestPayload is the shape of the evaluated request that is frozen onto the
// decision row.
func requestPayload(in engine.Input) map[string]any {
	entity := func(e engine.Entity) map[string]any {
		out := map[string]any{"type": e.Type, "id": e.ID}
		if len(e.Attributes) > 0 {
			out["attributes"] = e.Attributes
		}
		return out
	}
	return map[string]any{
		"action":   in.Action,
		"subject":  entity(in.Subject),
		"resource": entity(in.Resource),
		"context":  entity(in.Context),
	}
}

// idempotencyFingerprintBinding is the domain separator in the digest. It is
// there for the reason mfa.ContextBindingContext is there: a digest with no
// label is a digest that can be replayed as some other digest the day this
// repository hashes a second thing shaped like a request.
const idempotencyFingerprintBinding = "stamp/idempotency-fingerprint/v1"

// requestFingerprint is the digest an idempotency key is bound to: what the
// decision the key names was actually about.
//
// **Why a key needs one at all.** The lookup used to compare `(caller, key)` and
// nothing else, and the header's documentation said out loud that the server
// does not compare the key against the request body — without saying what that
// costs. It costs this: a caller reusing `job-91` for a different subject,
// resource or action was handed the first decision back, `201`, `state:
// allowed`, for an authorization this engine had never evaluated. And
// [Result] carries no subject, resource or action, so the PEP had nothing to
// compare either — the substitution was not merely undetected, it was
// undetectable from the answer. A generated key makes this a bug in a client;
// a key derived from something a request carries — an order number, a job id —
// makes it reachable from outside the client, by anyone who can get two
// different requests to name themselves the same way.
//
// **What it covers.** The action, the subject, the resource and the context,
// which is to say [requestPayload] — everything the evaluation read from the
// caller. The evidence is deliberately not in it: facts are resolved by this
// engine and move on their own, so hashing them would turn "the same request,
// asked again" into a mismatch every time a velocity counter ticked, and a
// retry that reports 409 because a fact changed is the orphaned-decision
// failure #47 exists to prevent, wearing a different word.
//
// **Why hashing requestPayload is canonical and not merely convenient.** Two
// requests that mean the same thing have to produce the same digest, or a
// retry of an unchanged request is refused. Three properties make that true and
// all three are load-bearing:
//
//   - encoding/json sorts map keys, so the attribute maps here encode in one
//     order regardless of how the JSON arrived or how Go's map iteration ran;
//   - the values in those maps are not the caller's bytes but the typed values
//     api.attributeValue produced against the declared schema — an int64, a
//     float64, a time.Time in UTC — so `25000`, `25000.0` and `2.5e4` for a
//     declared int all arrive here as one value and hash alike;
//   - an attribute the schema does not declare never reaches this function,
//     having been dropped at the surface, so a caller cannot move the digest
//     with a field the policy could not read.
//
// What the third property costs is worth stating: two requests that differ only
// in an undeclared property are one request to this digest, and the second is
// answered with the first's decision. That is correct — they are one request to
// the evaluation too, which is the thing the decision froze — but it is only
// correct as long as the fingerprint is computed from the evaluated input and
// never from the raw body.
//
// The one shape that is not canonical is a `double` attribute, where a caller
// writing `1.0` and `1` produces the same float64 and hashes alike, but
// `0.1+0.2` and `0.3` do not. That is float equality, it is the same answer the
// policy evaluation gives, and a fingerprint that disagreed with the evaluator
// about whether two requests are the same would be the worse failure.
func requestFingerprint(in engine.Input) string {
	// mustJSON and not json.Marshal-with-error, on the same reasoning: the value
	// hashed here is the value about to be frozen onto the row by the same call,
	// so an encoding failure would have to be a failure that happens exactly
	// once. If it ever did, mustJSON's `{}` would make every request hash alike,
	// so the binding label is not enough on its own — the digest covers the
	// encoded bytes and the length of them.
	payload := mustJSON(requestPayload(in))
	h := sha256.New()
	h.Write([]byte(idempotencyFingerprintBinding))
	h.Write([]byte{0x1f})
	h.Write([]byte(strconv.Itoa(len(payload))))
	h.Write([]byte{0x1f})
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// fingerprintFor pairs a fingerprint with the key it qualifies: a decision
// nobody named carries neither.
//
// The two columns are NULL together or set together, and the schema says so as
// a CHECK — see migration 000008. A row with a key and no fingerprint is a row
// the lookup cannot answer for, and this is the one place that could have
// written one.
func fingerprintFor(key, fingerprint string) string {
	if key == "" {
		return ""
	}
	return fingerprint
}

// sameRequest reports whether a stored decision is the one a key names.
//
// It is fail-closed on a stored decision that carries a key and no fingerprint.
// Such a row cannot be proved to name this request, and "cannot prove" has to
// answer the same way as "proved different": the alternative is that a row
// written before the fingerprint existed becomes a row where the substitution
// still works, which is a hole with a shape an attacker can look for.
//
// Nothing can be in that state. The key column, the fingerprint column and the
// unique index arrived unreleased in migrations 8 and 9, so there is no
// deployment where a keyed decision was written by a binary that did not compute
// a fingerprint, and the CHECK makes one unwritable from now on. The branch is
// here because a security property that rests on "no such row exists" should
// still be safe on the day one does.
func sameRequest(stored store.Decision, fingerprint string) bool {
	if stored.IdempotencyFingerprint == "" {
		return false
	}
	// Not constant time, deliberately. Both sides are digests of values this
	// caller already holds — it sent one of them and created the other — so
	// there is no secret here to leak the comparison of, and subtle.ConstantTimeCompare
	// where it buys nothing is how the next reader learns to distrust the places
	// it does buy something.
	return stored.IdempotencyFingerprint == fingerprint
}

// keyReused is the refusal a spent key gets.
//
// The message names the key and not the decision. Which decision the key already
// holds is something the caller is entitled to know — it created that decision —
// but it learns it by asking with the request that key names, not by sending a
// different one; and an identifier in an error string is an identifier in every
// log that error reaches, on a path whose whole subject is a caller confusing
// two requests for each other.
func keyReused(req Request, existing store.Decision) error {
	return fmt.Errorf("%w: caller %q used key %q for %s on %s, and it names %s on %s",
		ErrIdempotencyKeyReused, req.Caller.CallerID(), req.IdempotencyKey,
		req.Input.Action, req.Input.Resource.ID, existing.Action, existing.ResourceID)
}

func decodeObligations(raw json.RawMessage) ([]Obligation, error) {
	if len(raw) == 0 {
		return []Obligation{}, nil
	}
	var out []Obligation
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decision: decode obligations: %w", err)
	}
	if out == nil {
		out = []Obligation{}
	}
	return out, nil
}

// mustJSON encodes a value that has already been accepted elsewhere in the same
// call. An encoding failure here would mean the same value failed to encode
// twice in two different places, so it is reported as an empty object rather
// than propagated: the challenge context is informational, and losing the whole
// decision over it would be the worse trade.
func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("{}")
	}
	return raw
}
