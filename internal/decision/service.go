package decision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
)

// Audit kinds this package appends. The store's set is open; these names are
// stable because an operator alerts on them.
const (
	// AuditKindDecisionRefused records a decide that produced no decision
	// object: a deny with no policy to pin a row to, or a refusal under the
	// outstanding-decision cap. R43 requires the refusal itself to be audited,
	// and a refusal that leaves no trace is indistinguishable from a request
	// that was never made.
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
		ID:            id,
		CallerID:      req.Caller.CallerID(),
		PolicyID:      policyID,
		PolicyVersion: version,
		SubjectID:     req.Input.Subject.ID,
		ResourceID:    req.Input.Resource.ID,
		Action:        req.Input.Action,
		Request:       requestPayload(req.Input),
		FactSnapshot:  factSnapshot,
		Obligations:   obligations,
		ExpiresAt:     expiresAt,
		Challenges:    opened,
	})
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
func (s *Service) Submit(ctx context.Context, sub Submission) (Result, error) {
	if sub.Caller == nil {
		return Result{}, ErrUnauthenticated
	}
	now := s.Now()

	d, err := s.store.ActiveDecision(ctx, sub.DecisionID)
	if err != nil {
		return Result{}, err
	}
	if d.State != store.DecisionPending {
		return Result{}, fmt.Errorf("decision %q is %s: %w", d.ID, d.State, ErrNotPending)
	}

	progress, err := store.ChallengeProgressFor(ctx, s.store.Pool(), d.ID)
	if err != nil {
		return Result{}, err
	}
	var target *store.ChallengeProgress
	for i := range progress {
		if progress[i].Ordinal == sub.Ordinal {
			target = &progress[i]
			break
		}
	}
	if target == nil {
		return Result{}, fmt.Errorf("decision %q has no challenge %d: %w", d.ID, sub.Ordinal, ErrNoSuchChallenge)
	}
	if challengeState(target.State) != challenge.StatePending {
		return Result{}, fmt.Errorf("challenge %d of decision %q is %s: %w",
			sub.Ordinal, d.ID, target.State, ErrNotPending)
	}
	if target.Deadline != nil && !now.Before(*target.Deadline) {
		return Result{}, fmt.Errorf("challenge %d of decision %q closed at %s: %w",
			sub.Ordinal, d.ID, target.Deadline, store.ErrDecisionExpired)
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
		case challenge.StatePending:
		}
	}

	switch {
	case failed > 0:
		if _, err := s.resolve(ctx, d, Fail, ReasonChallengeFailed); err != nil {
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
