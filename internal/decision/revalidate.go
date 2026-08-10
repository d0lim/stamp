package decision

// revalidate.go is the effect hook a policy revision runs when it takes effect.
//
// Four rules hold it together, and every one of them is a requirement rather
// than a design preference.
//
// The author picks the mode and the default is revaluation (D5, R5). Silence
// must not mean "let the old rules finish", because in a compliance domain a
// policy is usually tightened in response to something that already happened.
//
// Revaluation reuses the fact snapshot the decision froze at creation and does
// not re-fetch a single source. Re-fetching would move the snapshot, the
// snapshot is an input to the approval binding hash, and so re-fetching would
// invalidate every approval on every revision — which would leave D5's promise
// of preserving valid approvals promising nothing. The one exception is a new
// policy that reaches a source the snapshot never held: that source alone is
// fetched and added, and the hash then differs, so the approvals are all
// recollected.
//
// Approvals survive only when the binding hash is unchanged (R31). The check is
// [PreservesApprovals] and it is fail-closed in every direction: an absent
// digest, a malformed digest, an unreadable detail and a differing digest all
// invalidate.
//
// Every write here happens inside the caller's transaction, alongside the policy
// writes that caused it. A revision that took effect in one transaction and
// revalidated in another would leave a window in which a decision resolves under
// a policy that is no longer in force — the window D10 rejected git-as-store to
// avoid.
//
// The fourth rule is the one the challenge kinds add: re-issuing a challenge is
// not a neutral way to bring it up to date. It is neutral for a quorum and for
// nothing else. See [Revalidator.rebindChallenges].

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/challenge/mfa"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// Audit kinds the revision effect hook appends.
const (
	// AuditKindGrandfathered records a pending decision left to finish under the
	// policy version it was created against.
	AuditKindGrandfathered = "decision.grandfathered"

	// AuditKindRevalidated records a pending decision re-judged against a newly
	// effective policy set.
	AuditKindRevalidated = "decision.revalidated"

	// AuditKindApprovalsInvalidated records approvals dropped because the
	// material they were bound to changed.
	AuditKindApprovalsInvalidated = "decision.approvals.invalidated"
)

// ReasonRevisionUnmet is the ground for a decision denied because a revision
// left its condition unsatisfied.
const ReasonRevisionUnmet engine.Reason = "revision_condition_not_met"

// ErrRevalidation reports a failure while applying a revision to pending
// decisions.
var ErrRevalidation = errors.New("decision: revalidating a pending decision")

// ApplicationMode is the author's choice of what a revision does to the
// decisions that are already open (R5).
type ApplicationMode string

// The application modes.
const (
	// ModeRevaluate re-judges every pending decision against the new policy set.
	// It is the default.
	ModeRevaluate ApplicationMode = "revaluate"

	// ModeGrandfather leaves pending decisions to finish under the version they
	// were created against. It has to be chosen explicitly.
	ModeGrandfather ApplicationMode = "grandfather"
)

// ApplicationModes returns every mode, in declaration order.
func ApplicationModes() []ApplicationMode { return []ApplicationMode{ModeRevaluate, ModeGrandfather} }

// Valid reports whether m is a declared mode. The empty mode is valid and means
// the default.
func (m ApplicationMode) Valid() bool {
	if m == "" {
		return true
	}
	for _, known := range ApplicationModes() {
		if m == known {
			return true
		}
	}
	return false
}

// OrDefault resolves the empty mode to revaluation.
func (m ApplicationMode) OrDefault() ApplicationMode {
	if m == "" {
		return ModeRevaluate
	}
	return m
}

// PreservesApprovals reports whether approvals collected under one set of
// challenge terms survive a revision that re-issued the challenge.
//
// The comparison is over the binding hash and nothing else, because the hash is
// the statement "this is the material the approver read" (R31). Everything that
// is not a well-formed digest present on both sides is treated as a change: an
// absent digest binds nothing, and two equal strings that are not digests are
// not evidence that the material held still. The failure modes are not
// symmetric — invalidating wrongly costs a second round of approvals, preserving
// wrongly is an authorization nobody gave.
func PreservesApprovals(stored, reissued json.RawMessage) (bool, error) {
	before, err := bindingHashOf(stored)
	if err != nil {
		return false, err
	}
	after, err := bindingHashOf(reissued)
	if err != nil {
		return false, err
	}
	if before == "" || after == "" {
		return false, nil
	}
	return before == after, nil
}

// bindingHashOf reads a challenge detail's binding hash, returning the empty
// string when there is not a well-formed one.
func bindingHashOf(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var detail struct {
		BindingHash string `json:"binding_hash"`
	}
	if err := json.Unmarshal(raw, &detail); err != nil {
		return "", fmt.Errorf("%w: reading a challenge detail: %w", ErrRevalidation, err)
	}
	value := detail.BindingHash
	if len(value) != 2*sha256Size {
		return "", nil
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", nil
	}
	return strings.ToLower(value), nil
}

// sha256Size is the digest length the binding hash is required to have. A
// shorter or longer value is not a truncated digest to be compared leniently;
// it is not a digest.
const sha256Size = 32

// RevalidatorConfig configures a [Revalidator].
type RevalidatorConfig struct {
	// Challenges maps challenge kinds to handlers. Required: a re-issued
	// challenge's terms, including its binding hash, come from the handler that
	// owns the kind rather than from a second implementation here.
	Challenges *challenge.Registry

	// Obligations produces the obligation list for a re-judged decision. Nil
	// means no obligations.
	Obligations ObligationSource

	// Now is the clock. Nil uses time.Now.
	Now func() time.Time
}

// Revalidator applies a policy revision to the decisions that are still open.
type Revalidator struct {
	challenges  *challenge.Registry
	obligations ObligationSource
	now         func() time.Time
}

// NewRevalidator builds the effect hook.
func NewRevalidator(cfg RevalidatorConfig) (*Revalidator, error) {
	if cfg.Challenges == nil {
		return nil, errors.New("decision: a revalidator needs the challenge registry")
	}
	r := &Revalidator{challenges: cfg.Challenges, obligations: cfg.Obligations, now: cfg.Now}
	if r.now == nil {
		r.now = time.Now
	}
	return r, nil
}

// PolicyVersionAt reports the stored version of a policy inside the caller's
// transaction. Revalidation runs in the same transaction as the writes that
// created those versions, so it cannot read them through the pool.
type PolicyVersionAt func(ctx context.Context, q store.Querier, policyID string) (int64, error)

// RevalidateRequest is one application of a revision to the open decisions.
type RevalidateRequest struct {
	// Mode is the author's choice. The empty mode is revaluation.
	Mode ApplicationMode

	// Snapshot is the newly effective policy set.
	Snapshot *engine.Snapshot

	// Resolver fetches a source the frozen snapshot does not hold. It is not
	// consulted for anything the snapshot already answers, and a nil resolver
	// makes a newly referenced source a fail-closed deny rather than a silent
	// omission.
	Resolver engine.SourceResolver

	// PolicyVersion pins the version a re-judged decision records.
	PolicyVersion PolicyVersionAt

	// RevisionID names the revision in the audit trail.
	RevisionID string

	// Skip excludes decisions by the policy they were created against. The
	// governance decision that carries the revision is excluded through it:
	// re-judging a revision's own decision under the revision it is deciding is
	// circular.
	Skip func(policyID string) bool

	// Now is the instant expiry is judged against.
	Now time.Time
}

// Outcome is what a revision did to one open decision.
type Outcome struct {
	DecisionID  string   `json:"decision_id"`
	Disposition string   `json:"disposition"`
	Invalidated int      `json:"approvals_invalidated,omitempty"`
	Fetched     []string `json:"sources_fetched,omitempty"`
}

// The dispositions a revision can hand a pending decision.
const (
	DispositionGrandfathered = "grandfathered"
	DispositionUnchanged     = "unchanged"
	DispositionRebound       = "rebound"
	DispositionResolved      = "resolved"
	DispositionDenied        = "denied"
)

// RevalidateReport summarizes what the revision did.
type RevalidateReport struct {
	Mode        ApplicationMode `json:"mode"`
	Considered  int             `json:"considered"`
	Denied      int             `json:"denied"`
	Invalidated int             `json:"approvals_invalidated"`
	Fetched     []string        `json:"sources_fetched,omitempty"`
	Outcomes    []Outcome       `json:"outcomes,omitempty"`
}

// Apply runs the effect hook inside the caller's transaction.
func (r *Revalidator) Apply(ctx context.Context, tx pgx.Tx, ap *store.Appender, req RevalidateRequest) (RevalidateReport, error) {
	mode := req.Mode.OrDefault()
	if !mode.Valid() {
		return RevalidateReport{}, fmt.Errorf("%w: unknown application mode %q", ErrRevalidation, req.Mode)
	}
	now := req.Now
	if now.IsZero() {
		now = r.now().UTC()
	}
	report := RevalidateReport{Mode: mode}

	open, err := openDecisions(ctx, tx, now)
	if err != nil {
		return RevalidateReport{}, err
	}
	fetched := map[string]struct{}{}
	for i := range open {
		d := open[i]
		if req.Skip != nil && req.Skip(d.PolicyID) {
			continue
		}
		report.Considered++
		if mode == ModeGrandfather {
			if err := r.grandfather(ctx, ap, d, req.RevisionID); err != nil {
				return RevalidateReport{}, err
			}
			report.Outcomes = append(report.Outcomes,
				Outcome{DecisionID: d.ID, Disposition: DispositionGrandfathered})
			continue
		}
		outcome, err := r.revaluate(ctx, tx, ap, d, req, now)
		if err != nil {
			return RevalidateReport{}, err
		}
		for _, name := range outcome.Fetched {
			fetched[name] = struct{}{}
		}
		report.Invalidated += outcome.Invalidated
		if outcome.Disposition == DispositionDenied {
			report.Denied++
		}
		report.Outcomes = append(report.Outcomes, outcome)
	}
	for name := range fetched {
		report.Fetched = append(report.Fetched, name)
	}
	sort.Strings(report.Fetched)
	return report, nil
}

// grandfather records that a decision was left alone.
//
// The audit row is the whole of the work: the decision keeps the policy version
// it pinned at creation, which is what "grandfather" means, and the record is
// what makes the choice visible afterwards rather than inferable from the
// absence of a change.
func (r *Revalidator) grandfather(ctx context.Context, ap *store.Appender, d store.Decision, revisionID string) error {
	_, err := ap.Append(ctx, store.AuditEntry{
		Kind:    AuditKindGrandfathered,
		Subject: d.ID,
		Payload: map[string]any{
			"revision_id":      revisionID,
			"application_mode": string(ModeGrandfather),
			"policy_id":        d.PolicyID,
			"policy_version":   d.PolicyVersion,
		},
	})
	return err
}

// revaluate re-judges one decision against the newly effective set.
func (r *Revalidator) revaluate(ctx context.Context, tx pgx.Tx, ap *store.Appender,
	d store.Decision, req RevalidateRequest, now time.Time,
) (Outcome, error) {
	out := Outcome{DecisionID: d.ID}
	schema := req.Snapshot.Schema()

	in, err := restoreInput(schema, d.Request)
	if err != nil {
		return r.deny(ctx, tx, ap, d, req, fmt.Sprintf("the frozen request could not be re-bound: %v", err))
	}

	frozen, err := newFrozenFacts(schema, d.FactSnapshot, req.Resolver)
	if err != nil {
		return Outcome{}, err
	}
	evaluated, err := engine.NewDecideEvaluator(req.Snapshot,
		engine.WithSourceResolver(frozen)).Evaluate(ctx, in)
	out.Fetched = frozen.fetchedNames()
	if err != nil {
		return r.deny(ctx, tx, ap, d, req, fmt.Sprintf("the revised policy set could not be evaluated: %v", err))
	}
	if evaluated.Decision() == engine.Deny {
		return r.deny(ctx, tx, ap, d, req, "the revised policy set no longer allows this request: "+string(evaluated.Reason()))
	}

	// The snapshot only moves when a newly referenced source had to be fetched,
	// and then it moves by exactly those values.
	factSnapshot := d.FactSnapshot
	if len(out.Fetched) > 0 {
		factSnapshot, err = frozen.merged(d.FactSnapshot)
		if err != nil {
			return Outcome{}, err
		}
	}

	policyID := evaluated.PolicyID()
	version := d.PolicyVersion
	if req.PolicyVersion != nil {
		version, err = req.PolicyVersion(ctx, tx, policyID)
		if err != nil {
			return Outcome{}, fmt.Errorf("%w: pinning %q: %w", ErrRevalidation, policyID, err)
		}
	}

	obligations, err := r.obligationsFor(ctx, in, evaluated)
	if err != nil {
		return Outcome{}, err
	}
	obligationsJSON, err := json.Marshal(obligations)
	if err != nil {
		return Outcome{}, fmt.Errorf("%w: encoding obligations: %w", ErrRevalidation, err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE decisions
		SET policy_id = $2, policy_version = $3, fact_snapshot = $4, obligations = $5, updated_at = now()
		WHERE id = $1 AND state = 'pending'`,
		d.ID, policyID, version, []byte(factSnapshot), obligationsJSON); err != nil {
		return Outcome{}, fmt.Errorf("%w: rewriting decision %q: %w", ErrRevalidation, d.ID, err)
	}
	d.PolicyID, d.PolicyVersion = policyID, version
	d.FactSnapshot, d.Obligations = factSnapshot, obligationsJSON

	rebound, invalidated, err := r.rebindChallenges(ctx, tx, ap, d, flatten(evaluated.Gates()), req, now)
	if err != nil {
		return Outcome{}, err
	}
	out.Invalidated = invalidated

	total, satisfied, failed, err := challengeTally(ctx, tx, d.ID)
	if err != nil {
		return Outcome{}, err
	}
	switch {
	case failed > 0:
		// A challenge the rebinding could not carry forward — an external round
		// trip a revision pointed somewhere else — denies here rather than
		// waiting for the sweeper. The sweeper would get there, because a failed
		// challenge fails the decision on the next advance, but a revision that
		// left a decision provably doomed sitting pending is a decision whose
		// caller is still waiting for an answer this transaction already knows.
		if err := r.resolve(ctx, tx, ap, d, Fail, ReasonChallengeFailed, req.RevisionID); err != nil {
			return Outcome{}, err
		}
		out.Disposition = DispositionDenied
	case total == satisfied:
		if err := r.resolve(ctx, tx, ap, d, Satisfy, ReasonChallengeSatisfied, req.RevisionID); err != nil {
			return Outcome{}, err
		}
		out.Disposition = DispositionResolved
	case rebound:
		out.Disposition = DispositionRebound
	default:
		out.Disposition = DispositionUnchanged
	}

	_, err = ap.Append(ctx, store.AuditEntry{
		Kind:    AuditKindRevalidated,
		Subject: d.ID,
		Payload: map[string]any{
			"revision_id":           req.RevisionID,
			"application_mode":      string(ModeRevaluate),
			"policy_id":             policyID,
			"policy_version":        version,
			"disposition":           out.Disposition,
			"approvals_invalidated": invalidated,
			"sources_fetched":       out.Fetched,
		},
	})
	return out, err
}

// deny resolves a decision whose condition no longer holds under the revision.
func (r *Revalidator) deny(ctx context.Context, tx pgx.Tx, ap *store.Appender,
	d store.Decision, req RevalidateRequest, detail string,
) (Outcome, error) {
	if err := r.resolve(ctx, tx, ap, d, Revalidate, ReasonRevisionUnmet, req.RevisionID); err != nil {
		return Outcome{}, err
	}
	_, err := ap.Append(ctx, store.AuditEntry{
		Kind:    AuditKindRevalidated,
		Subject: d.ID,
		Payload: map[string]any{
			"revision_id":      req.RevisionID,
			"application_mode": string(ModeRevaluate),
			"disposition":      DispositionDenied,
			"detail":           detail,
		},
	})
	return Outcome{DecisionID: d.ID, Disposition: DispositionDenied}, err
}

// resolve writes a terminal state inside the caller's transaction.
//
// It restates the store's ResolveDecision rather than calling it, and the reason
// is structural: an audit writer serializes its appends behind a mutex it holds
// for the whole audited transaction, so calling a method that opens its own
// transaction from inside one would deadlock against the writer this Appender
// belongs to. The legality of the edge still comes from [Next], which is the
// part that must not be restated.
func (r *Revalidator) resolve(ctx context.Context, tx pgx.Tx, ap *store.Appender,
	d store.Decision, t Transition, reason engine.Reason, revisionID string,
) error {
	next, err := Next(d.State, t)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE decisions
		SET state = $2, resolved_at = now(), updated_at = now(),
		    next_deadline = NULL, next_deadline_kind = NULL
		WHERE id = $1 AND state = 'pending'`, d.ID, string(next))
	if err != nil {
		return fmt.Errorf("%w: resolving decision %q: %w", ErrRevalidation, d.ID, err)
	}
	if tag.RowsAffected() == 0 {
		// Somebody else resolved it between the claim and here. That is the
		// expected outcome of two writers meeting, not a fault.
		return nil
	}
	_, err = ap.Append(ctx, store.AuditEntry{
		Kind:    store.AuditKindDecisionResolved,
		Subject: d.ID,
		Payload: map[string]any{
			"state":       string(next),
			"actor":       string(t.Trigger()) + ":" + string(reason),
			"revision_id": revisionID,
			"obligations": d.Obligations,
		},
	})
	return err
}

// rebindChallenges brings a decision's challenges up to the revised policy's
// terms and drops the approvals that no longer bind.
//
// When the shape of the challenge list changes — a different kind at an ordinal,
// or a different number of them — every progress row is rebuilt and every
// approval goes with it. There is no correspondence to preserve in that case,
// and inventing one is how an approval collected for a quorum ends up counted
// toward a challenge nobody approved. A rebuilt list does restart timers, and
// that is correct: a decision whose challenge list changed is on genuinely
// different terms.
//
// When the shape holds, each kind is re-bound by its own rule, and the rules do
// not generalize. Only a quorum may be re-issued freely, because issuing one is
// pure. Re-issuing the other three has a side effect the subject can see: an mfa
// re-issue rotates a correlator somebody is holding, a delay re-issue restarts a
// wait that has been partly served, and an external re-issue posts a second
// webhook — from inside this transaction, while it holds a row lock on every
// open decision. So the switch below is not a dispatch table over four
// interchangeable cases; it is four different answers to "what does a revision
// do to work already in flight".
func (r *Revalidator) rebindChallenges(ctx context.Context, tx pgx.Tx, ap *store.Appender,
	d store.Decision, specs []policy.Challenge, req RevalidateRequest, now time.Time,
) (bool, int, error) {
	stored, err := store.ChallengeProgressFor(ctx, tx, d.ID)
	if err != nil {
		return false, 0, err
	}
	decisionCtx := contextOf(d)

	if !sameShape(stored, specs) {
		return r.reopenChallenges(ctx, tx, ap, d, decisionCtx, specs, req, now)
	}

	rebound, invalidated, timerMoved := false, 0, false
	for ordinal, spec := range specs {
		in := rebind{
			decision: d,
			context:  decisionCtx,
			ordinal:  ordinal,
			spec:     spec,
			stored:   stored[ordinal],
			revision: req.RevisionID,
			now:      now,
		}
		var out rebound1
		switch spec.ChallengeType() {
		case policy.ChallengeQuorum:
			out, err = r.rebindQuorum(ctx, tx, ap, in)
		case policy.ChallengeMFA:
			out, err = r.rebindMFA(ctx, tx, in)
		case policy.ChallengeDelay:
			out, err = r.rebindDelay(ctx, tx, in)
		case policy.ChallengeExternal:
			out, err = r.rebindExternal(ctx, tx, in)
		default:
			// A kind with no rule here is a kind nobody decided what a revision
			// does to. Leaving it alone would be a decision made by omission, so
			// it stops the revision instead.
			err = fmt.Errorf("%w: %s carries no rebinding rule", ErrRevalidation, in.instance())
		}
		if err != nil {
			return false, 0, err
		}
		rebound = rebound || out.changed
		invalidated += out.invalidated
		timerMoved = timerMoved || out.timerMoved
	}
	if timerMoved {
		if err := store.RefreshNextDeadline(ctx, tx, d.ID); err != nil {
			return false, 0, err
		}
	}
	return rebound, invalidated, nil
}

// rebind is one challenge's rebinding input. It is a struct because the four
// rules take almost the same arguments and a seven-parameter signature repeated
// four times is four places to get the order wrong.
type rebind struct {
	decision store.Decision
	context  challenge.DecisionContext
	ordinal  int
	spec     policy.Challenge
	stored   store.ChallengeProgress
	revision string
	now      time.Time
}

func (in rebind) instance() challenge.Instance {
	return challenge.Instance{
		DecisionID: in.decision.ID, Ordinal: in.ordinal, Kind: in.spec.ChallengeType(),
	}
}

// rebound1 is what one rebinding did.
type rebound1 struct {
	// changed reports that the stored row moved.
	changed bool
	// invalidated counts approvals dropped.
	invalidated int
	// timerMoved reports that the row's deadline column was rewritten, so the
	// decision's scheduler column has to be recomputed.
	timerMoved bool
}

// reopenChallenges rebuilds every progress row from scratch.
func (r *Revalidator) reopenChallenges(ctx context.Context, tx pgx.Tx, ap *store.Appender,
	d store.Decision, decisionCtx challenge.DecisionContext, specs []policy.Challenge,
	req RevalidateRequest, now time.Time,
) (bool, int, error) {
	invalidated, err := countApprovalsOf(ctx, tx, d.ID)
	if err != nil {
		return false, 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM challenge_progress WHERE decision_id = $1`, d.ID); err != nil {
		return false, 0, fmt.Errorf("%w: clearing challenges of %q: %w", ErrRevalidation, d.ID, err)
	}
	for ordinal, spec := range specs {
		if err := r.issue(ctx, tx, d, decisionCtx, ordinal, spec, now); err != nil {
			return false, 0, err
		}
	}
	// The rebuilt rows carry their own timers, and the decision's scheduler
	// column summarizes them. Without this the sweeper would wake for the
	// deadline of a challenge that no longer exists.
	if err := store.RefreshNextDeadline(ctx, tx, d.ID); err != nil {
		return false, 0, err
	}
	if invalidated > 0 {
		if err := auditInvalidation(ctx, ap, d.ID, -1, invalidated,
			"the revision changed which challenges this decision carries", req.RevisionID); err != nil {
			return false, 0, err
		}
	}
	return true, invalidated, nil
}

// rebindQuorum re-issues a quorum and keeps the approvals whose binding hash
// survived (R31).
//
// Re-issuing is safe here and nowhere else in this file: opening a quorum
// resolves an approver set and computes a hash, and does nothing a person or
// another system can observe.
func (r *Revalidator) rebindQuorum(ctx context.Context, tx pgx.Tx, ap *store.Appender, in rebind) (rebound1, error) {
	detail, err := r.reissue(ctx, in)
	if err != nil {
		return rebound1{}, err
	}
	preserved, err := PreservesApprovals(in.stored.Detail, detail)
	if err != nil {
		return rebound1{}, err
	}
	if preserved && string(in.stored.Detail) == string(detail) {
		return rebound1{}, nil
	}

	dropped := 0
	if !preserved {
		dropped, err = dropApprovals(ctx, tx, in.decision.ID, in.ordinal)
		if err != nil {
			return rebound1{}, err
		}
	}
	state, err := quorumStateAfter(ctx, tx, in.decision.ID, in.ordinal, detail)
	if err != nil {
		return rebound1{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE challenge_progress
		SET detail = $3, state = $4,
		    satisfied_at = CASE WHEN $4 = 'satisfied' THEN satisfied_at ELSE NULL END
		WHERE decision_id = $1 AND ordinal = $2`,
		in.decision.ID, in.ordinal, detail, string(state)); err != nil {
		return rebound1{}, fmt.Errorf("%w: rebinding %s: %w", ErrRevalidation, in.instance(), err)
	}
	if !preserved {
		if err := auditInvalidation(ctx, ap, in.decision.ID, in.ordinal, dropped,
			"the approval binding hash changed", in.revision); err != nil {
			return rebound1{}, err
		}
	}
	return rebound1{changed: true, invalidated: dropped}, nil
}

// rebindMFA leaves a step-up alone unless the revision moved what it is asking
// about.
//
// Two questions decide it, and both have to answer yes for the row to be left
// as it is. Does the decision still hash to what it hashed to at issue — the
// question U10 exported [mfa.PreservesCompletion] for. And does the policy still
// ask for the classes the challenge was opened under, which the hash cannot see
// because `acr_values` is not decision content.
//
// The reason for leaving it alone rather than re-issuing on the safe side is
// that a re-issue is not free: it rotates the correlator, which strands a
// step-up the subject already has open in another tab, and it moves IssuedAt,
// which is the lower bound an `auth_time` has to beat — so an authentication
// already in flight would come back too old to count. A satisfied step-up stays
// satisfied; a pending one keeps the prompt somebody is looking at.
//
// The `acr_values` question is answered by re-issuing rather than by patching
// the stored detail, and in that direction for both a tightened and a loosened
// requirement. Tightened, leaving the row would let an authentication the policy
// no longer accepts satisfy the challenge. Loosened, leaving it would ask the
// subject for a class nobody declared, which at worst is a challenge that cannot
// be met at all. The handler's own re-issue suppression is keyed on the class
// lists as well as the context hash, so a genuinely unchanged requirement inside
// the suppression window still costs no prompt.
func (r *Revalidator) rebindMFA(ctx context.Context, tx pgx.Tx, in rebind) (rebound1, error) {
	spec, ok := in.spec.(policy.MFA)
	if !ok {
		return rebound1{}, fmt.Errorf("%w: %s is declared %T", ErrRevalidation, in.instance(), in.spec)
	}
	// Fail closed in the same direction PreservesApprovals does: a detail this
	// build cannot read stops the revision rather than being re-issued over.
	bound, err := mfa.PreservesCompletion(in.stored.Detail, in.context)
	if err != nil {
		return rebound1{}, fmt.Errorf("%w: %s: %w", ErrRevalidation, in.instance(), err)
	}
	if bound {
		asked, rerr := mfa.PreservesRequirement(in.stored.Detail, spec)
		if rerr != nil {
			return rebound1{}, fmt.Errorf("%w: %s: %w", ErrRevalidation, in.instance(), rerr)
		}
		if asked {
			return rebound1{}, nil
		}
	}

	detail, err := r.reissue(ctx, in)
	if err != nil {
		return rebound1{}, err
	}
	if string(in.stored.Detail) == string(detail) {
		return rebound1{}, nil
	}
	// A fresh issue carries no consumption, so writing it is what clears the
	// spent correlator; the state goes back with it, because a satisfaction
	// recorded against material nobody is being asked about any more is not a
	// satisfaction.
	if _, err := tx.Exec(ctx, `
		UPDATE challenge_progress
		SET detail = $3, state = 'pending', satisfied_at = NULL
		WHERE decision_id = $1 AND ordinal = $2`,
		in.decision.ID, in.ordinal, detail); err != nil {
		return rebound1{}, fmt.Errorf("%w: rebinding %s: %w", ErrRevalidation, in.instance(), err)
	}
	return rebound1{changed: true}, nil
}

// rebindDelay adjusts a running wait without ever restarting it.
//
// [Delay.Issue] computes ReleaseAt as now plus the declared duration, so calling
// it here would restart a wait the subject has already partly served — on every
// revaluation, including revisions that had nothing to do with this decision.
// The wait's start is therefore recovered from what the detail already froze:
// ReleaseAt minus the duration it was opened under. A revised duration is
// measured from that instant, never from now. Shortening a two-hour wait to one
// hour ninety minutes in ends it; `now + newDuration` would have added another
// hour to a wait that was already over.
//
// The cancellation authority is re-resolved and rewritten on its own, leaving
// the release instant and any recorded cancellation exactly where they are. A
// revision may change who could have stopped a wait. It may not un-stop one.
func (r *Revalidator) rebindDelay(ctx context.Context, tx pgx.Tx, in rebind) (rebound1, error) {
	spec, ok := in.spec.(policy.Delay)
	if !ok {
		return rebound1{}, fmt.Errorf("%w: %s is declared %T", ErrRevalidation, in.instance(), in.spec)
	}
	if spec.Duration <= 0 {
		return rebound1{}, fmt.Errorf("%w: %s: a delay of %s is not a wait",
			ErrRevalidation, in.instance(), spec.Duration)
	}
	stored, err := challenge.DecodeDelayDetail(in.stored.Detail)
	if err != nil {
		return rebound1{}, fmt.Errorf("%w: %s: %w", ErrRevalidation, in.instance(), err)
	}
	opened, err := time.ParseDuration(stored.Duration)
	if err != nil {
		// Without the duration it was opened under there is no way to find the
		// instant the wait started, and every alternative — restarting it,
		// leaving it, guessing — is a wait of the wrong length.
		return rebound1{}, fmt.Errorf("%w: %s: the stored wait records duration %q: %w",
			ErrRevalidation, in.instance(), stored.Duration, err)
	}

	next := stored
	timerMoved := false
	if opened != spec.Duration {
		issuedAt := stored.ReleaseAt.Add(-opened)
		next.ReleaseAt = issuedAt.Add(spec.Duration)
		next.Duration = spec.Duration.String()
		timerMoved = true
	}
	authorityMoved, err := r.rebindCancelAuthority(ctx, &next, spec, in)
	if err != nil {
		return rebound1{}, err
	}
	if !timerMoved && !authorityMoved {
		return rebound1{}, nil
	}

	detail, err := json.Marshal(next)
	if err != nil {
		return rebound1{}, fmt.Errorf("%w: encoding the rebound detail for %s: %w",
			ErrRevalidation, in.instance(), err)
	}
	if !timerMoved {
		// Only the authority moved. The timer column and the state are not
		// touched at all, so there is nothing here that could end a wait early
		// or walk a recorded cancellation back.
		if _, err := tx.Exec(ctx, `
			UPDATE challenge_progress SET detail = $3 WHERE decision_id = $1 AND ordinal = $2`,
			in.decision.ID, in.ordinal, detail); err != nil {
			return rebound1{}, fmt.Errorf("%w: rebinding %s: %w", ErrRevalidation, in.instance(), err)
		}
		return rebound1{changed: true}, nil
	}

	// The state comes from the handler rather than from a comparison here: a
	// release instant that has arrived means satisfied for a delay and failed
	// for everything else, and only the handler knows which it is. A recorded
	// cancellation is terminal and Status does not walk it back.
	deadline := next.ReleaseAt
	state, err := r.statusOf(ctx, in, detail, &deadline)
	if err != nil {
		return rebound1{}, err
	}
	stamped := deadline
	if stamped.After(in.decision.ExpiresAt) {
		// A challenge may not outlive the decision it hangs off, and a revision
		// does not extend a decision's own expiry. The detail keeps the truthful
		// release instant; the scheduler column keeps the earlier of the two.
		stamped = in.decision.ExpiresAt
	}
	if _, err := tx.Exec(ctx, `
		UPDATE challenge_progress
		SET detail = $3, deadline = $4, state = $5,
		    satisfied_at = CASE WHEN $5 = 'satisfied' THEN COALESCE(satisfied_at, now()) ELSE NULL END
		WHERE decision_id = $1 AND ordinal = $2`,
		in.decision.ID, in.ordinal, detail, stamped, string(storeChallengeState(state))); err != nil {
		return rebound1{}, fmt.Errorf("%w: rebinding %s: %w", ErrRevalidation, in.instance(), err)
	}
	return rebound1{changed: true, timerMoved: true}, nil
}

// rebindCancelAuthority re-resolves a delay's cancellation authority and reports
// whether it moved.
func (r *Revalidator) rebindCancelAuthority(ctx context.Context, detail *challenge.DelayDetail,
	spec policy.Delay, in rebind,
) (bool, error) {
	if spec.CancellableBy == nil {
		if detail.CancellableBy == nil {
			return false, nil
		}
		detail.CancellableBy = nil
		return true, nil
	}
	handler, err := r.challenges.Handler(policy.ChallengeDelay)
	if err != nil {
		return false, err
	}
	resolver, ok := handler.(challenge.CancelAuthorityResolver)
	if !ok {
		return false, fmt.Errorf("%w: %s: the delay handler cannot re-resolve a cancellation authority",
			ErrRevalidation, in.instance())
	}
	resolved, err := resolver.ResolveCancelAuthority(ctx, *spec.CancellableBy, in.context)
	if err != nil {
		return false, fmt.Errorf("%w: re-resolving the cancellation authority of %s: %w",
			ErrRevalidation, in.instance(), err)
	}
	if detail.CancellableBy != nil && detail.CancellableBy.Equal(resolved) {
		return false, nil
	}
	detail.CancellableBy = &resolved
	return true, nil
}

// rebindExternal answers for a round trip that is already out.
//
// A target the revision left alone is left completely alone, nonce included. The
// nonce is what binds one answer to one issuance, so rotating it would
// invalidate a callback the target is already holding — for a revision that did
// not change the question.
//
// A target the revision changed fails the challenge instead of being re-issued.
// U11 recommends it and the reason is structural rather than stylistic:
// [External.Issue] performs a network POST, and this runs inside the transaction
// that is landing the revision, holding a row lock on every open decision. A
// webhook sent from there is a remote system's latency added to a lock hold.
// Failing is also the fail-closed answer — the decision denies — and it is what
// the house does everywhere else a round trip could not be completed.
func (r *Revalidator) rebindExternal(ctx context.Context, tx pgx.Tx, in rebind) (rebound1, error) {
	spec, ok := in.spec.(policy.External)
	if !ok {
		return rebound1{}, fmt.Errorf("%w: %s is declared %T", ErrRevalidation, in.instance(), in.spec)
	}
	stored, err := challenge.DecodeExternalDetail(in.stored.Detail)
	if err != nil {
		return rebound1{}, fmt.Errorf("%w: %s: %w", ErrRevalidation, in.instance(), err)
	}
	if strings.TrimSpace(spec.Target) == stored.Target {
		return rebound1{}, nil
	}
	if stored.Failure != "" {
		// Already failed for some other reason. Overwriting why would lose the
		// operational story the audit trail is for.
		return rebound1{}, nil
	}

	next := stored
	next.Failure = challenge.ExternalFailureRetargeted
	detail, err := json.Marshal(next)
	if err != nil {
		return rebound1{}, fmt.Errorf("%w: encoding the rebound detail for %s: %w",
			ErrRevalidation, in.instance(), err)
	}
	// The timer goes with the wait, as it does at issue: a failed challenge has
	// nothing to wake up for, and a deadline on it would have the sweeper claim
	// a decision that is finished.
	if _, err := tx.Exec(ctx, `
		UPDATE challenge_progress
		SET detail = $3, state = 'failed', deadline = NULL, satisfied_at = NULL
		WHERE decision_id = $1 AND ordinal = $2`,
		in.decision.ID, in.ordinal, detail); err != nil {
		return rebound1{}, fmt.Errorf("%w: rebinding %s: %w", ErrRevalidation, in.instance(), err)
	}
	return rebound1{changed: true, timerMoved: true}, nil
}

// reissue opens a challenge again and returns the detail to store. It is only
// reached from the two paths where issuing has no observable side effect.
func (r *Revalidator) reissue(ctx context.Context, in rebind) (json.RawMessage, error) {
	handler, err := r.challenges.Handler(in.spec.ChallengeType())
	if err != nil {
		return nil, err
	}
	issued, err := handler.Issue(ctx, challenge.IssueRequest{
		Instance: in.instance(), Spec: in.spec, Decision: in.context, Now: in.now,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: re-issuing %s: %w", ErrRevalidation, in.instance(), err)
	}
	detail, err := json.Marshal(issued.Detail)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding re-issued detail for %s: %w",
			ErrRevalidation, in.instance(), err)
	}
	return detail, nil
}

// statusOf asks a handler where a challenge stands under a rewritten detail.
func (r *Revalidator) statusOf(ctx context.Context, in rebind,
	detail json.RawMessage, deadline *time.Time,
) (challenge.State, error) {
	handler, err := r.challenges.Handler(in.spec.ChallengeType())
	if err != nil {
		return "", err
	}
	status, err := handler.Status(ctx, challenge.StatusRequest{
		Instance: in.instance(),
		Decision: in.context,
		Detail:   detail,
		Stored:   challengeState(in.stored.State),
		Deadline: deadline,
		Now:      in.now,
	})
	if err != nil {
		return "", fmt.Errorf("%w: reading %s after rebinding: %w", ErrRevalidation, in.instance(), err)
	}
	if !status.State.Valid() {
		return "", fmt.Errorf("%w: %s reports state %q", ErrRevalidation, in.instance(), status.State)
	}
	return status.State, nil
}

func (r *Revalidator) issue(ctx context.Context, tx pgx.Tx, d store.Decision,
	decisionCtx challenge.DecisionContext, ordinal int, spec policy.Challenge, now time.Time,
) error {
	handler, err := r.challenges.Handler(spec.ChallengeType())
	if err != nil {
		return err
	}
	instance := challenge.Instance{DecisionID: d.ID, Ordinal: ordinal, Kind: spec.ChallengeType()}
	issued, err := handler.Issue(ctx, challenge.IssueRequest{
		Instance: instance, Spec: spec, Decision: decisionCtx, Now: now,
	})
	if err != nil {
		return fmt.Errorf("%w: issuing %s: %w", ErrRevalidation, instance, err)
	}
	detail, err := json.Marshal(issued.Detail)
	if err != nil {
		return fmt.Errorf("%w: encoding detail for %s: %w", ErrRevalidation, instance, err)
	}
	deadline := issued.Deadline
	if deadline != nil && deadline.After(d.ExpiresAt) {
		// A challenge may not outlive the decision it hangs off; the decision's
		// own expiry is not extended by a revision.
		deadline = &d.ExpiresAt
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO challenge_progress (decision_id, ordinal, kind, state, deadline, detail)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		d.ID, ordinal, string(spec.ChallengeType()), string(storeChallengeState(issued.State)),
		deadline, detail); err != nil {
		return fmt.Errorf("%w: opening %s: %w", ErrRevalidation, instance, err)
	}
	return nil
}

func (r *Revalidator) obligationsFor(ctx context.Context, in engine.Input, evaluated engine.DecideResult) ([]Obligation, error) {
	if r.obligations == nil {
		return []Obligation{}, nil
	}
	out, err := r.obligations.ObligationsFor(ctx, ObligationRequest{
		Input: in, PolicyID: evaluated.PolicyID(), Gates: evaluated.Gates(),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: resolving obligations: %w", ErrRevalidation, err)
	}
	if out == nil {
		out = []Obligation{}
	}
	return out, nil
}

func sameShape(stored []store.ChallengeProgress, specs []policy.Challenge) bool {
	if len(stored) != len(specs) {
		return false
	}
	for i := range stored {
		if stored[i].Ordinal != i || stored[i].Kind != specs[i].ChallengeType() {
			return false
		}
	}
	return true
}

func auditInvalidation(ctx context.Context, ap *store.Appender, decisionID string, ordinal, dropped int, why, revisionID string) error {
	payload := map[string]any{
		"revision_id": revisionID,
		"dropped":     dropped,
		"reason":      why,
	}
	if ordinal >= 0 {
		payload["ordinal"] = ordinal
	}
	_, err := ap.Append(ctx, store.AuditEntry{
		Kind: AuditKindApprovalsInvalidated, Subject: decisionID, Payload: payload,
	})
	return err
}

// ---------------------------------------------------------------------------
// queries
// ---------------------------------------------------------------------------

// openDecisions claims every decision a revision could still affect.
//
// The rows are locked for the caller's transaction, so an approval submitted
// while the revision is landing waits for it rather than counting against terms
// that are about to change.
func openDecisions(ctx context.Context, q store.Querier, now time.Time) ([]store.Decision, error) {
	rows, err := q.Query(ctx, `
		SELECT id, caller_id, policy_id, policy_version, subject_id, resource_id, action,
		       request::text, fact_snapshot::text, obligations::text, state, created_at, expires_at
		FROM decisions
		WHERE state = 'pending' AND expires_at > $1
		ORDER BY created_at
		FOR UPDATE`, now.UTC())
	if err != nil {
		return nil, fmt.Errorf("%w: claiming open decisions: %w", ErrRevalidation, err)
	}
	defer rows.Close()
	var out []store.Decision
	for rows.Next() {
		var (
			d                           store.Decision
			request, facts, obligations string
			state                       string
		)
		if err := rows.Scan(&d.ID, &d.CallerID, &d.PolicyID, &d.PolicyVersion, &d.SubjectID,
			&d.ResourceID, &d.Action, &request, &facts, &obligations, &state,
			&d.CreatedAt, &d.ExpiresAt); err != nil {
			return nil, fmt.Errorf("%w: reading an open decision: %w", ErrRevalidation, err)
		}
		d.Request = json.RawMessage(request)
		d.FactSnapshot = json.RawMessage(facts)
		d.Obligations = json.RawMessage(obligations)
		d.State = store.DecisionState(state)
		d.CreatedAt, d.ExpiresAt = d.CreatedAt.UTC(), d.ExpiresAt.UTC()
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: reading open decisions: %w", ErrRevalidation, err)
	}
	return out, nil
}

func countApprovalsOf(ctx context.Context, q store.Querier, decisionID string) (int, error) {
	var n int
	if err := q.QueryRow(ctx,
		`SELECT count(*) FROM approvals WHERE decision_id = $1`, decisionID).Scan(&n); err != nil {
		return 0, fmt.Errorf("%w: counting approvals of %q: %w", ErrRevalidation, decisionID, err)
	}
	return n, nil
}

// dropApprovals removes the approvals bound to material that has changed.
//
// The rows go, the audit entries that recorded them do not: the chain still
// holds every approval that was ever submitted, so nothing about who approved
// what is lost. What goes is the countable evidence, which is the only thing an
// invalidated approval may not keep.
func dropApprovals(ctx context.Context, q store.Querier, decisionID string, ordinal int) (int, error) {
	tag, err := q.Exec(ctx,
		`DELETE FROM approvals WHERE decision_id = $1 AND challenge_ordinal = $2`, decisionID, ordinal)
	if err != nil {
		return 0, fmt.Errorf("%w: invalidating approvals of %q: %w", ErrRevalidation, decisionID, err)
	}
	return int(tag.RowsAffected()), nil
}

// quorumStateAfter reports where a re-bound quorum stands, so a challenge that
// lost its approvals goes back to pending rather than staying satisfied on the
// strength of evidence that no longer exists.
func quorumStateAfter(ctx context.Context, q store.Querier, decisionID string, ordinal int, detail json.RawMessage) (store.ChallengeState, error) {
	var terms struct {
		Threshold int `json:"threshold"`
	}
	if err := json.Unmarshal(detail, &terms); err != nil {
		return "", fmt.Errorf("%w: reading a re-issued quorum detail: %w", ErrRevalidation, err)
	}
	have, err := store.CountApprovals(ctx, q, decisionID, ordinal, store.VerdictApprove)
	if err != nil {
		return "", err
	}
	if terms.Threshold > 0 && have >= terms.Threshold {
		return store.ChallengeSatisfied, nil
	}
	return store.ChallengePending, nil
}

// challengeTally counts where a decision's challenges stand after rebinding.
//
// Failed and cancelled are counted together because they deny alike, which is
// the same equivalence [Service.advance] makes on the settle path.
func challengeTally(ctx context.Context, q store.Querier, decisionID string) (total, satisfied, failed int, err error) {
	err = q.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE state = 'satisfied'),
		       count(*) FILTER (WHERE state IN ('failed', 'cancelled'))
		FROM challenge_progress WHERE decision_id = $1`, decisionID).Scan(&total, &satisfied, &failed)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("%w: reading challenge progress of %q: %w", ErrRevalidation, decisionID, err)
	}
	return total, satisfied, failed, nil
}

// ---------------------------------------------------------------------------
// the frozen fact snapshot
// ---------------------------------------------------------------------------

// frozenFacts is the fact plane a revaluation sees: the snapshot the decision
// froze, and nothing else unless the revised policy reaches somewhere the
// snapshot never went.
//
// This is the mechanism behind R5's "does not re-fetch". A resolver that went to
// the network for values it already held would move the snapshot on every
// revision, and the snapshot is an input to the approval binding hash, so every
// revision would invalidate every approval.
type frozenFacts struct {
	schema *policy.Schema
	values map[string]any
	live   engine.SourceResolver

	fetched map[string]any
	names   map[string]struct{}
}

func newFrozenFacts(schema *policy.Schema, raw json.RawMessage, live engine.SourceResolver) (*frozenFacts, error) {
	values := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &values); err != nil {
			return nil, fmt.Errorf("%w: reading a frozen fact snapshot: %w", ErrRevalidation, err)
		}
	}
	return &frozenFacts{
		schema:  schema,
		values:  values,
		live:    live,
		fetched: map[string]any{},
		names:   map[string]struct{}{},
	}, nil
}

// ResolveSources answers from the frozen snapshot, fetching only what it does
// not hold.
func (f *frozenFacts) ResolveSources(ctx context.Context, calls []engine.SourceCall) (*engine.Facts, error) {
	facts := engine.NewFacts()
	var missing []engine.SourceCall
	for _, call := range calls {
		key := call.String()
		if raw, ok := f.values[key]; ok {
			value, err := f.restore(call, raw)
			if err != nil {
				return nil, err
			}
			facts.Set(call, value)
			continue
		}
		missing = append(missing, call)
	}
	if len(missing) == 0 {
		return facts, nil
	}
	if f.live == nil {
		return nil, fmt.Errorf("%w: %w: the revised policy set reaches %d source call(s) the frozen "+
			"snapshot does not hold and no resolver was supplied",
			ErrRevalidation, engine.ErrUnresolvedFact, len(missing))
	}
	resolved, err := f.live.ResolveSources(ctx, missing)
	if err != nil {
		return nil, fmt.Errorf("%w: fetching a newly referenced source: %w", ErrRevalidation, err)
	}
	for _, call := range missing {
		value, ok := resolved.Value(call)
		if !ok {
			return nil, fmt.Errorf("%w: %w: %s", ErrRevalidation, engine.ErrUnresolvedFact, call)
		}
		facts.Set(call, value)
		f.fetched[call.String()] = value
		f.names[call.Name] = struct{}{}
	}
	return facts, nil
}

// restore converts a value that has been through the database back into the Go
// shape the evaluator's type system expects. A frozen int comes back out of
// jsonb as a float, and the type system has no implicit numeric conversion.
func (f *frozenFacts) restore(call engine.SourceCall, raw any) (any, error) {
	decl, ok := f.schema.Source(call.Name)
	if !ok {
		return nil, fmt.Errorf("%w: the frozen snapshot holds %s, which the revised schema does not declare",
			ErrRevalidation, call)
	}
	value, err := restoreValue(decl.Returns, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: frozen fact %s: %w", ErrRevalidation, call, err)
	}
	return value, nil
}

func (f *frozenFacts) fetchedNames() []string {
	if len(f.names) == 0 {
		return nil
	}
	out := make([]string, 0, len(f.names))
	for name := range f.names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// merged returns the frozen snapshot with the newly fetched values added.
func (f *frozenFacts) merged(raw json.RawMessage) (json.RawMessage, error) {
	values := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &values); err != nil {
			return nil, fmt.Errorf("%w: reading a frozen fact snapshot: %w", ErrRevalidation, err)
		}
	}
	for key, value := range f.fetched {
		values[key] = value
	}
	out, err := json.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding the extended fact snapshot: %w", ErrRevalidation, err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// restoring the frozen request
// ---------------------------------------------------------------------------

// restoreInput rebuilds the evaluation request from the row the decision froze.
//
// The request is read back rather than reconstructed from anything live. A
// revaluation judges the request that was made, and a request assembled from
// current state would be a different request that resembles it.
func restoreInput(schema *policy.Schema, raw json.RawMessage) (engine.Input, error) {
	var frozen struct {
		Action   string         `json:"action"`
		Subject  map[string]any `json:"subject"`
		Resource map[string]any `json:"resource"`
		Context  map[string]any `json:"context"`
	}
	if err := json.Unmarshal(raw, &frozen); err != nil {
		return engine.Input{}, fmt.Errorf("decoding the frozen request: %w", err)
	}
	subject, err := restoreEntity(schema, frozen.Subject)
	if err != nil {
		return engine.Input{}, fmt.Errorf("subject: %w", err)
	}
	resource, err := restoreEntity(schema, frozen.Resource)
	if err != nil {
		return engine.Input{}, fmt.Errorf("resource: %w", err)
	}
	entityContext, err := restoreEntity(schema, frozen.Context)
	if err != nil {
		return engine.Input{}, fmt.Errorf("context: %w", err)
	}
	return engine.Input{
		Action: frozen.Action, Subject: subject, Resource: resource, Context: entityContext,
	}, nil
}

func restoreEntity(schema *policy.Schema, raw map[string]any) (engine.Entity, error) {
	if len(raw) == 0 {
		return engine.Entity{}, nil
	}
	out := engine.Entity{}
	out.Type, _ = raw["type"].(string)
	out.ID, _ = raw["id"].(string)
	attributes, _ := raw["attributes"].(map[string]any)
	if len(attributes) == 0 || out.Type == "" {
		return out, nil
	}
	declared, ok := schema.Entity(out.Type)
	if !ok {
		return engine.Entity{}, fmt.Errorf("the revised schema does not declare entity type %q", out.Type)
	}
	out.Attributes = make(map[string]any, len(attributes))
	for name, value := range attributes {
		attr, ok := declared.Attribute(name)
		if !ok {
			// An attribute the revised schema dropped is carried through as it
			// was frozen; the evaluator refuses it, and a refusal is the
			// fail-closed answer for a request that no longer type-checks.
			out.Attributes[name] = value
			continue
		}
		restored, err := restoreValue(attr.Type, value)
		if err != nil {
			return engine.Entity{}, fmt.Errorf("attribute %q: %w", name, err)
		}
		out.Attributes[name] = restored
	}
	return out, nil
}

// restoreValue converts one JSON value back to the Go representation the policy
// type system uses.
func restoreValue(t policy.Type, v any) (any, error) {
	if t.IsList() {
		items, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("expected %s, got %T", t, v)
		}
		out := make([]any, len(items))
		for i, item := range items {
			restored, err := restoreValue(t.Elem(), item)
			if err != nil {
				return nil, fmt.Errorf("element %d: %w", i, err)
			}
			out[i] = restored
		}
		return out, nil
	}
	switch t {
	case policy.TypeBool, policy.TypeString, policy.TypeDouble:
		return v, nil
	case policy.TypeInt:
		n, ok := v.(float64)
		if !ok {
			return v, nil
		}
		if n != float64(int64(n)) {
			return nil, fmt.Errorf("expected %s, got the non-integral %v", t, n)
		}
		return int64(n), nil
	case policy.TypeTimestamp:
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("expected %s as a string, got %T", t, v)
		}
		parsed, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return nil, fmt.Errorf("expected %s: %w", t, err)
		}
		return parsed.UTC(), nil
	case policy.TypeDuration:
		switch n := v.(type) {
		case float64:
			return time.Duration(int64(n)), nil
		case string:
			parsed, err := time.ParseDuration(n)
			if err != nil {
				return nil, fmt.Errorf("expected %s: %w", t, err)
			}
			return parsed, nil
		default:
			return nil, fmt.Errorf("expected %s, got %T", t, v)
		}
	default:
		return v, nil
	}
}
