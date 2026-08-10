package revision

// governance.go is the dogfooding: a change to the policy set is a decision
// STAMP makes about itself, gated by a policy that is itself in the policy store
// (D6).
//
// The reserved policy is what makes that literal rather than metaphorical. It
// lives in the same table, carries the same challenge declarations, and is
// versioned by the same writes as any other policy — so "changing the rules goes
// through the rules currently in force" is a property of where the rule is
// stored and not of a branch somebody remembered to write.
//
// Installation puts a solo-admin version of it in place: no challenges, and the
// bootstrap token as the only control. The lock replaces it with a quorum-
// bearing version and cannot be undone from inside the running system. A
// revision that would strip the quorum back off is refused here, because
// otherwise the irreversibility would be worth exactly one revision.
//
// The reserved policy is evaluated against its own schema and its own snapshot,
// never against the tenant's. It binds entity types the tenant schema has never
// heard of, so a snapshot that mixed the two would not compile. Everything that
// builds a tenant policy set therefore has to exclude it, which is what
// [IsReserved] is for.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// The reserved governance vocabulary.
const (
	// GovernancePolicyID is the reserved policy every revision is gated by.
	GovernancePolicyID = "stamp.governance"

	// ActionRevise is the action a revision proposal is evaluated as.
	ActionRevise = "policy.revise"

	// PolicySetID names the policy set a revision acts on. There is one.
	PolicySetID = "default"

	// The entity types the governance schema declares.
	EntityAdmin     = "admin"
	EntityPolicySet = "policy_set"
	EntityRevision  = "revision"

	// SystemAuthor is the author recorded for writes the installation itself
	// makes.
	SystemAuthor = "stamp.system"
)

// Audit kinds the governance path appends.
const (
	AuditKindInstalled        = "governance.installed"
	AuditKindLocked           = "governance.locked"
	AuditKindRevisionProposed = "policy.revision.proposed"
	AuditKindRevisionApplied  = "policy.revision.applied"
	AuditKindRevisionRejected = "policy.revision.rejected"
	AuditKindRevisionWithdraw = "policy.revision.withdrawn"

	// AuditKindGovernanceReset records a governance policy put back to
	// solo-admin mode from outside the running system. It is the loudest event
	// this system emits.
	AuditKindGovernanceReset = "governance.reset"
)

// Errors the governance path returns as sentinels.
var (
	// ErrAlreadyLocked reports a second lock, or any attempt to return an
	// installation to solo-admin mode from inside it (R34, D6).
	ErrAlreadyLocked = errors.New("revision: governance is already locked, and the lock is irreversible")

	// ErrRevisionPending reports a proposal made while another is open. One at a
	// time is what lets an approver review a diff against the state in force
	// (D24).
	ErrRevisionPending = errors.New("revision: another revision is already pending")

	// ErrNotApproved reports an apply attempted before the governance decision
	// resolved.
	ErrNotApproved = errors.New("revision: the governance decision has not resolved")

	// ErrInvalidRevision reports a revision whose outcome would not be a valid
	// policy set.
	ErrInvalidRevision = errors.New("revision: the revised policy set would not validate")

	// ErrNotProposer reports a withdrawal by somebody other than the proposer.
	ErrNotProposer = errors.New("revision: only the proposer may withdraw a revision")

	// ErrNotInstalled reports governance operations before Install has run.
	ErrNotInstalled = errors.New("revision: governance is not installed")
)

// IsReserved reports whether a policy identifier names a policy the system owns
// rather than the tenant.
//
// Every path that assembles an evaluable tenant policy set must filter through
// it. The reserved policy is written against the governance schema, so a
// snapshot that included it would fail to compile against the tenant's.
func IsReserved(policyID string) bool { return policyID == GovernancePolicyID }

// Mode is which governance regime an installation is in.
type Mode string

// The governance modes.
const (
	// ModeSolo is the installation window: no quorum, the bootstrap token as
	// the only control.
	ModeSolo Mode = "solo_admin"
	// ModeQuorum is the locked regime: revisions pass through a quorum.
	ModeQuorum Mode = "quorum"
)

// State is a revision proposal's lifecycle state.
type State string

// The proposal states.
const (
	StatePending   State = "pending"
	StateApplied   State = "applied"
	StateWithdrawn State = "withdrawn"
	StateRejected  State = "rejected"
)

// GovernanceSchema is the schema the reserved policy is written against.
//
// It is fixed in code rather than authored, because it is the vocabulary the
// governance decision is expressed in and an installation that could edit it
// could edit the meaning of its own gate.
func GovernanceSchema() *policy.Schema {
	return &policy.Schema{
		Entities: []policy.EntityType{
			{Name: EntityAdmin},
			{Name: EntityPolicySet},
			{Name: EntityRevision, Attributes: []policy.Attribute{
				// The delta digest is an attribute of the request, which means it
				// is inside the approval binding hash. An approval for a revision
				// is therefore bound to the exact change set that was shown, not
				// to a revision identifier behind which anything could move.
				{Name: "delta_digest", Type: policy.TypeString},
				{Name: "weakening", Type: policy.TypeBool},
				{Name: "change_count", Type: policy.TypeInt},
			}},
		},
		Actions: []policy.Action{{Name: ActionRevise, Description: "propose a revision of the policy set"}},
	}
}

// GovernancePolicy renders the reserved policy for a set of challenges. No
// challenges is solo-admin mode.
//
// The condition is always true: which requests the policy applies to is decided
// by the action and the entity bindings, and the digest comparison is there so
// that the request the policy is evaluated against is one that carries a digest
// at all.
func GovernancePolicy(challenges ...policy.Challenge) *policy.Policy {
	return &policy.Policy{
		ID:          GovernancePolicyID,
		Description: "STAMP's own rule for changing the policy set",
		Subject:     EntityAdmin,
		Resource:    EntityPolicySet,
		Context:     EntityRevision,
		Actions:     []string{ActionRevise},
		Condition: policy.Compare{
			Op:    policy.OpNe,
			Left:  policy.Field(policy.RoleContext, "delta_digest"),
			Right: policy.String(""),
		},
		Challenges: challenges,
	}
}

// GovernanceQuorum returns the quorum the reserved policy demands, and false
// when it demands none — which is solo-admin mode.
func GovernanceQuorum(p *policy.Policy) (policy.Quorum, bool) {
	if p == nil {
		return policy.Quorum{}, false
	}
	for _, c := range p.Challenges {
		if q, ok := c.(policy.Quorum); ok {
			return q, true
		}
	}
	return policy.Quorum{}, false
}

// Config configures a governance [Service].
type Config struct {
	// Store is the persistence handle. Required.
	Store *store.Store
	// Audit is the audit writer every governance write goes through. Required.
	Audit *store.AuditWriter
	// Challenges maps challenge kinds to handlers. Required: a governance
	// decision opens a quorum through the same handler every other decision
	// does.
	Challenges *challenge.Registry
	// Revalidator applies a revision to the decisions already open. Required.
	Revalidator *decision.Revalidator
	// Resolver fetches a source a frozen snapshot does not hold. Optional; a nil
	// resolver makes a newly referenced source a fail-closed deny.
	Resolver engine.SourceResolver
	// Floor is the operator's lower bound. The zero value uses [DefaultFloor].
	Floor Floor
	// TTL bounds how long a revision may stay pending. Zero uses
	// [DefaultRevisionTTL], which is D24's answer to approvers who do nothing.
	TTL time.Duration
	// Now is the clock. Nil uses the store's.
	Now func() time.Time
}

// DefaultRevisionTTL is how long a proposal stays open before it expires and
// releases the gate (D24).
const DefaultRevisionTTL = 24 * time.Hour

// Service is the governance path.
type Service struct {
	store       *store.Store
	audit       *store.AuditWriter
	challenges  *challenge.Registry
	revalidator *decision.Revalidator
	resolver    engine.SourceResolver
	bootstrap   *Bootstrap
	floor       Floor
	ttl         time.Duration
	now         func() time.Time
}

// New builds the governance service.
func New(cfg Config) (*Service, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("revision: governance needs a store")
	case cfg.Audit == nil:
		return nil, errors.New("revision: governance needs an audit writer")
	case cfg.Challenges == nil:
		return nil, errors.New("revision: governance needs the challenge registry")
	case cfg.Revalidator == nil:
		return nil, errors.New("revision: governance needs a revalidator")
	}
	bootstrap, err := NewBootstrap(BootstrapConfig{Store: cfg.Store, Audit: cfg.Audit, Now: cfg.Now})
	if err != nil {
		return nil, err
	}
	s := &Service{
		store:       cfg.Store,
		audit:       cfg.Audit,
		challenges:  cfg.Challenges,
		revalidator: cfg.Revalidator,
		resolver:    cfg.Resolver,
		bootstrap:   bootstrap,
		floor:       cfg.Floor,
		ttl:         cfg.TTL,
		now:         cfg.Now,
	}
	if s.floor.MinApprovers <= 0 {
		s.floor.MinApprovers = DefaultFloor().MinApprovers
	}
	if s.ttl <= 0 {
		s.ttl = DefaultRevisionTTL
	}
	if s.now == nil {
		s.now = cfg.Store.Now
	}
	return s, nil
}

// Bootstrap exposes the token gate, so a deployment can print the token, report
// its status and run the unused-token warning.
func (s *Service) Bootstrap() *Bootstrap { return s.bootstrap }

// Install puts the reserved policy in place in solo-admin mode and issues the
// bootstrap token, returning the token's plaintext exactly once.
//
// It is idempotent: a second call finds the policy already installed and
// returns the empty string, because the token is printed at first start and
// there is no second print.
func (s *Service) Install(ctx context.Context) (string, error) {
	var token string
	err := s.audit.InTx(ctx, func(ctx context.Context, tx pgx.Tx, ap *store.Appender) error {
		existing, err := store.EffectivePolicy(ctx, tx, GovernancePolicyID)
		switch {
		case err == nil && !existing.Deleted:
			// Already installed; the token, if any, was printed at its first
			// start.
			issued, ierr := s.bootstrap.issue(ctx, tx, ap)
			token = issued
			return ierr
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return err
		}

		schema, err := store.PutSchema(ctx, tx, GovernanceSchema(), store.OriginForm, SystemAuthor)
		if err != nil {
			return err
		}
		if _, err := store.PutPolicy(ctx, tx, store.PolicyInput{
			Policy:        GovernancePolicy(),
			SchemaVersion: schema.Version,
			Origin:        store.OriginForm,
			Author:        SystemAuthor,
		}); err != nil {
			return err
		}
		issued, err := s.bootstrap.issue(ctx, tx, ap)
		if err != nil {
			return err
		}
		token = issued
		_, err = ap.Append(ctx, store.AuditEntry{
			Kind:    AuditKindInstalled,
			Subject: GovernancePolicyID,
			Payload: map[string]any{
				SeverityKey:      SeverityNotice,
				"mode":           string(ModeSolo),
				"schema_version": schema.Version,
			},
		})
		return err
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// Mode reports which governance regime the installation is in.
func (s *Service) Mode(ctx context.Context) (Mode, error) {
	_, p, err := s.governance(ctx, s.store.Pool())
	if err != nil {
		return "", err
	}
	if _, locked := GovernanceQuorum(p); locked {
		return ModeQuorum, nil
	}
	return ModeSolo, nil
}

// governance reads the reserved policy as it currently stands.
func (s *Service) governance(ctx context.Context, q store.Querier) (store.PolicyRecord, *policy.Policy, error) {
	rec, err := store.EffectivePolicy(ctx, q, GovernancePolicyID)
	if errors.Is(err, store.ErrNotFound) {
		return store.PolicyRecord{}, nil, ErrNotInstalled
	}
	if err != nil {
		return store.PolicyRecord{}, nil, err
	}
	if rec.Deleted {
		return store.PolicyRecord{}, nil, ErrNotInstalled
	}
	p, err := rec.Policy()
	if err != nil {
		return store.PolicyRecord{}, nil, err
	}
	return rec, p, nil
}

// ---------------------------------------------------------------------------
// the lock
// ---------------------------------------------------------------------------

// LockRequest installs quorum governance.
type LockRequest struct {
	// Actor is the administrator running the lock. Required.
	Actor *identity.Subject
	// Token is the bootstrap token. Required, and consumed on success.
	Token string
	// Quorum is the governance quorum to install.
	Quorum policy.Quorum
}

// Lock replaces the reserved policy with a quorum-bearing one and kills the
// bootstrap token in the same transaction (R34, D6).
//
// It refuses a second lock. There is deliberately no unlock: after this, a
// governance policy can only be changed by a revision that passes through the
// quorum it installs, and the only way back to solo-admin mode is the offline
// break-glass procedure, which cannot run while the service is up and which
// leaves the loudest record the audit chain has.
func (s *Service) Lock(ctx context.Context, req LockRequest) error {
	if req.Actor == nil || req.Actor.Kind != identity.SubjectUser {
		return decision.ErrUnauthenticated
	}
	if err := s.bootstrap.Verify(ctx, req.Token); err != nil {
		return err
	}
	locked := GovernancePolicy(req.Quorum)
	if err := CheckSatisfiable(Delta{Changes: []Change{
		{Kind: ChangeModify, PolicyID: GovernancePolicyID, Before: GovernancePolicy(), After: locked},
	}}); err != nil {
		return err
	}
	if diags := policy.Validate(&policy.Set{
		Schema: *GovernanceSchema(), Policies: []policy.Policy{*locked},
	}); len(diags) > 0 {
		return fmt.Errorf("%w: %w", ErrInvalidRevision, diags)
	}

	return s.audit.InTx(ctx, func(ctx context.Context, tx pgx.Tx, ap *store.Appender) error {
		rec, current, err := s.governance(ctx, tx)
		if err != nil {
			return err
		}
		if _, already := GovernanceQuorum(current); already {
			return ErrAlreadyLocked
		}
		if _, err := store.PutPolicy(ctx, tx, store.PolicyInput{
			Policy:        locked,
			SchemaVersion: rec.SchemaVersion,
			Origin:        rec.Origin,
			Author:        req.Actor.ID,
		}); err != nil {
			return err
		}
		if err := s.bootstrap.consume(ctx, tx, ap); err != nil {
			return err
		}
		_, err = ap.Append(ctx, store.AuditEntry{
			Kind:    AuditKindLocked,
			Subject: GovernancePolicyID,
			Payload: map[string]any{
				SeverityKey: SeverityNotice,
				"actor":     req.Actor.CallerID(),
				"threshold": req.Quorum.Threshold,
				"approvers": req.Quorum.Approvers.Members,
				"claim":     req.Quorum.Approvers.Claim,
			},
		})
		return err
	})
}

// ---------------------------------------------------------------------------
// proposals
// ---------------------------------------------------------------------------

// Proposal is a revision as it stands.
type Proposal struct {
	ID          string                     `json:"id"`
	DecisionID  string                     `json:"decision_id,omitempty"`
	ProposerID  string                     `json:"proposer_id"`
	Delta       Delta                      `json:"delta"`
	DeltaDigest string                     `json:"delta_digest"`
	Mode        decision.ApplicationMode   `json:"application_mode"`
	State       State                      `json:"state"`
	Weakening   bool                       `json:"weakening"`
	Findings    []Finding                  `json:"findings"`
	Threshold   int                        `json:"threshold"`
	CreatedAt   time.Time                  `json:"created_at"`
	ResolvedAt  *time.Time                 `json:"resolved_at,omitempty"`
	Report      *decision.RevalidateReport `json:"revalidation,omitempty"`
}

// PreviewRequest asks what a revision would cost before it is submitted.
type PreviewRequest struct {
	Proposer *identity.Subject
	Delta    Delta
}

// Preview is R23's pre-submission answer: the weakening classification, the
// floors the revision would break, and how many open decisions it would touch.
//
// A revision that breaks a floor is shown here and refused at submission, so an
// author learns the cost before a quorum spends its attention on something that
// could never take effect.
type Preview struct {
	Mode              Mode      `json:"mode"`
	Weakening         bool      `json:"weakening"`
	Findings          []Finding `json:"findings"`
	Threshold         int       `json:"threshold"`
	Approvers         []string  `json:"approvers,omitempty"`
	ExcludeProposer   bool      `json:"exclude_proposer"`
	AffectedDecisions int       `json:"affected_decisions"`
	Violations        []string  `json:"violations,omitempty"`
}

// Admissible reports whether the revision could be submitted as it stands.
func (p Preview) Admissible() bool { return len(p.Violations) == 0 }

// Preview classifies a revision and reports what adopting it would require.
func (s *Service) Preview(ctx context.Context, req PreviewRequest) (Preview, error) {
	proposer := ""
	if req.Proposer != nil {
		proposer = req.Proposer.ID
	}
	assessed, err := s.assess(ctx, req.Delta, proposer)
	out := Preview{
		Mode:            assessed.mode,
		Weakening:       assessed.class.Weakening(),
		Findings:        assessed.class.Findings,
		Threshold:       assessed.requirement.Threshold,
		Approvers:       assessed.requirement.Approvers.Members,
		ExcludeProposer: assessed.requirement.ExcludeProposer,
		Violations:      assessed.violations,
	}
	if err != nil && len(out.Violations) == 0 {
		return Preview{}, err
	}
	affected, cerr := s.affectedDecisions(ctx)
	if cerr != nil {
		return Preview{}, cerr
	}
	out.AffectedDecisions = affected
	return out, nil
}

// assessment is everything the governance path concludes about a delta before
// it decides whether to open a decision for it.
type assessment struct {
	mode        Mode
	class       Classification
	requirement Requirement
	current     *policy.Quorum
	proposed    *policy.Quorum
	violations  []string
}

func (s *Service) assess(ctx context.Context, d Delta, proposer string) (assessment, error) {
	out := assessment{}
	_, governance, err := s.governance(ctx, s.store.Pool())
	if err != nil {
		return out, err
	}
	if q, locked := GovernanceQuorum(governance); locked {
		out.mode, out.current = ModeQuorum, &q
	} else {
		out.mode = ModeSolo
	}

	if err := d.Validate(); err != nil {
		out.violations = append(out.violations, err.Error())
		return out, err
	}
	// Satisfiability is checked before the set is validated. The validator also
	// refuses a quorum larger than its own approver list, but it reports it as a
	// schema diagnostic, and R34's answer to an unreachable quorum is a distinct
	// refusal an operator can act on.
	if err := CheckSatisfiable(d); err != nil {
		out.violations = append(out.violations, err.Error())
		return out, err
	}
	if err := s.validateOutcome(ctx, d, out.mode); err != nil {
		out.violations = append(out.violations, err.Error())
		return out, err
	}

	out.class = Classify(d)
	if c, ok := d.Change(GovernancePolicyID); ok && c.After != nil {
		if q, has := GovernanceQuorum(c.After); has {
			out.proposed = &q
		}
	}
	req, err := Require(out.current, out.proposed, out.class, s.floor, proposer)
	if err != nil {
		out.violations = append(out.violations, err.Error())
		return out, err
	}
	out.requirement = req
	return out, nil
}

// validateOutcome refuses a revision whose result would not be a policy set the
// engine could load, and refuses one that would undo the lock.
func (s *Service) validateOutcome(ctx context.Context, d Delta, mode Mode) error {
	if c, ok := d.Change(GovernancePolicyID); ok {
		switch {
		case c.Kind == ChangeDelete:
			return fmt.Errorf("%w: the reserved governance policy cannot be deleted", ErrAlreadyLocked)
		case mode == ModeQuorum && c.After != nil:
			if _, has := GovernanceQuorum(c.After); !has {
				return fmt.Errorf("%w: this revision would remove the governance quorum", ErrAlreadyLocked)
			}
		}
		if c.After != nil {
			if diags := policy.Validate(&policy.Set{
				Schema: *GovernanceSchema(), Policies: []policy.Policy{*c.After},
			}); len(diags) > 0 {
				return fmt.Errorf("%w: %w", ErrInvalidRevision, diags)
			}
		}
	}

	tenant, err := s.tenantSet(ctx, s.store.Pool())
	if err != nil {
		return err
	}
	result, err := tenantDelta(d).Result(tenant)
	if err != nil {
		return err
	}
	if len(result.Policies) == 0 && len(result.Schema.Actions) == 0 {
		// An empty set is a legitimate outcome — every policy deleted — and the
		// validator has nothing to say about it.
		return nil
	}
	if diags := policy.Validate(result); len(diags) > 0 {
		return fmt.Errorf("%w: %w", ErrInvalidRevision, diags)
	}
	return nil
}

// tenantDelta is the delta with the reserved policy removed. The reserved
// policy is validated against its own schema, so it must not be folded into the
// tenant set.
func tenantDelta(d Delta) Delta {
	out := Delta{SchemaBefore: d.SchemaBefore, SchemaAfter: d.SchemaAfter}
	for _, c := range d.Changes {
		if IsReserved(c.PolicyID) {
			continue
		}
		out.Changes = append(out.Changes, c)
	}
	return out
}

// tenantSet loads the effective policy set with the reserved policy excluded,
// and the schema version it is written against.
func (s *Service) tenantSet(ctx context.Context, q store.Querier) (*policy.Set, error) {
	schema, err := store.LatestSchema(ctx, q)
	if err != nil {
		return nil, err
	}
	decoded, err := DecodeSchema(schema.Document)
	if err != nil {
		return nil, err
	}
	records, err := store.EffectivePolicies(ctx, q)
	if err != nil {
		return nil, err
	}
	set := &policy.Set{Schema: *decoded}
	for _, rec := range records {
		if IsReserved(rec.ID) {
			continue
		}
		p, perr := rec.Policy()
		if perr != nil {
			return nil, perr
		}
		set.Policies = append(set.Policies, *p)
	}
	return set, nil
}

func (s *Service) affectedDecisions(ctx context.Context) (int, error) {
	var n int
	err := s.store.Pool().QueryRow(ctx, `
		SELECT count(*) FROM decisions
		WHERE state = 'pending' AND expires_at > $1 AND policy_id <> $2`,
		s.now().UTC(), GovernancePolicyID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("revision: count affected decisions: %w", err)
	}
	return n, nil
}

// ProposeRequest submits a revision.
type ProposeRequest struct {
	// Proposer is the authenticated author. Required, and an end user: a
	// workload credential never authors policy.
	Proposer *identity.Subject
	// Delta is the change set.
	Delta Delta
	// Mode is how open decisions are treated. The empty mode is revaluation.
	Mode decision.ApplicationMode
	// BootstrapToken authorizes a pre-lock revision. Ignored after the lock.
	BootstrapToken string
	// TTL bounds how long the revision stays open. Zero uses the service's.
	TTL time.Duration
}

// Propose turns a policy change into a decision (R6).
//
// Before the lock the decision has no challenges and resolves immediately, and
// the bootstrap token is what authorizes it. After the lock the decision carries
// a quorum computed for this delta: the stricter of the old and new rules when
// the delta weakens anything, plus the operator floor, with the proposer removed
// from the eligible set.
func (s *Service) Propose(ctx context.Context, req ProposeRequest) (Proposal, error) {
	if req.Proposer == nil || req.Proposer.Kind != identity.SubjectUser {
		return Proposal{}, decision.ErrUnauthenticated
	}
	if !req.Mode.Valid() {
		return Proposal{}, fmt.Errorf("%w: unknown application mode %q", ErrInvalidDelta, req.Mode)
	}
	assessed, err := s.assess(ctx, req.Delta, req.Proposer.ID)
	if err != nil {
		return Proposal{}, err
	}
	if assessed.mode == ModeSolo {
		if err := s.bootstrap.Verify(ctx, req.BootstrapToken); err != nil {
			return Proposal{}, err
		}
	}

	digest, err := req.Delta.Digest()
	if err != nil {
		return Proposal{}, err
	}
	id, err := store.NewDecisionID()
	if err != nil {
		return Proposal{}, err
	}
	proposal := Proposal{
		ID:          id,
		ProposerID:  req.Proposer.ID,
		Delta:       req.Delta,
		DeltaDigest: hex.EncodeToString(digest[:]),
		Mode:        req.Mode.OrDefault(),
		State:       StatePending,
		Weakening:   assessed.class.Weakening(),
		Findings:    assessed.class.Findings,
		Threshold:   assessed.requirement.Threshold,
		CreatedAt:   s.now().UTC(),
	}

	// The row goes in first. The unique index on a pending revision is what
	// serializes proposals, and a proposal that created its decision before
	// claiming the gate would leave an orphan decision behind when it lost.
	if err := s.insertProposal(ctx, proposal, req.Proposer); err != nil {
		return Proposal{}, err
	}

	result, err := s.decide(ctx, proposal, assessed, req.TTL)
	if err != nil {
		s.discard(ctx, proposal.ID)
		return Proposal{}, err
	}
	proposal.DecisionID = result.ID
	if _, err := s.store.Pool().Exec(ctx,
		`UPDATE policy_revisions SET decision_id = $2 WHERE id = $1`, proposal.ID, result.ID); err != nil {
		return Proposal{}, fmt.Errorf("revision: attach decision to revision %q: %w", proposal.ID, err)
	}

	if result.State == store.DecisionAllowed {
		return s.Apply(ctx, proposal.ID)
	}
	return proposal, nil
}

// decide runs the revision through the decision path.
//
// The evaluator is built for this proposal alone, over a one-policy snapshot
// holding the reserved policy with the computed requirement in it. That is what
// makes "the stricter of old and new, plus the floor, minus the proposer" a
// challenge the quorum handler enforces rather than an arithmetic the governance
// path does afterwards: a proposer who submits an approval is refused as a
// non-target and the refusal is audited.
func (s *Service) decide(ctx context.Context, proposal Proposal, assessed assessment, ttl time.Duration) (decision.Result, error) {
	rec, _, err := s.governance(ctx, s.store.Pool())
	if err != nil {
		return decision.Result{}, err
	}
	var challenges []policy.Challenge
	if quorum, ok := assessed.requirement.Quorum(); ok {
		challenges = append(challenges, quorum)
	}
	gate := GovernancePolicy(challenges...)
	snapshot, err := engine.NewSnapshot(
		strconv.FormatInt(rec.SchemaVersion, 10), *GovernanceSchema(),
		[]engine.PolicyVersion{{
			Version: GovernancePolicyID + "@" + strconv.FormatInt(rec.Version, 10),
			Policy:  *gate,
		}})
	if err != nil {
		return decision.Result{}, fmt.Errorf("revision: build the governance snapshot: %w", err)
	}
	svc, err := decision.New(decision.Config{
		Store:      s.store,
		Audit:      s.audit,
		Evaluator:  engine.NewDecideEvaluator(snapshot),
		Challenges: s.challenges,
		PolicyVersion: func(context.Context, string) (int64, error) {
			return rec.Version, nil
		},
		TTL: s.ttl,
		// A governance proposal is not capped by how many ordinary decisions the
		// proposer already holds; the one-pending-revision index is the cap that
		// applies here.
		MaxOutstanding: -1,
		Now:            s.now,
	})
	if err != nil {
		return decision.Result{}, err
	}
	return svc.Decide(ctx, decision.Request{
		Caller: &identity.Subject{
			Kind: identity.SubjectUser, Issuer: "stamp", ID: proposal.ProposerID,
		},
		Input: engine.Input{
			Action:   ActionRevise,
			Subject:  engine.Entity{Type: EntityAdmin, ID: proposal.ProposerID},
			Resource: engine.Entity{Type: EntityPolicySet, ID: PolicySetID},
			Context: engine.Entity{Type: EntityRevision, ID: proposal.ID, Attributes: map[string]any{
				"delta_digest": proposal.DeltaDigest,
				"weakening":    proposal.Weakening,
				"change_count": int64(proposal.Delta.Len()),
			}},
		},
		// A zero TTL lets the decision service apply the service default, which
		// is the pending-revision lifetime cap D24 relies on to release a gate
		// that approvers have simply ignored.
		TTL: ttl,
	})
}

func (s *Service) insertProposal(ctx context.Context, p Proposal, proposer *identity.Subject) error {
	delta, err := p.Delta.MarshalJSON()
	if err != nil {
		return err
	}
	findings, err := marshalFindings(p.Findings)
	if err != nil {
		return err
	}
	digest, err := hex.DecodeString(p.DeltaDigest)
	if err != nil {
		return fmt.Errorf("revision: decode delta digest: %w", err)
	}
	return s.audit.InTx(ctx, func(ctx context.Context, tx pgx.Tx, ap *store.Appender) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO policy_revisions
				(id, proposer_id, delta, delta_digest, application_mode, state, weakening, findings, threshold, created_at)
			VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, $8, $9)`,
			p.ID, p.ProposerID, delta, digest, string(p.Mode), p.Weakening, findings, p.Threshold, p.CreatedAt)
		if err != nil {
			if isPendingConflict(err) {
				return ErrRevisionPending
			}
			return fmt.Errorf("revision: open revision %q: %w", p.ID, err)
		}
		if _, err := ap.Append(ctx, store.AuditEntry{
			Kind:    AuditKindRevisionProposed,
			Subject: p.ID,
			Payload: map[string]any{
				SeverityKey:        severityOf(p.Weakening),
				"proposer":         proposer.CallerID(),
				"application_mode": string(p.Mode),
				"delta_digest":     p.DeltaDigest,
				"weakening":        p.Weakening,
				"findings":         findingStrings(p.Findings),
				"threshold":        p.Threshold,
				"policies":         p.Delta.PolicyIDs(),
			},
		}); err != nil {
			return err
		}
		if s.floorlessMode(ctx, tx) {
			return s.bootstrap.recordUse(ctx, ap, AuditKindRevisionProposed, proposer.CallerID())
		}
		return nil
	})
}

// floorlessMode reports whether the installation is still in solo-admin mode,
// which is the only mode in which the bootstrap token authorizes anything.
func (s *Service) floorlessMode(ctx context.Context, tx pgx.Tx) bool {
	_, p, err := s.governance(ctx, tx)
	if err != nil {
		return false
	}
	_, locked := GovernanceQuorum(p)
	return !locked
}

// discard removes a proposal whose decision could not be opened, so a failed
// submission does not hold the gate.
func (s *Service) discard(ctx context.Context, id string) {
	_, _ = s.store.Pool().Exec(ctx,
		`DELETE FROM policy_revisions WHERE id = $1 AND state = 'pending' AND decision_id IS NULL`, id)
}

// ---------------------------------------------------------------------------
// reading, withdrawing, applying
// ---------------------------------------------------------------------------

// Get returns one revision.
func (s *Service) Get(ctx context.Context, id string) (Proposal, error) {
	return readProposal(ctx, s.store.Pool(), id)
}

// Pending returns the open revision, if there is one.
func (s *Service) Pending(ctx context.Context) (Proposal, bool, error) {
	var id string
	err := s.store.Pool().QueryRow(ctx,
		`SELECT id FROM policy_revisions WHERE state = 'pending'`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Proposal{}, false, nil
	}
	if err != nil {
		return Proposal{}, false, fmt.Errorf("revision: read the pending revision: %w", err)
	}
	p, err := readProposal(ctx, s.store.Pool(), id)
	return p, err == nil, err
}

// Withdraw closes a revision at the proposer's request (D24).
//
// It needs no quorum because it only returns the set to where it already is:
// the failure mode it answers is a proposal made in error holding the gate, and
// requiring approvals to undo a mistake is how the gate stays stuck.
func (s *Service) Withdraw(ctx context.Context, caller *identity.Subject, id string) (Proposal, error) {
	if caller == nil || caller.Kind != identity.SubjectUser {
		return Proposal{}, decision.ErrUnauthenticated
	}
	var out Proposal
	err := s.audit.InTx(ctx, func(ctx context.Context, tx pgx.Tx, ap *store.Appender) error {
		p, err := readProposal(ctx, tx, id)
		if err != nil {
			return err
		}
		if p.State != StatePending {
			return fmt.Errorf("revision %q is %s: %w", id, p.State, decision.ErrNotPending)
		}
		if p.ProposerID != caller.ID {
			return ErrNotProposer
		}
		if err := closeProposal(ctx, tx, id, StateWithdrawn, s.now().UTC()); err != nil {
			return err
		}
		if p.DecisionID != "" {
			if err := cancelDecision(ctx, tx, ap, p.DecisionID, "revision withdrawn by its proposer"); err != nil {
				return err
			}
		}
		if _, err := ap.Append(ctx, store.AuditEntry{
			Kind:    AuditKindRevisionWithdraw,
			Subject: id,
			Payload: map[string]any{SeverityKey: SeverityNotice, "actor": caller.CallerID()},
		}); err != nil {
			return err
		}
		p.State = StateWithdrawn
		out = p
		return nil
	})
	return out, err
}

// Reconcile applies every pending revision whose decision has resolved.
//
// A deployment calls it after a submission and on a timer. It is the seam
// between "the last approval landed" and "the revision took effect", and it is a
// separate step because the approval that completes a quorum arrives through the
// approval surface, which knows nothing about revisions.
func (s *Service) Reconcile(ctx context.Context) ([]Proposal, error) {
	pending, ok, err := s.Pending(ctx)
	if err != nil || !ok {
		return nil, err
	}
	applied, err := s.Apply(ctx, pending.ID)
	if errors.Is(err, ErrNotApproved) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return []Proposal{applied}, nil
}

// Apply takes an approved revision into effect.
//
// Everything lands in one transaction: the policy writes, the revalidation of
// every decision that is still open, the revision's own state, and the audit
// rows for all of it. A revision that took effect in one transaction and
// revalidated in another would leave a window in which a decision could resolve
// under a policy that is no longer in force.
func (s *Service) Apply(ctx context.Context, id string) (Proposal, error) {
	proposal, err := s.Get(ctx, id)
	if err != nil {
		return Proposal{}, err
	}
	if proposal.State != StatePending {
		return proposal, fmt.Errorf("revision %q is %s: %w", id, proposal.State, decision.ErrNotPending)
	}
	if proposal.DecisionID != "" {
		d, derr := store.GetDecision(ctx, s.store.Pool(), proposal.DecisionID)
		if derr != nil {
			return Proposal{}, derr
		}
		switch d.State {
		case store.DecisionAllowed:
			// The quorum is in.
		case store.DecisionPending:
			return proposal, ErrNotApproved
		default:
			return s.reject(ctx, proposal, string(d.State))
		}
	}

	tenant, err := s.tenantSet(ctx, s.store.Pool())
	if err != nil {
		return Proposal{}, err
	}
	result, err := tenantDelta(proposal.Delta).Result(tenant)
	if err != nil {
		return Proposal{}, err
	}
	snapshot, err := snapshotOf(result, proposal.ID)
	if err != nil {
		return Proposal{}, err
	}

	var report decision.RevalidateReport
	err = s.audit.InTx(ctx, func(ctx context.Context, tx pgx.Tx, ap *store.Appender) error {
		schemaVersion, err := s.writeSchema(ctx, tx, ap, proposal)
		if err != nil {
			return err
		}
		for _, c := range proposal.Delta.Changes {
			if err := s.writeChange(ctx, tx, ap, proposal, c, schemaVersion); err != nil {
				return err
			}
		}
		report, err = s.revalidator.Apply(ctx, tx, ap, decision.RevalidateRequest{
			Mode:       proposal.Mode,
			Snapshot:   snapshot,
			Resolver:   s.resolver,
			RevisionID: proposal.ID,
			Skip:       IsReserved,
			Now:        s.now().UTC(),
			PolicyVersion: func(ctx context.Context, q store.Querier, policyID string) (int64, error) {
				rec, err := store.EffectivePolicy(ctx, q, policyID)
				if err != nil {
					return 0, err
				}
				return rec.Version, nil
			},
		})
		if err != nil {
			return err
		}
		if err := closeProposal(ctx, tx, proposal.ID, StateApplied, s.now().UTC()); err != nil {
			return err
		}
		_, err = ap.Append(ctx, store.AuditEntry{
			Kind:    AuditKindRevisionApplied,
			Subject: proposal.ID,
			Payload: map[string]any{
				SeverityKey:             severityOf(proposal.Weakening),
				"application_mode":      string(proposal.Mode),
				"weakening":             proposal.Weakening,
				"findings":              findingStrings(proposal.Findings),
				"policies":              proposal.Delta.PolicyIDs(),
				"delta_digest":          proposal.DeltaDigest,
				"decisions_considered":  report.Considered,
				"decisions_denied":      report.Denied,
				"approvals_invalidated": report.Invalidated,
				"sources_fetched":       report.Fetched,
			},
		})
		return err
	})
	if err != nil {
		return Proposal{}, err
	}
	proposal.State = StateApplied
	proposal.Report = &report
	return proposal, nil
}

func (s *Service) writeSchema(ctx context.Context, tx pgx.Tx, ap *store.Appender, p Proposal) (int64, error) {
	if !p.Delta.SchemaChanged() || p.Delta.SchemaAfter == nil {
		latest, err := store.LatestSchema(ctx, tx)
		if err != nil {
			return 0, err
		}
		return latest.Version, nil
	}
	rec, err := store.PutSchema(ctx, tx, p.Delta.SchemaAfter, store.OriginForm, p.ProposerID)
	if err != nil {
		return 0, err
	}
	_, err = ap.Append(ctx, store.AuditEntry{
		Kind:    store.AuditKindSchemaPut,
		Subject: strconv.FormatInt(rec.Version, 10),
		Payload: map[string]any{
			"revision_id":  p.ID,
			"version":      rec.Version,
			"content_hash": hex.EncodeToString(rec.ContentHash[:]),
		},
	})
	return rec.Version, err
}

func (s *Service) writeChange(ctx context.Context, tx pgx.Tx, ap *store.Appender,
	p Proposal, c Change, schemaVersion int64,
) error {
	if c.Kind == ChangeDelete {
		rec, err := store.DeletePolicy(ctx, tx, c.PolicyID, p.ProposerID)
		if err != nil {
			return err
		}
		_, err = ap.Append(ctx, store.AuditEntry{
			Kind:    store.AuditKindPolicyDelete,
			Subject: c.PolicyID,
			Payload: map[string]any{"revision_id": p.ID, "version": rec.Version, "author": p.ProposerID},
		})
		return err
	}

	origin := store.OriginForm
	version := schemaVersion
	existing, err := store.EffectivePolicy(ctx, tx, c.PolicyID)
	switch {
	case err == nil:
		origin = existing.Origin
		if IsReserved(c.PolicyID) {
			// The reserved policy is written against the governance schema and
			// stays there whatever the tenant's schema does.
			version = existing.SchemaVersion
		}
	case !errors.Is(err, store.ErrNotFound):
		return err
	}
	if c.Kind == ChangeTakeOwnership {
		origin = c.ToOrigin
	}
	rec, err := store.PutPolicy(ctx, tx, store.PolicyInput{
		Policy:          c.After,
		SchemaVersion:   version,
		Origin:          origin,
		Author:          p.ProposerID,
		AssumeOwnership: c.Kind == ChangeTakeOwnership,
	})
	if err != nil {
		return err
	}
	_, err = ap.Append(ctx, store.AuditEntry{
		Kind:    store.AuditKindPolicyPut,
		Subject: c.PolicyID,
		Payload: map[string]any{
			"revision_id":  p.ID,
			"change":       string(c.Kind),
			"version":      rec.Version,
			"origin":       string(rec.Origin),
			"content_hash": hex.EncodeToString(rec.ContentHash[:]),
			"author":       p.ProposerID,
		},
	})
	return err
}

func (s *Service) reject(ctx context.Context, p Proposal, why string) (Proposal, error) {
	err := s.audit.InTx(ctx, func(ctx context.Context, tx pgx.Tx, ap *store.Appender) error {
		if err := closeProposal(ctx, tx, p.ID, StateRejected, s.now().UTC()); err != nil {
			return err
		}
		_, err := ap.Append(ctx, store.AuditEntry{
			Kind:    AuditKindRevisionRejected,
			Subject: p.ID,
			Payload: map[string]any{SeverityKey: SeverityNotice, "reason": why},
		})
		return err
	})
	if err != nil {
		return Proposal{}, err
	}
	p.State = StateRejected
	return p, nil
}

// snapshotOf builds the evaluable set a revalidation judges against.
//
// Version identifiers carry the policy identifier as well as the revision. The
// compile cache is keyed by version alone, so two policies sharing one
// identifier would share one compiled condition — a wrong allow rather than a
// slow one.
func snapshotOf(set *policy.Set, revisionID string) (*engine.Snapshot, error) {
	versions := make([]engine.PolicyVersion, 0, len(set.Policies))
	for i := range set.Policies {
		if IsReserved(set.Policies[i].ID) {
			continue
		}
		versions = append(versions, engine.PolicyVersion{
			Version: set.Policies[i].ID + "@" + revisionID,
			Policy:  set.Policies[i],
		})
	}
	snap, err := engine.NewSnapshot(revisionID, set.Schema, versions)
	if err != nil {
		return nil, fmt.Errorf("revision: build the revised snapshot: %w", err)
	}
	return snap, nil
}

// cancelDecision resolves a governance decision whose revision went away.
//
// Like the revalidator's resolve, it writes on the caller's transaction rather
// than through the store's helper: the audit writer holds its append lock across
// the whole audited transaction, so a nested call that opened its own would
// deadlock against the writer this Appender belongs to.
func cancelDecision(ctx context.Context, tx pgx.Tx, ap *store.Appender, decisionID, why string) error {
	tag, err := tx.Exec(ctx, `
		UPDATE decisions
		SET state = 'cancelled', resolved_at = now(), updated_at = now(),
		    next_deadline = NULL, next_deadline_kind = NULL
		WHERE id = $1 AND state = 'pending'`, decisionID)
	if err != nil {
		return fmt.Errorf("revision: cancel decision %q: %w", decisionID, err)
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE challenge_progress SET state = 'cancelled'
		WHERE decision_id = $1 AND state = 'pending'`, decisionID); err != nil {
		return fmt.Errorf("revision: cancel challenges of %q: %w", decisionID, err)
	}
	_, err = ap.Append(ctx, store.AuditEntry{
		Kind:    store.AuditKindDecisionResolved,
		Subject: decisionID,
		Payload: map[string]any{
			"state": string(store.DecisionCancelled),
			"actor": string(decision.TriggerCancellation) + ":" + why,
		},
	})
	return err
}

// ---------------------------------------------------------------------------
// rows
// ---------------------------------------------------------------------------

func readProposal(ctx context.Context, q store.Querier, id string) (Proposal, error) {
	var (
		p          Proposal
		decisionID *string
		delta      []byte
		digest     []byte
		findings   []byte
		mode       string
		state      string
	)
	err := q.QueryRow(ctx, `
		SELECT id, decision_id, proposer_id, delta::text, delta_digest, application_mode,
		       state, weakening, findings::text, threshold, created_at, resolved_at
		FROM policy_revisions WHERE id = $1`, id).Scan(
		&p.ID, &decisionID, &p.ProposerID, &delta, &digest, &mode,
		&state, &p.Weakening, &findings, &p.Threshold, &p.CreatedAt, &p.ResolvedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Proposal{}, store.ErrNotFound
	}
	if err != nil {
		return Proposal{}, fmt.Errorf("revision: read revision %q: %w", id, err)
	}
	if decisionID != nil {
		p.DecisionID = *decisionID
	}
	p.Mode = decision.ApplicationMode(mode)
	p.State = State(state)
	p.DeltaDigest = hex.EncodeToString(digest)
	p.CreatedAt = p.CreatedAt.UTC()
	if err := p.Delta.UnmarshalJSON(delta); err != nil {
		return Proposal{}, err
	}
	if err := unmarshalFindings(findings, &p.Findings); err != nil {
		return Proposal{}, err
	}
	return p, nil
}

func closeProposal(ctx context.Context, q store.Querier, id string, state State, at time.Time) error {
	tag, err := q.Exec(ctx,
		`UPDATE policy_revisions SET state = $2, resolved_at = $3 WHERE id = $1 AND state = 'pending'`,
		id, string(state), at)
	if err != nil {
		return fmt.Errorf("revision: close revision %q: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("revision %q is not pending: %w", id, store.ErrConflict)
	}
	return nil
}

func severityOf(weakening bool) string {
	if weakening {
		return SeverityCritical
	}
	return SeverityNotice
}

func findingStrings(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.String())
	}
	return out
}

// isPendingConflict reports the unique-index violation that means another
// revision holds the gate.
func isPendingConflict(err error) bool {
	if errors.Is(err, store.ErrConflict) {
		return true
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func marshalFindings(findings []Finding) ([]byte, error) {
	if findings == nil {
		findings = []Finding{}
	}
	out, err := json.Marshal(findings)
	if err != nil {
		return nil, fmt.Errorf("revision: encode findings: %w", err)
	}
	return out, nil
}

func unmarshalFindings(raw []byte, out *[]Finding) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("revision: decode findings: %w", err)
	}
	return nil
}
