package challenge

// quorum.go implements R3's quorum challenge: m distinct approvals from a
// resolved set of approvers.
//
// Three things in here are load-bearing beyond "count to m".
//
// The approver is the token's `sub` and nothing else. There is no approver
// field in the submission payload, and a payload that carries one is refused
// rather than ignored, because a field that is ignored today is a field
// somebody reads tomorrow. D7 puts approver identity in the external IdP, so
// the only statement about who is approving that STAMP will accept is the one
// the IdP signed.
//
// The set is resolved at issue and frozen in Detail. R18 allows three
// resolutions and v1 implements two of them — an explicit list and a token
// claim. The third, an IdP group, joins in U13 as a fact source; the seam is
// [GroupResolver] and until something fills it a policy that reaches for it
// fails at issue rather than opening a challenge nothing can satisfy.
//
// Every approval is bound to a hash of the material the approver reviewed
// (R31). The hash is computed at issue over the frozen decision, frozen in
// Detail beside the terms, handed to the approver by [Quorum.Review], and
// recomputed at submit. U9 verifies that hash across a policy revision; this
// unit's job is that the number it verifies is the right one.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// Errors the quorum handler adds to the contract's sentinels.
var (
	// ErrGroupSourceUnsupported reports an approver set that resolves from an
	// IdP group while no [GroupResolver] is configured. It wraps
	// [ErrUnsupportedSpec]: to a caller it is a declaration this build cannot
	// serve, and it is refused at issue rather than at collection time.
	ErrGroupSourceUnsupported = errors.New("challenge: idp group approver sets need a group resolver")

	// ErrBindingChanged reports a submission against material that no longer
	// hashes to the value the challenge was issued under (R31). The approvals
	// already collected belong to different material, so this is fail-closed:
	// the revision path re-issues, it does not paper over.
	ErrBindingChanged = errors.New("challenge: the approval material changed since the challenge was issued")

	// ErrVerdictUnsupported reports a verdict v1 does not collect. The store
	// names a rejection verdict, but what a rejection does to a decision is not
	// fixed by any requirement yet, so it is refused rather than recorded as
	// something the lifecycle would have to guess about.
	ErrVerdictUnsupported = errors.New("challenge: only approvals are collected in this version")
)

// ApprovalBindingContext is the domain separator in the binding hash. It is
// part of the hashed material so that a digest computed for an approval cannot
// be replayed as a digest computed for anything else.
const ApprovalBindingContext = "stamp.approval-binding.v1"

// ResolutionMode names how an approver set was resolved (R18).
type ResolutionMode string

// The resolution modes. v1 resolves the first two; the third is a seam.
const (
	// ResolveMembers is an explicit list of approver identifiers.
	ResolveMembers ResolutionMode = "members"
	// ResolveClaim admits any identity whose token asserts a named claim.
	ResolveClaim ResolutionMode = "claim"
	// ResolveGroupSource is an IdP group lookup, resolved to members at issue.
	ResolveGroupSource ResolutionMode = "source"
)

// QuorumDetail is what a quorum challenge persists on its challenge row.
//
// It is the terms the challenge was opened under, frozen: the threshold, the
// resolution, and the binding hash of the material as it stood. The handler
// gets it back verbatim at Submit and Status, which is why this package never
// needs to serialize the policy AST.
type QuorumDetail struct {
	// Threshold is how many distinct approvals satisfy the challenge.
	Threshold int `json:"threshold"`
	// Mode is which resolution produced the set.
	Mode ResolutionMode `json:"mode"`
	// Members is the resolved approver list, deduplicated and sorted. It is set
	// for ResolveMembers and for a resolved ResolveGroupSource.
	Members []string `json:"members,omitempty"`
	// Claim is the claim an approver's token must assert, for ResolveClaim.
	Claim string `json:"claim,omitempty"`
	// Source names the group source a ResolveGroupSource set came from. It is
	// recorded for the audit trail; the resolved names are in Members.
	Source string `json:"source,omitempty"`
	// BindingHash is R31's digest, hex-encoded.
	BindingHash string `json:"binding_hash"`
}

// QuorumSubmission is the body of an approval submission.
//
// There is deliberately no approver field. Unknown members are refused rather
// than ignored, so a client that tries to name one gets an error instead of a
// silently discarded claim about who is approving.
type QuorumSubmission struct {
	// Verdict is "approve", which is also what an empty body means.
	Verdict string `json:"verdict,omitempty"`
	// BindingHash, when present, is the digest the approver was shown. It must
	// equal the one the challenge was issued under.
	BindingHash string `json:"binding_hash,omitempty"`
}

// GroupResolver resolves an IdP-group approver set to member identifiers.
//
// This is R18's third mode and the seam U13 fills: a group lookup is shaped
// exactly like a fact source, so it resolves once at issue and freezes into the
// challenge alongside the fact snapshot. Nothing implements it in v1, and a
// nil resolver makes a group-backed approver set an issue-time refusal.
type GroupResolver interface {
	ResolveApprovers(ctx context.Context, ref policy.SourceRef, decision DecisionContext) ([]string, error)
}

// QuorumConfig configures a [Quorum].
type QuorumConfig struct {
	// Audit records approvals. Required to collect any; a handler without one
	// can still issue, judge targets and compute hashes, which is what the
	// pure-function tests and the authoring path need.
	Audit *store.AuditWriter
	// DB reads the approval rows a count is recomputed from. Required to
	// collect or to report progress.
	DB store.Querier
	// Groups resolves IdP-group approver sets. Nil in v1.
	Groups GroupResolver
}

// Quorum is the m-of-n approval handler.
type Quorum struct {
	audit  *store.AuditWriter
	db     store.Querier
	groups GroupResolver
}

// Compile-time proof that the handler serves the whole contract, including the
// optional read rule.
var (
	_ Handler  = (*Quorum)(nil)
	_ Targeter = (*Quorum)(nil)
)

// NewQuorum builds the quorum handler.
func NewQuorum(cfg QuorumConfig) (*Quorum, error) {
	if (cfg.Audit == nil) != (cfg.DB == nil) {
		return nil, errors.New("challenge: a quorum handler needs both an audit writer and a database, or neither")
	}
	return &Quorum{audit: cfg.Audit, db: cfg.DB, groups: cfg.Groups}, nil
}

// Kind implements [Handler].
func (q *Quorum) Kind() policy.ChallengeType { return policy.ChallengeQuorum }

// Issue resolves the approver set, freezes it with the threshold and the
// binding hash, and opens the challenge pending.
//
// It sets no deadline. A quorum ends when its decision does, so a timer here
// would be a second expiry that has to be kept in step with the first. The
// handler still answers a deadline that was set for it — see [Quorum.Status].
func (q *Quorum) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	spec, ok := req.Spec.(policy.Quorum)
	if !ok {
		return IssueResult{}, fmt.Errorf("%w: %T is not a quorum", ErrUnsupportedSpec, req.Spec)
	}
	detail, err := q.resolve(ctx, spec, req.Decision)
	if err != nil {
		return IssueResult{}, err
	}
	sum, err := ApprovalBindingHash(req.Decision, detail)
	if err != nil {
		return IssueResult{}, err
	}
	detail.BindingHash = hex.EncodeToString(sum[:])
	return IssueResult{State: StatePending, Detail: detail}, nil
}

// resolve turns a declaration into the frozen terms of one challenge.
func (q *Quorum) resolve(ctx context.Context, spec policy.Quorum, dec DecisionContext) (QuorumDetail, error) {
	if spec.Threshold < 1 {
		return QuorumDetail{}, fmt.Errorf("%w: a quorum of %d approvals is not a quorum",
			ErrUnsupportedSpec, spec.Threshold)
	}
	detail := QuorumDetail{Threshold: spec.Threshold}
	switch set := spec.Approvers; {
	case set.Source != nil:
		if q.groups == nil {
			return QuorumDetail{}, fmt.Errorf("%w: %w: source %q",
				ErrUnsupportedSpec, ErrGroupSourceUnsupported, set.Source.Name)
		}
		members, err := q.groups.ResolveApprovers(ctx, *set.Source, dec)
		if err != nil {
			return QuorumDetail{}, fmt.Errorf("challenge: resolve approver group %q: %w", set.Source.Name, err)
		}
		detail.Mode = ResolveGroupSource
		detail.Source = set.Source.Name
		detail.Members = normalizeMembers(members)
	case set.Claim != "":
		detail.Mode = ResolveClaim
		detail.Claim = set.Claim
	default:
		detail.Mode = ResolveMembers
		detail.Members = normalizeMembers(set.Members)
	}

	// A set that cannot reach its own threshold is a decision that can never
	// resolve. Policy validation refuses it at authoring time for an explicit
	// list; a resolved group can only be counted here.
	if detail.Mode != ResolveClaim && len(detail.Members) < detail.Threshold {
		return QuorumDetail{}, fmt.Errorf("%w: a quorum of %d cannot be met by %d distinct approver(s)",
			ErrUnsupportedSpec, detail.Threshold, len(detail.Members))
	}
	return detail, nil
}

// Submit records one approval and reports the resulting progress.
//
// It is idempotent by construction rather than by checking first: the store's
// uniqueness constraint is what makes a duplicate submission a conflict, and a
// conflict here is success with no second row. A quorum that could be met by
// one approver racing themselves would not be a quorum, and a read-then-write
// check would leave exactly that race open.
func (q *Quorum) Submit(ctx context.Context, req SubmitRequest) (SubmitResult, error) {
	if q.audit == nil || q.db == nil {
		return SubmitResult{}, errors.New("challenge: this quorum handler collects nothing: it has no store")
	}
	detail, err := decodeQuorumDetail(req.Detail)
	if err != nil {
		return SubmitResult{}, err
	}
	body, err := decodeQuorumSubmission(req.Payload)
	if err != nil {
		return SubmitResult{}, err
	}

	// The approver is the token's subject. Everything else about the request —
	// body, headers, path — has no say in who is approving.
	approver, err := approverID(req.Submitter)
	if err != nil {
		return SubmitResult{}, err
	}
	target, err := isTarget(detail, req.Submitter)
	if err != nil {
		return SubmitResult{}, err
	}
	if !target {
		return SubmitResult{}, fmt.Errorf("%w: %q is not in the approver set of %s",
			ErrNotTarget, approver, req.Instance)
	}

	sum, err := ApprovalBindingHash(req.Decision, detail)
	if err != nil {
		return SubmitResult{}, err
	}
	current := hex.EncodeToString(sum[:])
	if !strings.EqualFold(current, detail.BindingHash) {
		return SubmitResult{}, fmt.Errorf("%w: %s was issued over %s and now reads %s",
			ErrBindingChanged, req.Instance, detail.BindingHash, current)
	}
	if body.BindingHash != "" && !strings.EqualFold(body.BindingHash, detail.BindingHash) {
		return SubmitResult{}, fmt.Errorf("%w: the submission reviewed %s, not %s",
			ErrBindingChanged, body.BindingHash, detail.BindingHash)
	}

	_, err = q.audit.RecordApproval(ctx, store.NewApproval{
		DecisionID:       req.Instance.DecisionID,
		ChallengeOrdinal: req.Instance.Ordinal,
		ApproverID:       approver,
		Verdict:          store.VerdictApprove,
		BindingHash:      sum,
		Detail: map[string]any{
			"mode":      string(detail.Mode),
			"issuer":    req.Submitter.Issuer,
			"caller_id": req.Submitter.CallerID(),
			"at":        req.Now.UTC().Format(time.RFC3339Nano),
		},
	})
	// A duplicate is not an error to the caller: the approval they are
	// resubmitting is already recorded, and the progress below is the answer.
	if err != nil && !errors.Is(err, store.ErrConflict) {
		return SubmitResult{}, err
	}

	have, err := q.count(ctx, req.Instance)
	if err != nil {
		return SubmitResult{}, err
	}
	return SubmitResult{State: reached(have, detail.Threshold), Have: have, Need: detail.Threshold}, nil
}

// Status recomputes progress from the approval rows.
//
// It recounts rather than trusting the challenge row because the approval and
// the challenge state are two statements: a crash between them leaves the
// evidence written and the state stale, and the evidence is the one that has to
// win. A stored terminal state is never walked back — a cancelled challenge
// does not become satisfied because its rows still add up.
//
// A quorum that has a deadline and has not met it is failed, which is the
// opposite of what an elapsed delay means. That asymmetry is why the contract
// answers elapsed timers through this read instead of through a callback.
func (q *Quorum) Status(ctx context.Context, req StatusRequest) (Status, error) {
	detail, err := decodeQuorumDetail(req.Detail)
	if err != nil {
		return Status{}, err
	}
	have, err := q.count(ctx, req.Instance)
	if err != nil {
		return Status{}, err
	}
	state := req.Stored
	if !state.Terminal() {
		switch {
		case have >= detail.Threshold:
			state = StateSatisfied
		case req.Deadline != nil && !req.Now.Before(*req.Deadline):
			state = StateFailed
		default:
			state = StatePending
		}
	}
	return Status{State: state, Have: have, Need: detail.Threshold, Deadline: req.Deadline}, nil
}

// IsTarget implements [Targeter] for R40's read rule: a decision may be read by
// the caller who created it or by an approver it is waiting on.
func (q *Quorum) IsTarget(_ context.Context, req TargetRequest) (bool, error) {
	detail, err := decodeQuorumDetail(req.Detail)
	if err != nil {
		return false, err
	}
	return isTarget(detail, req.Subject)
}

// QuorumReviewRequest asks for the material one approver is being asked to
// judge.
type QuorumReviewRequest struct {
	// DecisionID and Ordinal name the challenge.
	DecisionID string
	Ordinal    int
	// Subject is the authenticated reader. Required.
	Subject *identity.Subject
	// Now is the instant the decision's expiry is judged against.
	Now time.Time
}

// QuorumReviewDecision is the frozen decision behind an approval screen.
//
// The JSON members are the stored ones: the request and the facts as they were
// frozen at creation, never as they read now. An approval binds to what the
// approver saw, so what the approver is shown has to be what the hash covers.
type QuorumReviewDecision struct {
	ID           string          `json:"id"`
	CallerID     string          `json:"caller_id"`
	SubjectID    string          `json:"subject_id"`
	ResourceID   string          `json:"resource_id"`
	Action       string          `json:"action"`
	PolicyID     string          `json:"policy_id"`
	Request      json.RawMessage `json:"request"`
	FactSnapshot json.RawMessage `json:"fact_snapshot"`
	Obligations  json.RawMessage `json:"obligations"`
	CreatedAt    time.Time       `json:"created_at"`
	ExpiresAt    time.Time       `json:"expires_at"`
}

// QuorumReview is what an approver is handed before they approve.
type QuorumReview struct {
	Ordinal int   `json:"ordinal"`
	State   State `json:"state"`
	Have    int   `json:"have"`
	Need    int   `json:"need"`
	// Approvers is the resolved set, when the set is a list. A claim-resolved
	// challenge has no list to show.
	Approvers []string       `json:"approvers,omitempty"`
	Mode      ResolutionMode `json:"mode"`
	// BindingHash is the digest this approval will be recorded against. An
	// approver echoes it back on submission to state which material they read.
	BindingHash string               `json:"binding_hash"`
	Decision    QuorumReviewDecision `json:"decision"`
}

// Review returns the material a target approver is judging.
//
// It refuses anyone the challenge is not waiting on, and refuses an expired or
// resolved decision, so that a screen is never rendered whose submission would
// be turned away.
func (q *Quorum) Review(ctx context.Context, req QuorumReviewRequest) (QuorumReview, error) {
	if q.db == nil {
		return QuorumReview{}, errors.New("challenge: this quorum handler has no store to read")
	}
	d, err := store.ActiveDecisionTx(ctx, q.db, req.DecisionID, req.Now)
	if err != nil {
		return QuorumReview{}, err
	}
	progress, err := store.ChallengeProgressFor(ctx, q.db, req.DecisionID)
	if err != nil {
		return QuorumReview{}, err
	}
	idx := slices.IndexFunc(progress, func(p store.ChallengeProgress) bool { return p.Ordinal == req.Ordinal })
	if idx < 0 || progress[idx].Kind != policy.ChallengeQuorum {
		return QuorumReview{}, fmt.Errorf("challenge: decision %q has no quorum at ordinal %d: %w",
			req.DecisionID, req.Ordinal, store.ErrNotFound)
	}
	row := progress[idx]

	detail, err := decodeQuorumDetail(row.Detail)
	if err != nil {
		return QuorumReview{}, err
	}
	target, err := isTarget(detail, req.Subject)
	if err != nil {
		return QuorumReview{}, err
	}
	if !target {
		return QuorumReview{}, fmt.Errorf("%w: challenge %d of decision %q",
			ErrNotTarget, req.Ordinal, req.DecisionID)
	}

	instance := Instance{DecisionID: req.DecisionID, Ordinal: req.Ordinal, Kind: policy.ChallengeQuorum}
	have, err := q.count(ctx, instance)
	if err != nil {
		return QuorumReview{}, err
	}
	return QuorumReview{
		Ordinal:     req.Ordinal,
		State:       State(row.State),
		Have:        have,
		Need:        detail.Threshold,
		Approvers:   detail.Members,
		Mode:        detail.Mode,
		BindingHash: detail.BindingHash,
		Decision: QuorumReviewDecision{
			ID:           d.ID,
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
		},
	}, nil
}

func (q *Quorum) count(ctx context.Context, in Instance) (int, error) {
	if q.db == nil {
		return 0, errors.New("challenge: this quorum handler has no store to count in")
	}
	return store.CountApprovals(ctx, q.db, in.DecisionID, in.Ordinal, store.VerdictApprove)
}

// ---------------------------------------------------------------------------
// target resolution
// ---------------------------------------------------------------------------

// approverID is the identifier an approval is recorded and counted under: the
// `sub` of the verified end-user token.
//
// A workload credential is never an approver. The console surface already
// admits only end-user tokens, so this is the same rule stated twice — which is
// the point of D21: the control lives in the code path, not only in the mount
// table a future route could get wrong.
func approverID(s *identity.Subject) (string, error) {
	switch {
	case s == nil:
		return "", fmt.Errorf("%w: no authenticated submitter", ErrNotTarget)
	case s.Kind != identity.SubjectUser:
		return "", fmt.Errorf("%w: %s is a %s credential, and approvers are people",
			ErrNotTarget, s.CallerID(), s.Kind)
	case strings.TrimSpace(s.ID) == "":
		return "", fmt.Errorf("%w: the credential carries no subject identifier", ErrNotTarget)
	}
	return s.ID, nil
}

// isTarget answers whether an identity is in the frozen approver set.
//
// It is fail-closed everywhere: an unreadable claim, an absent credential and a
// resolution this build does not know are all "not a target".
func isTarget(detail QuorumDetail, s *identity.Subject) (bool, error) {
	if _, err := approverID(s); err != nil {
		return false, nil //nolint:nilerr // not being an approver is an answer, not a failure
	}
	switch detail.Mode {
	case ResolveMembers, ResolveGroupSource:
		return slices.Contains(detail.Members, s.ID), nil
	case ResolveClaim:
		return assertsClaim(s, detail.Claim), nil
	default:
		return false, fmt.Errorf("%w: approver set mode %q", ErrInvalidPayload, detail.Mode)
	}
}

// assertsClaim reports whether the token affirmatively carries the named claim.
//
// The declaration names a claim and no value to compare it against, so this is
// presence with a truthiness rule: false, null, an empty string and an empty
// list are not assertions. The operator's side of the bargain is that the IdP
// releases the claim only to the people who should hold it — a claim scoped to
// a group's members is the shape this mode is for. Testing a value against a
// named group is the source mode, which arrives with U13.
func assertsClaim(s *identity.Subject, name string) bool {
	if name == "" {
		return false
	}
	var claims map[string]any
	if err := s.Claims(&claims); err != nil {
		return false
	}
	value, ok := claims[name]
	if !ok {
		return false
	}
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return strings.TrimSpace(v) != ""
	case float64:
		return v != 0
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	default:
		return true
	}
}

// ---------------------------------------------------------------------------
// the binding hash (R31)
// ---------------------------------------------------------------------------

// ApprovalBindingHash computes the digest an approval is bound to.
//
// The inputs are the decision's frozen identity and content, the fact snapshot,
// the obligations, and the terms of the challenge other than its threshold. Two
// things are excluded on purpose and R31 names both: the policy version
// identifier and the quorum number. A revision that only raises the threshold
// has not changed anything an approver was asked to judge, and evaporating the
// approvals already collected would make raising a quorum harder than lowering
// it.
//
// Two further exclusions are this unit's: the decision's timestamps, and the
// challenge's ordinal. expires_at is still moving while sibling challenges are
// being issued — a delay longer than the decision's lifetime extends it — so a
// hash covering it would depend on the order handlers ran in. created_at and
// the ordinal are stable but are not terms of the authorization, and every
// input that is not a term is an approval that evaporates for no reason.
//
// Every JSON member is re-serialized from its decoded form before hashing. The
// same content arrives as different bytes on either side of the database, and a
// hash over the bytes would differ between issue and submit.
func ApprovalBindingHash(dec DecisionContext, detail QuorumDetail) ([32]byte, error) {
	approvers := map[string]any{"mode": string(detail.Mode)}
	switch detail.Mode {
	case ResolveClaim:
		approvers["claim"] = detail.Claim
	case ResolveGroupSource:
		approvers["source"] = detail.Source
		approvers["members"] = normalizeMembers(detail.Members)
	case ResolveMembers:
		approvers["members"] = normalizeMembers(detail.Members)
	default:
		return [32]byte{}, fmt.Errorf("%w: approver set mode %q", ErrInvalidPayload, detail.Mode)
	}

	request, err := decodeJSON(dec.Request)
	if err != nil {
		return [32]byte{}, fmt.Errorf("challenge: binding hash: request: %w", err)
	}
	facts, err := decodeJSON(dec.FactSnapshot)
	if err != nil {
		return [32]byte{}, fmt.Errorf("challenge: binding hash: fact snapshot: %w", err)
	}
	obligations, err := decodeJSON(dec.Obligations)
	if err != nil {
		return [32]byte{}, fmt.Errorf("challenge: binding hash: obligations: %w", err)
	}

	material := map[string]any{
		"binding": ApprovalBindingContext,
		"decision": map[string]any{
			"id":          dec.DecisionID,
			"caller_id":   dec.CallerID,
			"subject_id":  dec.SubjectID,
			"resource_id": dec.ResourceID,
			"action":      dec.Action,
			"policy_id":   dec.PolicyID,
		},
		"request":       request,
		"fact_snapshot": facts,
		"obligations":   obligations,
		"challenge": map[string]any{
			"kind":      string(policy.ChallengeQuorum),
			"approvers": approvers,
		},
	}
	// encoding/json sorts map keys, and every value in here is either a Go
	// value we built or one decoded into the same generic shapes, so the
	// encoding is a function of the content alone.
	raw, err := json.Marshal(material)
	if err != nil {
		return [32]byte{}, fmt.Errorf("challenge: binding hash: %w", err)
	}
	return sha256.Sum256(raw), nil
}

func decodeJSON(raw json.RawMessage) (any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// decoding
// ---------------------------------------------------------------------------

func decodeQuorumDetail(raw json.RawMessage) (QuorumDetail, error) {
	var detail QuorumDetail
	if err := json.Unmarshal(raw, &detail); err != nil {
		return QuorumDetail{}, fmt.Errorf("%w: quorum detail: %w", ErrInvalidPayload, err)
	}
	if detail.Mode == "" {
		return QuorumDetail{}, fmt.Errorf("%w: quorum detail names no approver resolution", ErrInvalidPayload)
	}
	return detail, nil
}

// decodeQuorumSubmission reads the submission body.
//
// Unknown members are refused. The one a client is most likely to send is an
// approver name, and an ignored approver name is a client that believes it can
// approve on somebody's behalf right up until an audit says otherwise.
func decodeQuorumSubmission(raw json.RawMessage) (QuorumSubmission, error) {
	body := QuorumSubmission{}
	if len(raw) == 0 || string(raw) == "null" {
		return body, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		return QuorumSubmission{}, fmt.Errorf("%w: approval submission: %w", ErrInvalidPayload, err)
	}
	switch strings.ToLower(strings.TrimSpace(body.Verdict)) {
	case "", store.VerdictApprove:
		body.Verdict = store.VerdictApprove
	case store.VerdictReject:
		return QuorumSubmission{}, fmt.Errorf("%w: %q", ErrVerdictUnsupported, body.Verdict)
	default:
		return QuorumSubmission{}, fmt.Errorf("%w: unknown verdict %q", ErrInvalidPayload, body.Verdict)
	}
	if body.BindingHash != "" {
		if _, err := hex.DecodeString(body.BindingHash); err != nil {
			return QuorumSubmission{}, fmt.Errorf("%w: binding_hash is not a hex digest: %w", ErrInvalidPayload, err)
		}
	}
	return body, nil
}

// normalizeMembers deduplicates and sorts an approver list.
//
// The set is a set: an approver listed twice is one approver, and the order the
// author wrote them in is not a term of the authorization. Sorting is what
// keeps the binding hash stable when a revision only reorders the list.
func normalizeMembers(members []string) []string {
	out := make([]string, 0, len(members))
	for _, m := range members {
		if trimmed := strings.TrimSpace(m); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func reached(have, need int) State {
	if have >= need {
		return StateSatisfied
	}
	return StatePending
}
