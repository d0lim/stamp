package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/d0lim/stamp/internal/policy"
)

// ErrDecisionExpired reports that a decision's own deadline has passed. It is
// derived from expires_at and from nothing else.
var ErrDecisionExpired = errors.New("store: decision has expired")

// DecisionState is a decision's lifecycle state.
type DecisionState string

// The decision states.
const (
	DecisionPending   DecisionState = "pending"
	DecisionAllowed   DecisionState = "allowed"
	DecisionDenied    DecisionState = "denied"
	DecisionExpired   DecisionState = "expired"
	DecisionCancelled DecisionState = "cancelled"
)

// Terminal reports whether no further transition is possible.
func (s DecisionState) Terminal() bool { return s != DecisionPending }

// ChallengeState is one challenge's progress state.
type ChallengeState string

// The challenge progress states.
const (
	ChallengePending   ChallengeState = "pending"
	ChallengeSatisfied ChallengeState = "satisfied"
	ChallengeFailed    ChallengeState = "failed"
	ChallengeCancelled ChallengeState = "cancelled"
)

// DeadlineKind discriminates what the scheduler's next_deadline column is
// counting down to.
//
// It exists because the sweeper has to branch on the answer: an expiry deadline
// resolves the decision as expired, a challenge deadline resolves that one
// challenge. Without the discriminator the sweeper would have to re-derive the
// reason, and a wrong derivation expires decisions that were merely waiting.
type DeadlineKind string

// The deadline kinds.
const (
	DeadlineExpiry    DeadlineKind = "expiry"
	DeadlineChallenge DeadlineKind = "challenge"
)

// Decision is a stored decision.
//
// ExpiresAt and NextDeadline are separate on purpose and are read by different
// code. An entry-time check — status read, approval submission, transition
// function — reads ExpiresAt. The sweeper reads NextDeadline and branches on
// NextDeadlineKind. Folding them into one column would mean a decision with a
// delay timer of five minutes and an expiry of an hour reads as expired five
// minutes in.
type Decision struct {
	ID               string
	CallerID         string
	PolicyID         string
	PolicyVersion    int64
	SubjectID        string
	ResourceID       string
	Action           string
	Request          json.RawMessage
	FactSnapshot     json.RawMessage
	Obligations      json.RawMessage
	State            DecisionState
	CreatedAt        time.Time
	UpdatedAt        time.Time
	ExpiresAt        time.Time
	NextDeadline     *time.Time
	NextDeadlineKind DeadlineKind
	ResolvedAt       *time.Time
}

// Expired reports whether the decision's own deadline has passed. It reads
// ExpiresAt and never NextDeadline.
func (d *Decision) Expired(now time.Time) bool { return !now.Before(d.ExpiresAt) }

// ChallengeProgress is one challenge's state on a decision.
type ChallengeProgress struct {
	DecisionID  string
	Ordinal     int
	Kind        policy.ChallengeType
	State       ChallengeState
	Deadline    *time.Time
	SatisfiedAt *time.Time
	Detail      json.RawMessage
}

// NewChallenge describes one challenge to open with a decision. Ordinal is the
// challenge's index in the policy, which is what ties a progress row back to
// the declaration it came from.
type NewChallenge struct {
	Ordinal  int
	Kind     policy.ChallengeType
	Deadline *time.Time
	Detail   any
}

// NewDecision is a request to create a decision.
type NewDecision struct {
	ID            string
	CallerID      string
	PolicyID      string
	PolicyVersion int64
	SubjectID     string
	ResourceID    string
	Action        string
	Request       any
	FactSnapshot  any
	Obligations   any
	ExpiresAt     time.Time
	Challenges    []NewChallenge
}

// NewDecisionID returns a random UUIDv4 in string form.
func NewDecisionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("store: generate decision id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

// CreateDecision writes the decision, its challenge progress rows and the audit
// record in one transaction.
//
// It hangs off AuditWriter rather than Store so that "the decision and its audit
// row land together" is a property of the type rather than of every caller
// remembering. The policy version and the fact snapshot are frozen onto the row
// in that same transaction: a decision has to stay explainable by the policy
// text and the facts that produced it, not by whatever those say later.
func (w *AuditWriter) CreateDecision(ctx context.Context, in NewDecision) (Decision, error) {
	if in.PolicyID == "" || in.PolicyVersion <= 0 {
		return Decision{}, errors.New("store: a decision must name the policy version it was evaluated against")
	}
	if in.ExpiresAt.IsZero() {
		return Decision{}, errors.New("store: a decision must have an expires_at")
	}
	id := in.ID
	if id == "" {
		generated, err := NewDecisionID()
		if err != nil {
			return Decision{}, err
		}
		id = generated
	}

	request, err := canonicalJSON(in.Request)
	if err != nil {
		return Decision{}, fmt.Errorf("store: encode decision request: %w", err)
	}
	facts, err := canonicalJSON(in.FactSnapshot)
	if err != nil {
		return Decision{}, fmt.Errorf("store: encode fact snapshot: %w", err)
	}
	obligations, err := canonicalJSONList(in.Obligations)
	if err != nil {
		return Decision{}, fmt.Errorf("store: encode obligations: %w", err)
	}

	expiresAt := in.ExpiresAt.UTC().Truncate(time.Microsecond)
	deadline, kind := nextDeadline(expiresAt, in.Challenges)

	out := Decision{
		ID:               id,
		CallerID:         in.CallerID,
		PolicyID:         in.PolicyID,
		PolicyVersion:    in.PolicyVersion,
		SubjectID:        in.SubjectID,
		ResourceID:       in.ResourceID,
		Action:           in.Action,
		Request:          request,
		FactSnapshot:     facts,
		Obligations:      obligations,
		State:            DecisionPending,
		ExpiresAt:        expiresAt,
		NextDeadline:     deadline,
		NextDeadlineKind: kind,
	}

	err = w.InTx(ctx, func(ctx context.Context, tx pgx.Tx, ap *Appender) error {
		insertErr := tx.QueryRow(ctx, `
			INSERT INTO decisions
				(id, caller_id, policy_id, policy_version, subject_id, resource_id, action,
				 request, fact_snapshot, obligations, state, expires_at, next_deadline, next_deadline_kind)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			RETURNING created_at, updated_at`,
			out.ID, out.CallerID, out.PolicyID, out.PolicyVersion, out.SubjectID, out.ResourceID,
			out.Action, []byte(out.Request), []byte(out.FactSnapshot), []byte(out.Obligations),
			string(out.State), out.ExpiresAt, out.NextDeadline, nullableKind(out.NextDeadlineKind),
		).Scan(&out.CreatedAt, &out.UpdatedAt)
		if insertErr != nil {
			if isUniqueViolation(insertErr) {
				return fmt.Errorf("store: decision %q already exists: %w", out.ID, ErrConflict)
			}
			return fmt.Errorf("store: create decision: %w", insertErr)
		}

		for _, ch := range in.Challenges {
			detail, derr := canonicalJSON(ch.Detail)
			if derr != nil {
				return fmt.Errorf("store: encode challenge detail: %w", derr)
			}
			if _, derr = tx.Exec(ctx, `
				INSERT INTO challenge_progress (decision_id, ordinal, kind, state, deadline, detail)
				VALUES ($1, $2, $3, $4, $5, $6)`,
				out.ID, ch.Ordinal, string(ch.Kind), string(ChallengePending),
				truncPtr(ch.Deadline), []byte(detail)); derr != nil {
				return fmt.Errorf("store: create challenge progress: %w", derr)
			}
		}

		_, aerr := ap.Append(ctx, AuditEntry{
			Kind:    AuditKindDecisionCreated,
			Subject: out.ID,
			Payload: map[string]any{
				"caller_id":          out.CallerID,
				"policy_id":          out.PolicyID,
				"policy_version":     out.PolicyVersion,
				"subject_id":         out.SubjectID,
				"resource_id":        out.ResourceID,
				"action":             out.Action,
				"expires_at":         out.ExpiresAt.Format(time.RFC3339Nano),
				"fact_snapshot":      out.FactSnapshot,
				"obligations":        out.Obligations,
				"challenge_count":    len(in.Challenges),
				"next_deadline_kind": string(out.NextDeadlineKind),
			},
		})
		return aerr
	})
	if err != nil {
		return Decision{}, err
	}
	out.CreatedAt = out.CreatedAt.UTC()
	out.UpdatedAt = out.UpdatedAt.UTC()
	return out, nil
}

// nextDeadline computes the scheduler column: the earliest of the decision's
// own expiry and any unmet challenge timer, plus which of the two it is.
//
// A tie resolves to expiry. At the instant both land, the decision is over
// regardless of what the challenge would have done, and resolving the tie the
// other way would have the sweeper do challenge work on a decision that is
// already finished.
func nextDeadline(expiresAt time.Time, challenges []NewChallenge) (*time.Time, DeadlineKind) {
	best := expiresAt
	kind := DeadlineExpiry
	for _, ch := range challenges {
		if ch.Deadline == nil {
			continue
		}
		d := ch.Deadline.UTC().Truncate(time.Microsecond)
		if d.Before(best) {
			best, kind = d, DeadlineChallenge
		}
	}
	out := best
	return &out, kind
}

func truncPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC().Truncate(time.Microsecond)
	return &v
}

func nullableKind(k DeadlineKind) *string {
	if k == "" {
		return nil
	}
	s := string(k)
	return &s
}

const decisionColumns = `id, caller_id, policy_id, policy_version, subject_id, resource_id, action,
	request::text, fact_snapshot::text, obligations::text, state, created_at, updated_at,
	expires_at, next_deadline, next_deadline_kind, resolved_at`

// GetDecision reads a decision by identifier. It reports the row as stored and
// makes no judgement about deadlines.
func GetDecision(ctx context.Context, q Querier, id string) (Decision, error) {
	return scanDecision(q.QueryRow(ctx, `SELECT `+decisionColumns+` FROM decisions WHERE id = $1`, id))
}

// ActiveDecision reads a decision and refuses it if its own deadline has
// passed.
//
// The expiry test is `expires_at <= now`. next_deadline is not consulted, and
// that is the whole point of the column split: a decision holding a delay timer
// in next_deadline is still active, and every entry point that asks this
// question — status reads, approval submission, transition functions — gets the
// same answer because they all ask it here.
func (s *Store) ActiveDecision(ctx context.Context, id string) (Decision, error) {
	return ActiveDecisionTx(ctx, s.pool, id, s.Now())
}

// ActiveDecisionTx is ActiveDecision inside a caller's transaction, with an
// explicit clock.
func ActiveDecisionTx(ctx context.Context, q Querier, id string, now time.Time) (Decision, error) {
	d, err := GetDecision(ctx, q, id)
	if err != nil {
		return Decision{}, err
	}
	if d.Expired(now) {
		return d, fmt.Errorf("store: decision %q expired at %s: %w", id, d.ExpiresAt, ErrDecisionExpired)
	}
	return d, nil
}

// ChallengeProgressFor reads the challenge rows of a decision, ordered by
// ordinal.
func ChallengeProgressFor(ctx context.Context, q Querier, decisionID string) ([]ChallengeProgress, error) {
	rows, err := q.Query(ctx, `
		SELECT decision_id, ordinal, kind, state, deadline, satisfied_at, detail::text
		FROM challenge_progress WHERE decision_id = $1 ORDER BY ordinal`, decisionID)
	if err != nil {
		return nil, fmt.Errorf("store: read challenge progress: %w", err)
	}
	defer rows.Close()
	var out []ChallengeProgress
	for rows.Next() {
		var (
			cp     ChallengeProgress
			kind   string
			state  string
			detail string
		)
		if err := rows.Scan(&cp.DecisionID, &cp.Ordinal, &kind, &state,
			&cp.Deadline, &cp.SatisfiedAt, &detail); err != nil {
			return nil, fmt.Errorf("store: scan challenge progress: %w", err)
		}
		cp.Kind = policy.ChallengeType(kind)
		cp.State = ChallengeState(state)
		cp.Detail = json.RawMessage(detail)
		out = append(out, cp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read challenge progress: %w", err)
	}
	return out, nil
}

// SetChallengeState moves one challenge to a new state, recomputes the
// scheduler column and writes the audit row, all in one transaction.
func (w *AuditWriter) SetChallengeState(ctx context.Context, decisionID string, ordinal int, state ChallengeState, detail any) error {
	detailJSON, err := canonicalJSON(detail)
	if err != nil {
		return fmt.Errorf("store: encode challenge detail: %w", err)
	}
	return w.InTx(ctx, func(ctx context.Context, tx pgx.Tx, ap *Appender) error {
		tag, err := tx.Exec(ctx, `
			UPDATE challenge_progress
			SET state = $3,
			    satisfied_at = CASE WHEN $3 = 'satisfied' THEN now() ELSE satisfied_at END,
			    detail = $4
			WHERE decision_id = $1 AND ordinal = $2`,
			decisionID, ordinal, string(state), []byte(detailJSON))
		if err != nil {
			return fmt.Errorf("store: update challenge progress: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("store: challenge %d of decision %q: %w", ordinal, decisionID, ErrNotFound)
		}
		if err := refreshNextDeadline(ctx, tx, decisionID); err != nil {
			return err
		}
		_, err = ap.Append(ctx, AuditEntry{
			Kind:    AuditKindChallengeProgress,
			Subject: decisionID,
			Payload: map[string]any{
				"ordinal": ordinal,
				"state":   string(state),
				"detail":  detailJSON,
			},
		})
		return err
	})
}

// RefreshNextDeadline recomputes min(expires_at, unmet challenge timers) inside
// the caller's transaction.
//
// It is exported because the revision effect hook writes challenge rows
// directly — it has to, since the audit writer holds its append mutex across the
// whole audited transaction and a store helper that opened its own would
// deadlock against it — and a challenge timer that moved without this column
// moving is a sweeper that wakes at the old instant.
//
// It takes a [Querier] rather than opening a transaction for exactly that
// reason: it is a statement the caller runs, never a transaction it starts.
func RefreshNextDeadline(ctx context.Context, q Querier, decisionID string) error {
	return refreshNextDeadline(ctx, q, decisionID)
}

// refreshNextDeadline recomputes min(expires_at, unmet challenge timers).
//
// It is computed in SQL so that the invariant the column carries cannot drift
// from the rows it summarizes: a challenge that just became satisfied stops
// contributing in the same statement that recomputes the column.
func refreshNextDeadline(ctx context.Context, q Querier, decisionID string) error {
	_, err := q.Exec(ctx, `
		UPDATE decisions d
		SET next_deadline = LEAST(d.expires_at, c.soonest),
		    next_deadline_kind = CASE
		        WHEN c.soonest IS NOT NULL AND c.soonest < d.expires_at THEN 'challenge'
		        ELSE 'expiry'
		    END,
		    updated_at = now()
		FROM (
		    SELECT min(deadline) AS soonest
		    FROM challenge_progress
		    WHERE decision_id = $1 AND state = 'pending' AND deadline IS NOT NULL
		) c
		WHERE d.id = $1 AND d.state = 'pending'`, decisionID)
	if err != nil {
		return fmt.Errorf("store: refresh next_deadline of %q: %w", decisionID, err)
	}
	return nil
}

// ResolveDecision moves a decision to a terminal state and writes the audit row
// in the same transaction.
func (w *AuditWriter) ResolveDecision(ctx context.Context, id string, state DecisionState, obligations any, actor string) (Decision, error) {
	if !state.Terminal() {
		return Decision{}, fmt.Errorf("store: %q is not a terminal decision state", state)
	}
	// A nil obligations argument means "leave what is there", which the
	// COALESCE below needs as a SQL NULL rather than as an empty list.
	var obligationsJSON []byte
	if obligations != nil {
		encoded, err := canonicalJSONList(obligations)
		if err != nil {
			return Decision{}, fmt.Errorf("store: encode obligations: %w", err)
		}
		obligationsJSON = encoded
	}

	var out Decision
	err := w.InTx(ctx, func(ctx context.Context, tx pgx.Tx, ap *Appender) error {
		row := tx.QueryRow(ctx, `
			UPDATE decisions
			SET state = $2,
			    obligations = COALESCE($3, obligations),
			    resolved_at = now(),
			    updated_at = now(),
			    next_deadline = NULL,
			    next_deadline_kind = NULL
			WHERE id = $1 AND state = 'pending'
			RETURNING `+decisionColumns, id, string(state), obligationsJSON)
		d, serr := scanDecision(row)
		if errors.Is(serr, ErrNotFound) {
			return fmt.Errorf("store: decision %q is not pending: %w", id, ErrConflict)
		}
		if serr != nil {
			return serr
		}
		out = d
		_, aerr := ap.Append(ctx, AuditEntry{
			Kind:    AuditKindDecisionResolved,
			Subject: id,
			Payload: map[string]any{
				"state":       string(state),
				"actor":       actor,
				"obligations": out.Obligations,
			},
		})
		return aerr
	})
	if err != nil {
		return Decision{}, err
	}
	return out, nil
}

// ClaimDue claims decisions whose scheduler deadline has passed and runs fn
// over them inside the claiming transaction.
//
// The claim uses FOR UPDATE SKIP LOCKED, which is what lets several instances
// sweep the same table without a job queue: a row another instance is already
// working is skipped rather than waited on. The rows come back with their
// deadline kind, because expiry and a challenge timer need different work and
// the sweeper must not guess which one fired.
func (s *Store) ClaimDue(ctx context.Context, now time.Time, limit int, fn func(ctx context.Context, tx pgx.Tx, due []Decision) error) error {
	if limit <= 0 {
		return fmt.Errorf("store: ClaimDue limit must be positive, got %d", limit)
	}
	return s.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+decisionColumns+`
			FROM decisions
			WHERE state = 'pending' AND next_deadline IS NOT NULL AND next_deadline <= $1
			ORDER BY next_deadline
			LIMIT $2
			FOR UPDATE SKIP LOCKED`, now.UTC(), limit)
		if err != nil {
			return fmt.Errorf("store: claim due decisions: %w", err)
		}
		var due []Decision
		for rows.Next() {
			d, serr := scanDecision(rows)
			if serr != nil {
				rows.Close()
				return serr
			}
			due = append(due, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("store: claim due decisions: %w", err)
		}
		return fn(ctx, tx, due)
	})
}

func scanDecision(row pgx.Row) (Decision, error) {
	var (
		d           Decision
		request     string
		facts       string
		obligations string
		state       string
		kind        *string
	)
	err := row.Scan(&d.ID, &d.CallerID, &d.PolicyID, &d.PolicyVersion, &d.SubjectID, &d.ResourceID,
		&d.Action, &request, &facts, &obligations, &state, &d.CreatedAt, &d.UpdatedAt,
		&d.ExpiresAt, &d.NextDeadline, &kind, &d.ResolvedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Decision{}, ErrNotFound
	}
	if err != nil {
		return Decision{}, fmt.Errorf("store: read decision: %w", err)
	}
	d.Request = json.RawMessage(request)
	d.FactSnapshot = json.RawMessage(facts)
	d.Obligations = json.RawMessage(obligations)
	d.State = DecisionState(state)
	if kind != nil {
		d.NextDeadlineKind = DeadlineKind(*kind)
	}
	d.CreatedAt = d.CreatedAt.UTC()
	d.UpdatedAt = d.UpdatedAt.UTC()
	d.ExpiresAt = d.ExpiresAt.UTC()
	return d, nil
}

// ---------------------------------------------------------------------------
// approvals
// ---------------------------------------------------------------------------

// Approval is one recorded approval or rejection.
type Approval struct {
	ID               string
	DecisionID       string
	ChallengeOrdinal int
	ApproverID       string
	Verdict          string
	BindingHash      [32]byte
	Detail           json.RawMessage
	SubmittedAt      time.Time
}

// The approval verdicts.
const (
	VerdictApprove = "approve"
	VerdictReject  = "reject"
)

// NewApproval is a request to record an approval.
type NewApproval struct {
	ID               string
	DecisionID       string
	ChallengeOrdinal int
	ApproverID       string
	Verdict          string
	BindingHash      [32]byte
	Detail           any
}

// RecordApproval stores an approval and its audit row in one transaction.
//
// A second submission from the same approver on the same challenge returns
// ErrConflict rather than counting twice. That uniqueness is a database
// constraint, not a read-then-write check, because a quorum threshold that can
// be met by one approver racing themselves is not a quorum.
func (w *AuditWriter) RecordApproval(ctx context.Context, in NewApproval) (Approval, error) {
	if in.Verdict != VerdictApprove && in.Verdict != VerdictReject {
		return Approval{}, fmt.Errorf("store: approval verdict %q must be %q or %q",
			in.Verdict, VerdictApprove, VerdictReject)
	}
	id := in.ID
	if id == "" {
		generated, err := NewDecisionID()
		if err != nil {
			return Approval{}, err
		}
		id = generated
	}
	detail, err := canonicalJSON(in.Detail)
	if err != nil {
		return Approval{}, fmt.Errorf("store: encode approval detail: %w", err)
	}

	out := Approval{
		ID:               id,
		DecisionID:       in.DecisionID,
		ChallengeOrdinal: in.ChallengeOrdinal,
		ApproverID:       in.ApproverID,
		Verdict:          in.Verdict,
		BindingHash:      in.BindingHash,
		Detail:           detail,
	}
	err = w.InTx(ctx, func(ctx context.Context, tx pgx.Tx, ap *Appender) error {
		ierr := tx.QueryRow(ctx, `
			INSERT INTO approvals
				(id, decision_id, challenge_ordinal, approver_id, verdict, binding_hash, detail)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING submitted_at`,
			out.ID, out.DecisionID, out.ChallengeOrdinal, out.ApproverID, out.Verdict,
			out.BindingHash[:], []byte(out.Detail)).Scan(&out.SubmittedAt)
		if ierr != nil {
			if isUniqueViolation(ierr) {
				return fmt.Errorf("store: approver %q already voted on challenge %d of decision %q: %w",
					out.ApproverID, out.ChallengeOrdinal, out.DecisionID, ErrConflict)
			}
			return fmt.Errorf("store: record approval: %w", ierr)
		}
		_, aerr := ap.Append(ctx, AuditEntry{
			Kind:    AuditKindApproval,
			Subject: out.DecisionID,
			Payload: map[string]any{
				"approval_id":  out.ID,
				"ordinal":      out.ChallengeOrdinal,
				"approver_id":  out.ApproverID,
				"verdict":      out.Verdict,
				"binding_hash": fmt.Sprintf("%x", out.BindingHash),
			},
		})
		return aerr
	})
	if err != nil {
		return Approval{}, err
	}
	out.SubmittedAt = out.SubmittedAt.UTC()
	return out, nil
}

// CountApprovals counts distinct approvers with the given verdict on one
// challenge.
func CountApprovals(ctx context.Context, q Querier, decisionID string, ordinal int, verdict string) (int, error) {
	var n int
	err := q.QueryRow(ctx, `
		SELECT count(DISTINCT approver_id) FROM approvals
		WHERE decision_id = $1 AND challenge_ordinal = $2 AND verdict = $3`,
		decisionID, ordinal, verdict).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count approvals: %w", err)
	}
	return n, nil
}

// canonicalJSONList is canonicalJSON with an empty list, rather than an empty
// object, as the zero value. Obligations are a list and the column defaults to
// one; a nil that arrived as `{}` would fail to decode on the way back out.
func canonicalJSONList(v any) (json.RawMessage, error) {
	if v == nil {
		return json.RawMessage("[]"), nil
	}
	return canonicalJSON(v)
}
