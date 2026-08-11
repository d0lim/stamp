package store

// history.go is the read side of the decision record: the audit console's
// timeline (R22) and the approver's inbox (R21).
//
// The plan left the query axes open until this unit ("감사 콘솔의 조회 축…과 정렬·
// 페이지네이션, 대응 인덱스"), so they are settled here and the migration that
// indexes them names this file. Four axes, one order, one pagination scheme:
//
//	period   [From, To) on created_at. Half-open, so adjacent windows tile
//	         without double-counting a decision that landed on the boundary —
//	         an auditor paging month by month must not see one row twice.
//	policy   policy_id, exact. A version axis was considered and rejected:
//	         "what did policy X ever decide" is the question, and a per-version
//	         filter is a client-side narrowing of an answer that has to be read
//	         as a whole to be meaningful.
//	subject  subject_id, exact. The person or workload the decision was about.
//	state    one lifecycle state.
//
// Sorting is newest-first on (created_at, id) and is not selectable. An audit
// read is a timeline, one total order is what makes the cursor below correct,
// and every additional order is another composite index to carry. `id` breaks
// the tie because created_at is not unique — two decisions created in the same
// microsecond would otherwise make a page boundary ambiguous and could drop a
// row from the sequence entirely.
//
// Pagination is keyset, not OFFSET. The decision table is append-only in
// practice and grows while an auditor reads it, so OFFSET both drifts (a row
// inserted ahead of the cursor shifts every later page by one) and degrades
// linearly in the page number. A cursor names the last row of the previous
// page, and the next page is everything strictly below it in the sort order.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/d0lim/stamp/internal/policy"
)

// Page size bounds for [ListDecisions].
const (
	// DefaultDecisionPageSize is the page an unspecified limit selects.
	DefaultDecisionPageSize = 50
	// MaxDecisionPageSize caps a caller-supplied limit. A page is a screen, and
	// an unbounded one is a way to ask the database for the whole table.
	MaxDecisionPageSize = 200
)

// DecisionCursor is the position of one row in the (created_at DESC, id DESC)
// order.
//
// It is a value rather than an opaque server secret because there is nothing in
// it that the row it names does not already show. What it must not be is a
// row *number*: that is the property that makes the sequence stable while the
// table grows underneath it.
type DecisionCursor struct {
	CreatedAt time.Time
	ID        string
}

// Zero reports whether the cursor names no row, which asks for the first page.
func (c DecisionCursor) Zero() bool { return c.ID == "" }

// Encode renders the cursor as one URL-safe token.
//
// The nanosecond form is deliberate: Postgres stores microseconds, and a format
// that rounded would make the cursor name a position between two rows.
func (c DecisionCursor) Encode() string {
	if c.Zero() {
		return ""
	}
	raw := c.CreatedAt.UTC().Format(time.RFC3339Nano) + "|" + c.ID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// ErrInvalidCursor is returned for a cursor token that does not decode.
var ErrInvalidCursor = errors.New("store: invalid decision cursor")

// DecodeDecisionCursor parses a token produced by [DecisionCursor.Encode]. An
// empty token is the first page and not an error.
func DecodeDecisionCursor(token string) (DecisionCursor, error) {
	if token == "" {
		return DecisionCursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return DecisionCursor{}, fmt.Errorf("%w: not base64: %w", ErrInvalidCursor, err)
	}
	at, id, ok := strings.Cut(string(raw), "|")
	if !ok || id == "" {
		return DecisionCursor{}, ErrInvalidCursor
	}
	created, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return DecisionCursor{}, fmt.Errorf("%w: not an instant: %w", ErrInvalidCursor, err)
	}
	return DecisionCursor{CreatedAt: created.UTC(), ID: id}, nil
}

// DecisionQuery is one audit console query. Every field is optional; the zero
// query is "the most recent page of everything".
type DecisionQuery struct {
	// From and To bound created_at as the half-open interval [From, To).
	From time.Time
	To   time.Time
	// PolicyID, SubjectID and State are exact-match axes.
	PolicyID  string
	SubjectID string
	State     DecisionState
	// CallerID restricts the result to decisions one caller created. It is not
	// an audit console axis — it is the narrowing R22 applies to a reader
	// without auditor standing, and it exists here so that narrowing is one
	// SQL predicate rather than a filter applied after the page was cut.
	CallerID string
	// After is the last row of the previous page.
	After DecisionCursor
	// Limit is the page size; zero selects DefaultDecisionPageSize and
	// anything above MaxDecisionPageSize is clamped to it.
	Limit int
}

// DecisionPage is one page of history.
type DecisionPage struct {
	Decisions []Decision
	// Next is the cursor for the following page, zero when this page is the
	// last one.
	Next DecisionCursor
}

// ListDecisions reads one page of decision history, newest first.
func ListDecisions(ctx context.Context, q Querier, query DecisionQuery) (DecisionPage, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = DefaultDecisionPageSize
	}
	if limit > MaxDecisionPageSize {
		limit = MaxDecisionPageSize
	}

	var (
		where []string
		args  []any
	)
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, strings.ReplaceAll(clause, "$?", "$"+strconv.Itoa(len(args))))
	}
	if !query.From.IsZero() {
		add("created_at >= $?", query.From.UTC())
	}
	if !query.To.IsZero() {
		add("created_at < $?", query.To.UTC())
	}
	if query.PolicyID != "" {
		add("policy_id = $?", query.PolicyID)
	}
	if query.SubjectID != "" {
		add("subject_id = $?", query.SubjectID)
	}
	if query.State != "" {
		add("state = $?", string(query.State))
	}
	if query.CallerID != "" {
		add("caller_id = $?", query.CallerID)
	}
	if !query.After.Zero() {
		// Row-value comparison rather than the expanded OR form, because this
		// is exactly what a (created_at DESC, id DESC) index can seek to.
		args = append(args, query.After.CreatedAt.UTC(), query.After.ID)
		where = append(where, fmt.Sprintf("(created_at, id) < ($%d, $%d)", len(args)-1, len(args)))
	}

	sql := `SELECT ` + decisionColumns + ` FROM decisions`
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	// One row past the page, which is how "is there a next page" is answered
	// without a second count query over the same predicate.
	args = append(args, limit+1)
	sql += fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d", len(args))

	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return DecisionPage{}, fmt.Errorf("store: list decisions: %w", err)
	}
	defer rows.Close()

	page := DecisionPage{}
	for rows.Next() {
		d, serr := scanDecision(rows)
		if serr != nil {
			return DecisionPage{}, serr
		}
		page.Decisions = append(page.Decisions, d)
	}
	if err := rows.Err(); err != nil {
		return DecisionPage{}, fmt.Errorf("store: list decisions: %w", err)
	}
	if len(page.Decisions) > limit {
		last := page.Decisions[limit-1]
		page.Decisions = page.Decisions[:limit]
		page.Next = DecisionCursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return page, nil
}

// OpenQuorumChallenge is one unresolved quorum challenge together with the
// decision it belongs to and the collection state a member needs to see.
type OpenQuorumChallenge struct {
	Decision  Decision
	Challenge ChallengeProgress
	// Approvals is how many distinct approvers have said yes so far.
	Approvals int
	// Submitted reports whether the member this was read for has already
	// voted. An item they have voted on stays in the list — R21 asks the inbox
	// to show collection progress, and dropping the row the moment they act
	// takes away the only place they could watch it fill.
	Submitted bool
}

// OpenQuorumChallenges reads the quorum challenges a member could be a target
// of, soonest expiry first.
//
// The member predicate here is a *candidate* filter and not the authorization.
// It admits every set that names the member explicitly plus every claim-resolved
// set, because whether a claim-resolved set contains this person is a question
// about their token that SQL cannot answer. challenge.Quorum applies the exact
// test to what comes back — one implementation of "is this person a target",
// in the package that owns the question.
//
// The order is R21's: the inbox is sorted by how soon the decision expires, so
// the row an approver is about to lose the chance to act on is the first one.
func OpenQuorumChallenges(ctx context.Context, q Querier, member string, now time.Time, limit int) ([]OpenQuorumChallenge, error) {
	if limit <= 0 {
		limit = DefaultDecisionPageSize
	}
	if limit > MaxDecisionPageSize {
		limit = MaxDecisionPageSize
	}
	rows, err := q.Query(ctx, `
		SELECT `+prefixed("d", decisionColumns)+`,
			c.decision_id, c.ordinal, c.kind, c.state, c.deadline, c.satisfied_at, c.detail::text,
			(SELECT count(DISTINCT a.approver_id) FROM approvals a
				WHERE a.decision_id = c.decision_id AND a.challenge_ordinal = c.ordinal
					AND a.verdict = 'approve'),
			EXISTS (SELECT 1 FROM approvals a2
				WHERE a2.decision_id = c.decision_id AND a2.challenge_ordinal = c.ordinal
					AND a2.approver_id = $2)
		FROM decisions d
		JOIN challenge_progress c ON c.decision_id = d.id
		WHERE d.state = 'pending'
			AND d.expires_at > $1
			AND c.state = 'pending'
			AND c.kind = 'quorum'
			AND (c.detail -> 'members' @> to_jsonb($2::text) OR c.detail ->> 'mode' = 'claim')
		ORDER BY d.expires_at ASC, d.id ASC, c.ordinal ASC
		LIMIT $3`, now.UTC(), member, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list open quorum challenges: %w", err)
	}
	defer rows.Close()

	var out []OpenQuorumChallenge
	for rows.Next() {
		var (
			item        OpenQuorumChallenge
			request     string
			facts       string
			obligations string
			state       string
			kind        *string
			key         *string
			cpKind      string
			cpState     string
			detail      string
		)
		d := &item.Decision
		if err := rows.Scan(&d.ID, &d.CallerID, &d.PolicyID, &d.PolicyVersion, &d.SubjectID,
			&d.ResourceID, &d.Action, &request, &facts, &obligations, &state, &d.CreatedAt,
			&d.UpdatedAt, &d.ExpiresAt, &d.NextDeadline, &kind, &d.ResolvedAt, &key,
			&item.Challenge.DecisionID, &item.Challenge.Ordinal, &cpKind, &cpState,
			&item.Challenge.Deadline, &item.Challenge.SatisfiedAt, &detail,
			&item.Approvals, &item.Submitted); err != nil {
			return nil, fmt.Errorf("store: scan open quorum challenge: %w", err)
		}
		d.Request = []byte(request)
		d.FactSnapshot = []byte(facts)
		d.Obligations = []byte(obligations)
		d.State = DecisionState(state)
		if kind != nil {
			d.NextDeadlineKind = DeadlineKind(*kind)
		}
		if key != nil {
			d.IdempotencyKey = *key
		}
		d.CreatedAt = d.CreatedAt.UTC()
		d.UpdatedAt = d.UpdatedAt.UTC()
		d.ExpiresAt = d.ExpiresAt.UTC()
		item.Challenge.Kind = policy.ChallengeType(cpKind)
		item.Challenge.State = ChallengeState(cpState)
		item.Challenge.Detail = []byte(detail)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list open quorum challenges: %w", err)
	}
	return out, nil
}

// ApprovalsFor reads the approvals recorded against one decision, oldest first.
//
// The audit console shows them because R31's binding is only checkable if the
// hash each approval was recorded against is visible next to the material the
// decision froze.
func ApprovalsFor(ctx context.Context, q Querier, decisionID string) ([]Approval, error) {
	rows, err := q.Query(ctx, `
		SELECT id, decision_id, challenge_ordinal, approver_id, verdict, binding_hash, detail::text,
			submitted_at
		FROM approvals WHERE decision_id = $1 ORDER BY submitted_at ASC, id ASC`, decisionID)
	if err != nil {
		return nil, fmt.Errorf("store: read approvals: %w", err)
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		var (
			a      Approval
			hash   []byte
			detail string
		)
		if err := rows.Scan(&a.ID, &a.DecisionID, &a.ChallengeOrdinal, &a.ApproverID, &a.Verdict,
			&hash, &detail, &a.SubmittedAt); err != nil {
			return nil, fmt.Errorf("store: scan approval: %w", err)
		}
		copy(a.BindingHash[:], hash)
		a.Detail = []byte(detail)
		a.SubmittedAt = a.SubmittedAt.UTC()
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read approvals: %w", err)
	}
	return out, nil
}

// History is the read-only view of the decision record the audit console uses.
//
// It is a type rather than five loose functions so that the console surface can
// declare the interface it needs and be tested against a fake. Every method is
// a read; there is deliberately no writer here, because R32's chain is the only
// way a row about a decision is ever written.
type History struct{ q Querier }

// NewHistory builds the read view over a pool or a transaction.
func NewHistory(q Querier) *History { return &History{q: q} }

// ListDecisions reads one page of history.
func (h *History) ListDecisions(ctx context.Context, query DecisionQuery) (DecisionPage, error) {
	return ListDecisions(ctx, h.q, query)
}

// Decision reads one decision as stored, deadlines and all.
func (h *History) Decision(ctx context.Context, id string) (Decision, error) {
	return GetDecision(ctx, h.q, id)
}

// ChallengeProgress reads a decision's challenge rows.
func (h *History) ChallengeProgress(ctx context.Context, id string) ([]ChallengeProgress, error) {
	return ChallengeProgressFor(ctx, h.q, id)
}

// Approvals reads the approvals recorded against a decision.
func (h *History) Approvals(ctx context.Context, id string) ([]Approval, error) {
	return ApprovalsFor(ctx, h.q, id)
}

// PolicyVersion reads the exact policy version a decision was evaluated under.
//
// R22 asks the audit console to show it, and "the version the decision froze"
// is the only correct answer — reading the effective policy would show what the
// rule says now, which is precisely the substitution the frozen column exists
// to prevent.
func (h *History) PolicyVersion(ctx context.Context, id string, version int64) (PolicyRecord, error) {
	return GetPolicy(ctx, h.q, id, version)
}

// prefixed qualifies a column list with a table alias, so a join can reuse the
// single declaration of what a decision row is.
func prefixed(alias, columns string) string {
	parts := strings.Split(columns, ",")
	for i, part := range parts {
		parts[i] = alias + "." + strings.TrimSpace(part)
	}
	return strings.Join(parts, ", ")
}
