package api

// auditconsole.go is R22's surface: the decision history, and for one decision
// the policy version and the fact snapshot it was evaluated under.
//
// Two rules shape it, and both are D21's — a control is enforced by a code path
// and operator configuration, never by what a client is willing to send.
//
// Auditor standing is decided here, from an operator-configured claim, and the
// refusal is written to the audit chain. The console's role claim (U14) decides
// what navigation is *offered*; it decides nothing about what is served. The
// two default to the same claim so they cannot silently disagree in a normal
// deployment, and they are separately configurable because R22 permits a group.
//
// A reader without that standing is not locked out of their own record. R22
// gives them the decisions they created or are a target of, and the rule for
// that already exists — decision.Service.Get is R40's read rule, refusal audit
// included — so this asks it rather than reimplementing it. The one thing this
// surface must never do is answer a question it did not authorise.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/store"
)

// The audit console endpoints.
const (
	// AuditDecisionListPattern is the history query.
	AuditDecisionListPattern = "GET /audit/decisions"
	// AuditDecisionReadPattern is one decision with the material it froze.
	AuditDecisionReadPattern = "GET /audit/decisions/{id}"
)

// DefaultAuditorClaim is the claim auditor standing is read from when the
// operator names none. It is the console's default role claim, so a deployment
// that configured navigation has configured enforcement too.
const DefaultAuditorClaim = "roles"

// DefaultAuditorValues are the claim values that grant standing when the
// operator names none.
var DefaultAuditorValues = []string{"auditor", "audit", "stamp:auditor"}

// AuditorRule decides auditor standing from a verified token (R22).
//
// It is a value rather than a predicate so that "who may read the audit
// console" is a piece of deployment configuration that can be printed, and so
// that the console surface has no way to widen it at request time.
type AuditorRule struct {
	// Claim names the token claim standing is read from. Empty selects
	// DefaultAuditorClaim.
	Claim string
	// Values are the claim values that grant standing. Empty selects
	// DefaultAuditorValues. A rule whose Values are explicitly configured
	// admits those spellings and no others.
	Values []string
}

func (r AuditorRule) withDefaults() AuditorRule {
	out := AuditorRule{Claim: strings.TrimSpace(r.Claim), Values: r.Values}
	if out.Claim == "" {
		out.Claim = DefaultAuditorClaim
	}
	if len(out.Values) == 0 {
		out.Values = DefaultAuditorValues
	}
	return out
}

// Qualifies reports whether a token carries auditor standing.
//
// A claim may be a string, a space or comma separated string, or a list; an IdP
// emits all three shapes for group memberships and an operator does not get to
// choose. Comparison is case-insensitive on the value and exact on the claim
// name, because a claim name is a key and a group name is a label.
func (r AuditorRule) Qualifies(s *identity.Subject) bool {
	if s == nil {
		return false
	}
	rule := r.withDefaults()
	var claims map[string]any
	if err := s.Claims(&claims); err != nil {
		return false
	}
	held := claimValues(claims[rule.Claim])
	for _, want := range rule.Values {
		want = strings.ToLower(strings.TrimSpace(want))
		if want == "" {
			continue
		}
		if slices.ContainsFunc(held, func(have string) bool { return strings.ToLower(have) == want }) {
			return true
		}
	}
	return false
}

// claimValues flattens the shapes an IdP writes a membership claim in.
func claimValues(value any) []string {
	switch v := value.(type) {
	case string:
		return strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' })
	case []any:
		var out []string
		for _, item := range v {
			out = append(out, claimValues(item)...)
		}
		return out
	case []string:
		return v
	default:
		return nil
	}
}

// DecisionHistory is the read the audit console performs. store.History is the
// implementation.
type DecisionHistory interface {
	ListDecisions(ctx context.Context, query store.DecisionQuery) (store.DecisionPage, error)
	Decision(ctx context.Context, id string) (store.Decision, error)
	ChallengeProgress(ctx context.Context, id string) ([]store.ChallengeProgress, error)
	Approvals(ctx context.Context, id string) ([]store.Approval, error)
	PolicyVersion(ctx context.Context, id string, version int64) (store.PolicyRecord, error)
}

// DecisionAccess is R40's read rule. decision.Service implements it and audits
// its own refusals; this surface uses it as the gate for a reader without
// auditor standing rather than owning a second copy of the rule.
type DecisionAccess interface {
	Get(ctx context.Context, caller *identity.Subject, id string) (decision.Result, error)
}

// AuditAppender is the slice of the audit chain this surface writes: one entry,
// for a refusal.
type AuditAppender interface {
	Append(ctx context.Context, entries ...store.AuditEntry) ([]store.AuditRecord, error)
}

// AuditConsoleConfig configures an [AuditConsole].
type AuditConsoleConfig struct {
	// History reads the decision record. Required.
	History DecisionHistory
	// Access answers R40's read rule for a reader without auditor standing.
	// Required.
	Access DecisionAccess
	// Auditors is the operator's standing rule.
	Auditors AuditorRule
	// Audit records refusals. Required: R22 asks for the refusal to be
	// auditable, and a surface that cannot write one cannot serve.
	Audit AuditAppender
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// AuditConsole serves the audit console's reads.
type AuditConsole struct {
	history  DecisionHistory
	access   DecisionAccess
	auditors AuditorRule
	audit    AuditAppender
	now      func() time.Time
}

var _ Provider = (*AuditConsole)(nil)

// NewAuditConsole builds the audit console surface.
func NewAuditConsole(cfg AuditConsoleConfig) (*AuditConsole, error) {
	if cfg.History == nil {
		return nil, errors.New("api: the audit console requires a decision history")
	}
	if cfg.Access == nil {
		return nil, errors.New("api: the audit console requires a decision access rule")
	}
	if cfg.Audit == nil {
		return nil, errors.New("api: the audit console requires an audit appender")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &AuditConsole{
		history:  cfg.History,
		access:   cfg.Access,
		auditors: cfg.Auditors.withDefaults(),
		audit:    cfg.Audit,
		now:      now,
	}, nil
}

// Routes implements [Provider].
func (a *AuditConsole) Routes() []Route {
	return []Route{
		{
			Name:    "audit-decision-list",
			Surface: SurfaceConsole,
			Pattern: AuditDecisionListPattern,
			Auth:    AuthUser,
			Handler: http.HandlerFunc(a.list),
		},
		{
			Name:    "audit-decision-read",
			Surface: SurfaceConsole,
			Pattern: AuditDecisionReadPattern,
			Auth:    AuthUser,
			Handler: http.HandlerFunc(a.read),
		},
	}
}

// AuditDecisionRow is one row of the history list.
//
// It carries no fact snapshot and no request body. A list of a thousand
// decisions is not the place to spill every frozen payload in the deployment,
// and the detail read is one click away with the whole record.
type AuditDecisionRow struct {
	ID            string     `json:"id"`
	CallerID      string     `json:"caller_id"`
	PolicyID      string     `json:"policy_id"`
	PolicyVersion int64      `json:"policy_version"`
	SubjectID     string     `json:"subject_id"`
	ResourceID    string     `json:"resource_id"`
	Action        string     `json:"action"`
	State         string     `json:"state"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	ResolvedAt    *time.Time `json:"resolved_at,omitempty"`
}

// AuditDecisionListResponse is one page of history.
type AuditDecisionListResponse struct {
	Decisions []AuditDecisionRow `json:"decisions"`
	// NextCursor is the token for the following page, empty on the last one.
	NextCursor string `json:"next_cursor,omitempty"`
	// Query echoes the axes that were applied, so a console can show the
	// filter it is actually looking at rather than the one it thinks it sent.
	Query AuditQueryEcho `json:"query"`
}

// AuditQueryEcho is the applied query, as the server parsed it.
type AuditQueryEcho struct {
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	PolicyID  string `json:"policy,omitempty"`
	SubjectID string `json:"subject,omitempty"`
	State     string `json:"state,omitempty"`
	Limit     int    `json:"limit"`
	// Order is fixed. It is reported anyway so that the one total order this
	// endpoint has is a documented answer and not an assumption the console
	// makes.
	Order string `json:"order"`
}

// AuditApproval is one recorded approval, as the audit console shows it.
type AuditApproval struct {
	Ordinal     int       `json:"ordinal"`
	ApproverID  string    `json:"approver_id"`
	Verdict     string    `json:"verdict"`
	BindingHash string    `json:"binding_hash"`
	SubmittedAt time.Time `json:"submitted_at"`
}

// AuditChallenge is one challenge row.
type AuditChallenge struct {
	Ordinal     int        `json:"ordinal"`
	Kind        string     `json:"kind"`
	State       string     `json:"state"`
	Deadline    *time.Time `json:"deadline,omitempty"`
	SatisfiedAt *time.Time `json:"satisfied_at,omitempty"`
}

// AuditDecisionDetail is one decision with everything it froze.
type AuditDecisionDetail struct {
	AuditDecisionRow
	// Request, FactSnapshot and Obligations are the frozen JSON, passed
	// through unchanged. The console renders them as text.
	Request      json.RawMessage `json:"request"`
	FactSnapshot json.RawMessage `json:"fact_snapshot"`
	Obligations  json.RawMessage `json:"obligations"`
	// PolicyDocument is the exchange-format text of the exact version this
	// decision was evaluated under, never the effective one.
	PolicyDocument string `json:"policy_document"`
	// PolicyOrigin says which authoring path owned that version.
	PolicyOrigin string           `json:"policy_origin"`
	Challenges   []AuditChallenge `json:"challenges"`
	Approvals    []AuditApproval  `json:"approvals"`
	// ViaAuditorStanding reports which rule admitted this read. A reader who
	// got here through R40's own-record rule is seeing one decision, not the
	// history, and the console says so rather than implying a wider view.
	ViaAuditorStanding bool `json:"via_auditor_standing"`
}

func (a *AuditConsole) list(w http.ResponseWriter, r *http.Request) {
	caller, ok := identity.SubjectFromContext(r.Context())
	if !ok || caller == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "this endpoint requires an end-user credential")
		return
	}
	if !a.auditors.Qualifies(caller) {
		a.recordRefusal(r.Context(), caller, "list", "")
		writeError(w, http.StatusForbidden, "not_an_auditor",
			"reading the decision history requires auditor standing; "+
				"a decision you created or are an approver of is readable at /audit/decisions/{id}")
		return
	}

	query, echo, err := parseAuditQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	page, err := a.history.ListDecisions(r.Context(), query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "the decision history could not be read")
		return
	}
	rows := make([]AuditDecisionRow, 0, len(page.Decisions))
	for _, d := range page.Decisions {
		rows = append(rows, rowOf(d))
	}
	writeJSON(w, http.StatusOK, AuditDecisionListResponse{
		Decisions:  rows,
		NextCursor: page.Next.Encode(),
		Query:      echo,
	})
}

func (a *AuditConsole) read(w http.ResponseWriter, r *http.Request) {
	caller, ok := identity.SubjectFromContext(r.Context())
	if !ok || caller == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "this endpoint requires an end-user credential")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "the path names no decision")
		return
	}

	standing := a.auditors.Qualifies(caller)
	if !standing {
		// R40's rule, asked of the component that owns it. Its refusal is
		// already audited, so this adds nothing but the answer.
		if _, err := a.access.Get(r.Context(), caller, id); err != nil {
			status, code, message := auditReadError(err)
			writeError(w, status, code, message)
			return
		}
	}

	detail, err := a.detail(r.Context(), id)
	if err != nil {
		status, code, message := auditReadError(err)
		writeError(w, status, code, message)
		return
	}
	detail.ViaAuditorStanding = standing
	writeJSON(w, http.StatusOK, detail)
}

func (a *AuditConsole) detail(ctx context.Context, id string) (AuditDecisionDetail, error) {
	d, err := a.history.Decision(ctx, id)
	if err != nil {
		return AuditDecisionDetail{}, err
	}
	progress, err := a.history.ChallengeProgress(ctx, id)
	if err != nil {
		return AuditDecisionDetail{}, err
	}
	approvals, err := a.history.Approvals(ctx, id)
	if err != nil {
		return AuditDecisionDetail{}, err
	}
	out := AuditDecisionDetail{
		AuditDecisionRow: rowOf(d),
		Request:          d.Request,
		FactSnapshot:     d.FactSnapshot,
		Obligations:      d.Obligations,
		Challenges:       make([]AuditChallenge, 0, len(progress)),
		Approvals:        make([]AuditApproval, 0, len(approvals)),
	}
	// The policy version is read separately and its absence is not fatal: a
	// decision outlives nothing here, but a deployment restored from a partial
	// dump should still show the decision it has rather than a 500.
	if record, perr := a.history.PolicyVersion(ctx, d.PolicyID, d.PolicyVersion); perr == nil {
		out.PolicyDocument = record.Document
		out.PolicyOrigin = string(record.Origin)
	} else if !errors.Is(perr, store.ErrNotFound) {
		return AuditDecisionDetail{}, perr
	}
	for _, p := range progress {
		out.Challenges = append(out.Challenges, AuditChallenge{
			Ordinal:     p.Ordinal,
			Kind:        string(p.Kind),
			State:       string(p.State),
			Deadline:    p.Deadline,
			SatisfiedAt: p.SatisfiedAt,
		})
	}
	for _, ap := range approvals {
		out.Approvals = append(out.Approvals, AuditApproval{
			Ordinal:     ap.ChallengeOrdinal,
			ApproverID:  ap.ApproverID,
			Verdict:     ap.Verdict,
			BindingHash: hex.EncodeToString(ap.BindingHash[:]),
			SubmittedAt: ap.SubmittedAt,
		})
	}
	return out, nil
}

func rowOf(d store.Decision) AuditDecisionRow {
	return AuditDecisionRow{
		ID:            d.ID,
		CallerID:      d.CallerID,
		PolicyID:      d.PolicyID,
		PolicyVersion: d.PolicyVersion,
		SubjectID:     d.SubjectID,
		ResourceID:    d.ResourceID,
		Action:        d.Action,
		State:         string(d.State),
		CreatedAt:     d.CreatedAt,
		ExpiresAt:     d.ExpiresAt,
		ResolvedAt:    d.ResolvedAt,
	}
}

// recordRefusal writes the chain entry R22's test scenario asks for.
//
// A failure to write it is logged nowhere and swallowed here on purpose: the
// refusal has already happened and the caller is getting a 403 either way. What
// must not happen is a refusal that turns into a 500 and reads, in a log, like
// an outage.
func (a *AuditConsole) recordRefusal(ctx context.Context, caller *identity.Subject, action, subject string) {
	_, _ = a.audit.Append(ctx, store.AuditEntry{
		Kind:    store.AuditKindAuditRefused,
		Subject: subject,
		Payload: map[string]any{
			"caller_id": caller.CallerID(),
			"issuer":    caller.Issuer,
			"action":    action,
			"claim":     a.auditors.Claim,
			"reason":    "no_auditor_standing",
			"at":        a.now().UTC().Format(time.RFC3339Nano),
		},
	})
}

// parseAuditQuery reads the four axes, the cursor and the page size.
func parseAuditQuery(r *http.Request) (store.DecisionQuery, AuditQueryEcho, error) {
	q := r.URL.Query()
	out := store.DecisionQuery{
		PolicyID:  strings.TrimSpace(q.Get("policy")),
		SubjectID: strings.TrimSpace(q.Get("subject")),
	}
	echo := AuditQueryEcho{PolicyID: out.PolicyID, SubjectID: out.SubjectID, Order: "created_at desc"}

	var err error
	if out.From, err = parseInstant(q.Get("from")); err != nil {
		return store.DecisionQuery{}, AuditQueryEcho{}, fmt.Errorf("from: %w", err)
	}
	if out.To, err = parseInstant(q.Get("to")); err != nil {
		return store.DecisionQuery{}, AuditQueryEcho{}, fmt.Errorf("to: %w", err)
	}
	if !out.From.IsZero() && !out.To.IsZero() && !out.From.Before(out.To) {
		return store.DecisionQuery{}, AuditQueryEcho{},
			errors.New("the period is empty: from must be before to")
	}
	if !out.From.IsZero() {
		echo.From = out.From.Format(time.RFC3339)
	}
	if !out.To.IsZero() {
		echo.To = out.To.Format(time.RFC3339)
	}

	if state := strings.TrimSpace(q.Get("state")); state != "" {
		if !validDecisionState(state) {
			return store.DecisionQuery{}, AuditQueryEcho{},
				fmt.Errorf("state %s is not a decision state", strconv.Quote(state))
		}
		out.State = store.DecisionState(state)
		echo.State = state
	}

	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		limit, cerr := strconv.Atoi(raw)
		if cerr != nil || limit <= 0 {
			return store.DecisionQuery{}, AuditQueryEcho{},
				fmt.Errorf("limit must be a positive integer, got %s", strconv.Quote(raw))
		}
		out.Limit = limit
	}
	if out.Limit == 0 {
		out.Limit = store.DefaultDecisionPageSize
	}
	if out.Limit > store.MaxDecisionPageSize {
		out.Limit = store.MaxDecisionPageSize
	}
	echo.Limit = out.Limit

	if out.After, err = store.DecodeDecisionCursor(strings.TrimSpace(q.Get("cursor"))); err != nil {
		return store.DecisionQuery{}, AuditQueryEcho{}, errors.New("the cursor is not one this endpoint issued")
	}
	return out, echo, nil
}

// parseInstant accepts RFC 3339 and nothing else. A date-only form was
// considered and refused: "2026-08-09" has no timezone, and an audit window
// that silently means the server's midnight is a window an auditor cannot
// reproduce.
func parseInstant(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	at, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, errors.New("must be an RFC 3339 instant, for example 2026-08-09T00:00:00Z")
	}
	return at.UTC(), nil
}

func validDecisionState(state string) bool {
	switch store.DecisionState(state) {
	case store.DecisionPending, store.DecisionAllowed, store.DecisionDenied,
		store.DecisionExpired, store.DecisionCancelled:
		return true
	default:
		return false
	}
}

// auditReadError maps a read failure to a status.
//
// "not authorised" and "does not exist" are the same answer for the same reason
// they are on the approval surface: a reader who may not see a decision learns
// nothing from the difference.
func auditReadError(err error) (status int, code, message string) {
	switch {
	case errors.Is(err, decision.ErrUnauthenticated):
		return http.StatusUnauthorized, "unauthenticated", "this endpoint requires an end-user credential"
	case errors.Is(err, decision.ErrNotAuthorized):
		return http.StatusForbidden, "not_readable", "this decision is not yours to read"
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound, "not_found", "no such decision"
	default:
		return http.StatusInternalServerError, "internal_error", "the decision could not be read"
	}
}
