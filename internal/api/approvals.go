package api

// approvals.go is the surface an approver acts through: read what you are being
// asked to authorise, then say yes.
//
// Two things about it are the point rather than the plumbing.
//
// It is on the console listener behind an end-user credential, and it could not
// be anywhere else — the mount table admits only that pair there, so an
// approval endpoint that a workload could call is not a bug that review has to
// catch, it is a route that does not mount.
//
// The approver is the `sub` of the verified token. This layer never reads an
// identity out of a path, a query or a body; it takes the [identity.Subject]
// the middleware established and passes it down. The submission body is
// forwarded to the challenge handler verbatim, and it is the handler that
// refuses a body carrying an approver name — one refusal, in the place that
// knows what a valid body is.
//
// # The submission budget, and why its refusal looks different
//
// R43's fourth axis is here: a per-approver rate limit on submissions, charged
// before the lifecycle is asked anything. What makes it worth standing at this
// door is what a submission costs behind it — a row lock on the decision, a
// challenge handler's verification, and, for a quorum, an approval row — so a
// caller replaying submissions is a caller holding the serialized part of the
// lifecycle, and a limit applied after that has limited nothing.
//
// Its refusal is a status code, and the two other budgets this unit added are
// not. That is deliberate rather than an inconsistency to be factored away. A
// challenge issue has no HTTP response of its own — the caller on that path is a
// PEP asking for a decision — so a refusal there can only be expressed as
// challenge state. This one is answering a console, over a request the approver
// made themselves, about an action they can simply retry; 429 with a code is
// what a console can render and what a human can act on, and folding it into a
// decision object would be answering a question nobody asked.
//
// The limit is **per instance**: the buckets live in this process, so a fleet of
// N replicas admits N times what is configured. That is the same trade the
// decide surface makes and for the same reason — a limiter that queried would
// cost more than what it sheds — and it is bounded the same way, by the fact that
// what a submission can actually achieve is governed by the quorum threshold and
// the challenge's own idempotence, which are in the database. An operator sizing
// a fleet divides.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/store"
	"github.com/d0lim/stamp/internal/stream"
)

// The approval endpoints.
//
// The decision identifier and the challenge ordinal are path segments because
// they name the thing being acted on, and because a path is what an audit row,
// a log line and a console link can all carry unchanged.
const (
	// ApprovalSubmitPattern is the submission endpoint.
	ApprovalSubmitPattern = "POST /decisions/{id}/challenges/{ordinal}/approvals"
	// ApprovalReviewPattern is the read an approver does first.
	ApprovalReviewPattern = "GET /decisions/{id}/challenges/{ordinal}/approval"
)

// DefaultMaxApprovalBytes bounds an approval body. A submission is a verdict
// and a digest, so this is generous by two orders of magnitude and still small
// enough that the surface cannot be made to allocate.
const DefaultMaxApprovalBytes = 8 << 10

// DefaultMaxTrackedApprovers bounds the submission-budget table. Its keys are
// caller identifiers from verified tokens, which is a smaller and better
// controlled namespace than a subject identifier — and it is bounded anyway,
// because [stream.Limiter]'s refusal on a full table is what makes "the limiter
// could not record a charge" a refusal rather than a hole.
const DefaultMaxTrackedApprovers = 4096

// DefaultApprovalRate is how often one approver may submit, for a deployment
// that configured no budget (R43).
//
// A person clicking approve does it once per decision and then reads the next
// one. Two a second sustained, twenty in a burst, is far above anything a human
// does through a console and far below what a replay costs the lifecycle.
//
// An operator who wants no limit says so with a negative rate.
var DefaultApprovalRate = stream.RateLimit{PerSecond: 2, Burst: 20}

// The vocabulary of an approval refused under the budget.
const (
	// ApprovalRateLimitedCode is the error code the console reads.
	ApprovalRateLimitedCode = "rate_limited"

	// ApprovalRateLimitedReason is the ground written into the audit record.
	//
	// It is its own word, not the decide path's `rate_limited`, because the two
	// are different budgets over different traffic and an operator reading the
	// chain has to be able to tell which one shed what: one says a PEP was asking
	// for too many decisions, this one says an approver was submitting too often.
	ApprovalRateLimitedReason = "approval_rate_limited"

	// rateScopeApprover names the budget in the audit record, alongside the
	// "caller" and "subject" the decide path writes.
	rateScopeApprover = "approver"
)

// ApprovalSubmitter takes evidence toward a challenge and returns the decision
// as it then stands.
//
// It is an interface rather than *decision.Service so that this surface can be
// exercised without a database, and so that the console never reaches past the
// lifecycle into a challenge handler: everything a submission has to do — the
// expiry check, the state transition, the audit row — happens behind this call.
type ApprovalSubmitter interface {
	Submit(ctx context.Context, sub decision.Submission) (decision.Result, error)
}

// ApprovalReviewer returns the material an approver is being asked to judge,
// including the binding hash their approval will be recorded against (R31).
type ApprovalReviewer interface {
	Review(ctx context.Context, req challenge.QuorumReviewRequest) (challenge.QuorumReview, error)
}

// ApprovalsConfig configures an [Approvals].
type ApprovalsConfig struct {
	// Decisions collects submissions. Required.
	Decisions ApprovalSubmitter
	// Reviews serves the approval screen's read. Required.
	Reviews ApprovalReviewer
	// MaxRequestBytes bounds a submission body. Zero selects
	// DefaultMaxApprovalBytes.
	MaxRequestBytes int64
	// Rate bounds submissions per approver (R43). A zero field selects
	// [DefaultApprovalRate] for that field; a negative rate removes the limit.
	Rate stream.RateLimit
	// MaxTrackedApprovers overrides [DefaultMaxTrackedApprovers].
	MaxTrackedApprovers int
	// Audit records refusals under the budget. It is optional only so that a
	// test of this surface need not stand up a chain writer; a deployment that
	// leaves it nil has a limit that sheds silently, which is why the wiring
	// passes the same buffer the decide surface writes through.
	Audit EventRecorder
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Approvals serves the approval endpoints.
type Approvals struct {
	decisions ApprovalSubmitter
	reviews   ApprovalReviewer
	maxBytes  int64
	limiter   *stream.Limiter
	rate      stream.RateLimit
	audit     EventRecorder
	now       func() time.Time
}

var _ Provider = (*Approvals)(nil)

// NewApprovals builds the approval surface.
func NewApprovals(cfg ApprovalsConfig) (*Approvals, error) {
	if cfg.Decisions == nil {
		return nil, errors.New("api: the approval surface requires a decision service")
	}
	if cfg.Reviews == nil {
		return nil, errors.New("api: the approval surface requires a reviewer")
	}
	a := &Approvals{
		decisions: cfg.Decisions,
		reviews:   cfg.Reviews,
		maxBytes:  cfg.MaxRequestBytes,
		rate:      cfg.Rate,
		audit:     cfg.Audit,
		now:       cfg.Now,
	}
	if a.maxBytes <= 0 {
		a.maxBytes = DefaultMaxApprovalBytes
	}
	if a.now == nil {
		a.now = time.Now
	}
	a.rate = a.rate.WithZeroDefault(DefaultApprovalRate)
	tracked := cfg.MaxTrackedApprovers
	if tracked <= 0 {
		tracked = DefaultMaxTrackedApprovers
	}
	a.limiter = stream.NewLimiter(tracked, func() time.Time { return a.now() })
	return a, nil
}

// Routes implements [Provider]. Both endpoints are console endpoints behind an
// end-user credential, which is the only pair the mount table admits there.
func (a *Approvals) Routes() []Route {
	return []Route{
		{
			Name:    "approval-review",
			Surface: SurfaceConsole,
			Pattern: ApprovalReviewPattern,
			Auth:    AuthUser,
			Handler: http.HandlerFunc(a.review),
		},
		{
			Name:    "approval-submit",
			Surface: SurfaceConsole,
			Pattern: ApprovalSubmitPattern,
			Auth:    AuthUser,
			Handler: http.HandlerFunc(a.submit),
		},
	}
}

func (a *Approvals) submit(w http.ResponseWriter, r *http.Request) {
	caller, ok := identity.SubjectFromContext(r.Context())
	if !ok || caller == nil {
		// Unreachable behind RequireUser, and still checked: the day this route
		// is mounted somewhere else, the failure should be a 401 and not a
		// submission attributed to nobody.
		writeError(w, http.StatusUnauthorized, "unauthenticated", "this endpoint requires an end-user credential")
		return
	}
	// Charged before the path is parsed and before the body is read, because
	// everything below this line is work a caller over its budget has already
	// been told it may not have. The key is the caller identifier the verified
	// token established — never anything from the request — so a budget cannot be
	// escaped by spelling a decision differently.
	if !a.limiter.Allow("approver\x1f"+caller.CallerID(), a.rate, 1) {
		a.refuseSubmission(w, r, caller)
		return
	}

	id, ordinal, err := challengeRef(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	payload, err := readApprovalBody(w, r, a.maxBytes)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", err.Error())
		return
	}

	result, err := a.decisions.Submit(r.Context(), decision.Submission{
		// The approver is the token's subject and nothing from the request
		// says otherwise.
		Caller:     caller,
		DecisionID: id,
		Ordinal:    ordinal,
		Payload:    payload,
	})
	if err != nil {
		status, code, message := approvalError(err)
		writeError(w, status, code, message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// refuseSubmission answers a submission over the budget and records it.
//
// The audit goes through the buffer rather than through a synchronous append,
// for the reason the decide surface's does: this is the path taken by a caller
// sending more than it is allowed to, and a chain transaction per refusal would
// make the limiter generate load in proportion to the load it exists to shed.
// What can be lost that way is the record of a refusal, never the record of a
// submission that was accepted — those are written by the lifecycle, inside the
// transaction that accepted them.
//
// It carries `Retry-After` for the reason the decide path's refusal does, and
// here the header is doing exactly what RFC 9110 specifies it for: this is a
// 429, which is one of the three statuses the specification names. The shape of
// the refusal is otherwise untouched — same status, same code, same message —
// because what an approver needs is unchanged and it is the console in front of
// them, not an intermediary, that renders it.
func (a *Approvals) refuseSubmission(w http.ResponseWriter, r *http.Request, caller *identity.Subject) {
	if a.audit != nil {
		a.audit.Record(r.Context(), Event{
			Kind:     EventRateLimited,
			Time:     a.now(),
			CallerID: caller.CallerID(),
			Reason:   ApprovalRateLimitedReason,
			Method:   r.Method,
			Path:     r.URL.Path,
			Scope:    rateScopeApprover,
			Limit:    formatRate(a.rate),
		})
	}
	w.Header().Set(RetryAfterHeader, strconv.Itoa(retryAfterSeconds(a.rate)))
	writeError(w, http.StatusTooManyRequests, ApprovalRateLimitedCode,
		"too many submissions; try again shortly")
}

func (a *Approvals) review(w http.ResponseWriter, r *http.Request) {
	caller, ok := identity.SubjectFromContext(r.Context())
	if !ok || caller == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "this endpoint requires an end-user credential")
		return
	}
	id, ordinal, err := challengeRef(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	review, err := a.reviews.Review(r.Context(), challenge.QuorumReviewRequest{
		DecisionID: id,
		Ordinal:    ordinal,
		Subject:    caller,
		Now:        a.now().UTC(),
	})
	if err != nil {
		status, code, message := approvalError(err)
		writeError(w, status, code, message)
		return
	}
	writeJSON(w, http.StatusOK, review)
}

// challengeRef reads the decision identifier and challenge ordinal out of the
// path.
func challengeRef(r *http.Request) (string, int, error) {
	id := r.PathValue("id")
	if id == "" {
		return "", 0, errors.New("the path names no decision")
	}
	raw := r.PathValue("ordinal")
	ordinal, err := strconv.Atoi(raw)
	if err != nil || ordinal < 0 {
		return "", 0, errors.New("the challenge ordinal must be a non-negative integer, got " + strconv.Quote(raw))
	}
	return id, ordinal, nil
}

// readApprovalBody reads the submission body, bounded.
//
// An empty body is a valid submission — "I approve" needs no fields — so this
// returns nil rather than an error for one, and leaves every judgement about
// the content to the challenge handler.
func readApprovalBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
	if err != nil {
		return nil, errors.New("the submission body is too large")
	}
	if len(body) == 0 {
		return nil, nil
	}
	return body, nil
}

// approvalError maps a collection failure to a status a console can act on.
//
// The mapping is a table for the same reason the mount table is: every one of
// these is a refusal an operator has to be able to tell apart from an outage,
// and a handler deciding case by case is how "you are not an approver" ends up
// as a 500 that pages somebody.
//
// It is shared by every surface that acts on one named decision through the
// lifecycle — submission, review, cancellation, the inbox — so that "you may not
// have this" has one answer rather than one per handler.
func approvalError(err error) (status int, code, message string) {
	switch {
	case errors.Is(err, decision.ErrUnauthenticated):
		return http.StatusUnauthorized, "unauthenticated", "this endpoint requires an end-user credential"
	case errors.Is(err, challenge.ErrNotTarget), errors.Is(err, decision.ErrNotAuthorized),
		errors.Is(err, decision.ErrNoSuchChallenge), errors.Is(err, store.ErrNotFound):
		// One answer, and the same bytes, for every way of not being allowed to
		// have this decision — including the way that is simply that it does not
		// exist. This is what the comment here used to *claim* while the code
		// answered `403 not_an_approver` for the first two and `404 not_found`
		// for the last two (#38), which made a two-request oracle out of R40: ask
		// about an identifier, read the status, learn whether it names anything.
		//
		// The cost is paid by the person who has standing and lost it — an
		// approver revised out of the set reads "no such decision" rather than
		// "not waiting on you". The inbox is where that person is told the truth,
		// and it can afford to: a list of what is waiting on you leaks nothing by
		// omitting what is not.
		return http.StatusNotFound, "not_found", "no such decision or challenge"
	case errors.Is(err, store.ErrDecisionExpired):
		return http.StatusConflict, "expired", "this decision has expired"
	case errors.Is(err, decision.ErrNotPending), errors.Is(err, challenge.ErrNotSubmittable):
		return http.StatusConflict, "not_collecting", "this challenge is not collecting submissions"
	case errors.Is(err, challenge.ErrBindingChanged):
		return http.StatusConflict, "material_changed",
			"the decision changed since it was shown to you; review it again"
	case errors.Is(err, challenge.ErrVerdictUnsupported):
		return http.StatusBadRequest, "unsupported_verdict", err.Error()
	case errors.Is(err, challenge.ErrInvalidPayload):
		return http.StatusBadRequest, "invalid_submission", err.Error()
	case errors.Is(err, challenge.ErrGroupSourceUnsupported), errors.Is(err, challenge.ErrUnsupportedSpec),
		errors.Is(err, challenge.ErrNoHandler):
		return http.StatusNotImplemented, "unsupported_challenge",
			"this build cannot collect submissions for that challenge"
	default:
		// The error itself is not narrated: a console user is not the audience
		// for a database failure, and the audit chain is where it belongs.
		return http.StatusInternalServerError, "internal_error", "the submission could not be processed"
	}
}
