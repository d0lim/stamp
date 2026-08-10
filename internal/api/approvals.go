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
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Approvals serves the approval endpoints.
type Approvals struct {
	decisions ApprovalSubmitter
	reviews   ApprovalReviewer
	maxBytes  int64
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
		now:       cfg.Now,
	}
	if a.maxBytes <= 0 {
		a.maxBytes = DefaultMaxApprovalBytes
	}
	if a.now == nil {
		a.now = time.Now
	}
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
func approvalError(err error) (status int, code, message string) {
	switch {
	case errors.Is(err, decision.ErrUnauthenticated):
		return http.StatusUnauthorized, "unauthenticated", "this endpoint requires an end-user credential"
	case errors.Is(err, challenge.ErrNotTarget), errors.Is(err, decision.ErrNotAuthorized):
		// Deliberately the same answer as for a decision that does not exist
		// would be: a non-approver learns nothing about what they asked for.
		return http.StatusForbidden, "not_an_approver", "this decision is not waiting on you"
	case errors.Is(err, decision.ErrNoSuchChallenge), errors.Is(err, store.ErrNotFound):
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
