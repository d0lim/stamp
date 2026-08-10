package api

// cancel.go is the console side of a delay: the authority named by the policy
// stops the wait, and the decision resolves to deny.
//
// It is a route of its own rather than a body on the approval endpoint, for two
// reasons that are really one. An endpoint called "approvals" that sometimes
// withdraws the thing it is named after is a surprise, and surprises in an
// authorization surface get discovered by an audit. And the approval endpoint
// treats an empty body as consent — a convention that must not be inherited by
// a verb whose accidental invocation is a denied decision.
//
// The path states the action, so the submission this layer sends is built here
// rather than forwarded from the request. Whatever the caller put in the body,
// the handler is asked to cancel, which is what the caller asked for by posting
// to this path at all. That also means there is no body a client can craft that
// names somebody else as the canceller: the canceller is the token's subject,
// established by the middleware and passed down untouched.

import (
	"errors"
	"net/http"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/identity"
)

// CancellationPattern is the endpoint a cancellation authority acts through.
const CancellationPattern = "POST /decisions/{id}/challenges/{ordinal}/cancellation"

// CancellationsConfig configures a [Cancellations].
type CancellationsConfig struct {
	// Decisions collects submissions. Required.
	Decisions ApprovalSubmitter
}

// Cancellations serves the delay cancellation endpoint.
type Cancellations struct {
	decisions ApprovalSubmitter
}

var _ Provider = (*Cancellations)(nil)

// NewCancellations builds the cancellation surface.
func NewCancellations(cfg CancellationsConfig) (*Cancellations, error) {
	if cfg.Decisions == nil {
		return nil, errors.New("api: the cancellation surface requires a decision service")
	}
	return &Cancellations{decisions: cfg.Decisions}, nil
}

// Routes implements [Provider]. A cancellation is a console action behind an
// end-user credential, which is the only pair the mount table admits there — so
// a workload cannot reach this endpoint at all, quite apart from the handler
// refusing one.
func (c *Cancellations) Routes() []Route {
	return []Route{{
		Name:    "delay-cancel",
		Surface: SurfaceConsole,
		Pattern: CancellationPattern,
		Auth:    AuthUser,
		Handler: http.HandlerFunc(c.cancel),
	}}
}

func (c *Cancellations) cancel(w http.ResponseWriter, r *http.Request) {
	caller, ok := identity.SubjectFromContext(r.Context())
	if !ok || caller == nil {
		// Unreachable behind RequireUser, and still checked: the day this route
		// is mounted somewhere else, the failure should be a 401 and not a
		// cancellation attributed to nobody.
		writeError(w, http.StatusUnauthorized, "unauthenticated", "this endpoint requires an end-user credential")
		return
	}
	id, ordinal, err := challengeRef(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	result, err := c.decisions.Submit(r.Context(), decision.Submission{
		Caller:     caller,
		DecisionID: id,
		Ordinal:    ordinal,
		Payload:    challenge.DelayCancelPayload(),
	})
	if err != nil {
		// The same table the approval surface uses. A cancellation refused for
		// not holding the authority has to be indistinguishable from a decision
		// that does not exist, and that mapping already exists in one place.
		status, code, message := approvalError(err)
		writeError(w, status, code, message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
