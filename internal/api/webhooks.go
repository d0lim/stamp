package api

// webhooks.go is the listener an external system answers on when the challenge
// it was asked about is finished.
//
// It is the one surface a deployment may have to expose beyond its own
// perimeter, and three things follow from that.
//
// It verifies nothing itself. The correlator and the shared secret belong to
// the handler that issued them, so this layer reads a path and a body and hands
// both down. A signature check here would be a second implementation of the one
// that matters, in a place that does not know which target issued the
// challenge.
//
// It establishes no identity, because there is none to establish: the caller
// holds no credential and proves itself with the signature instead. The
// lifecycle still needs a principal to attribute the submission to, so this
// layer names one — a workload-kind subject that no human-target challenge
// handler will accept. A quorum or a delay reached through this path is refused
// for being a machine before anything else is even looked at.
//
// It answers on a table with two rows and tells a stranger nothing. A delivery
// that was accepted and a delivery that arrived after the challenge already
// transitioned are both 202, so a retrying sender stops retrying and a
// challenge that transitioned once stays transitioned once. Everything else —
// a forged signature, a decision that does not exist, a challenge that is not
// there, a body that cannot be read — is one 403 with one body. The alternative
// is a probe that learns which decision identifiers are real by reading status
// codes, which is a thing an unauthenticated caller must not be able to do.

import (
	"errors"
	"net/http"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/store"
)

// ExternalCallbackPattern is the endpoint an external challenge is answered on.
//
// The decision identifier and the ordinal are path segments for the same reason
// they are on the approval endpoints: they name the thing being acted on, and a
// path is what an audit row, a log line and a target's configuration can all
// carry unchanged. They are not the authentication — the body's signature is.
const ExternalCallbackPattern = "POST /external/{id}/{ordinal}"

// DefaultMaxCallbackBytes bounds a callback body. A callback is a correlator, a
// verdict and a digest, so this is generous and still small enough that an
// unauthenticated surface cannot be made to allocate.
const DefaultMaxCallbackBytes = 8 << 10

// CallbackPrincipalIssuer names the callback listener in the audit trail.
//
// A refused callback still has to be attributed to somebody, and "the callback
// listener" is the truthful name for a caller who presented no credential.
const CallbackPrincipalIssuer = "stamp.callback"

// CallbacksConfig configures a [Callbacks].
type CallbacksConfig struct {
	// Decisions collects submissions. Required.
	Decisions ApprovalSubmitter
	// MaxRequestBytes bounds a callback body. Zero selects
	// DefaultMaxCallbackBytes.
	MaxRequestBytes int64
}

// Callbacks serves the external challenge's callback endpoint.
type Callbacks struct {
	decisions ApprovalSubmitter
	maxBytes  int64
}

var _ Provider = (*Callbacks)(nil)

// NewCallbacks builds the callback surface.
func NewCallbacks(cfg CallbacksConfig) (*Callbacks, error) {
	if cfg.Decisions == nil {
		return nil, errors.New("api: the callback surface requires a decision service")
	}
	c := &Callbacks{decisions: cfg.Decisions, maxBytes: cfg.MaxRequestBytes}
	if c.maxBytes <= 0 {
		c.maxBytes = DefaultMaxCallbackBytes
	}
	return c, nil
}

// Routes implements [Provider].
func (c *Callbacks) Routes() []Route {
	return []Route{{
		Name:    "external-callback",
		Surface: SurfaceCallback,
		Pattern: ExternalCallbackPattern,
		Auth:    AuthPublic,
		Handler: http.HandlerFunc(c.external),
	}}
}

// callbackPrincipal is the subject a callback submission is attributed to.
//
// It is a workload rather than a user on purpose. Every challenge kind that
// collects from people refuses a workload credential in its own code path, so
// naming this principal a machine is what makes an approval or a cancellation
// unreachable through the unauthenticated listener even if a route ever pointed
// at the wrong ordinal.
func callbackPrincipal() *identity.Subject {
	return &identity.Subject{
		Kind:   identity.SubjectWorkload,
		Issuer: CallbackPrincipalIssuer,
		ID:     "external-callback",
	}
}

func (c *Callbacks) external(w http.ResponseWriter, r *http.Request) {
	id, ordinal, err := challengeRef(r)
	if err != nil {
		// Even a malformed path gets the uniform refusal: telling a caller
		// which part of their guess was wrong is telling them how to guess
		// better.
		rejectCallback(w)
		return
	}

	payload, err := readApprovalBody(w, r, c.maxBytes)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", err.Error())
		return
	}

	_, err = c.decisions.Submit(r.Context(), decision.Submission{
		Caller:     callbackPrincipal(),
		DecisionID: id,
		Ordinal:    ordinal,
		Payload:    payload,
	})
	switch callbackStatus(err) {
	case http.StatusAccepted:
		// The decision itself is not returned. The target answered a question;
		// what STAMP concluded is not theirs to read.
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
	case http.StatusForbidden:
		rejectCallback(w)
	default:
		// [callbackStatus] answers with exactly three statuses and the two
		// above are taken, so this arm is the outage one and writes its status
		// out rather than forwarding the switch tag. That is not style: the
		// error code artifact is rendered by reading these call sites
		// (internal/api/errorcodes_test.go), and a status that is a local
		// variable is a row the scanner cannot fill in. It fails the run rather
		// than rendering a hole, so this used to be the one call site standing
		// between the package and a machine-checkable vocabulary.
		//
		// The bytes are unchanged: the old code forwarded a value that could
		// only ever have been this constant.
		writeError(w, http.StatusInternalServerError, "internal_error", "the callback could not be processed")
	}
}

func rejectCallback(w http.ResponseWriter) {
	writeError(w, http.StatusForbidden, "rejected", "the callback was not accepted")
}

// callbackStatus maps a submission outcome to one of three answers.
//
// The accepted row is the one worth reading twice. A challenge that is no
// longer collecting and a decision that expired first are both success from the
// sender's side: the state transitioned exactly once, and there is nothing a
// retry could improve. Reporting them as conflicts would have a well-behaved
// target retry a delivery that already landed until it gave up.
func callbackStatus(err error) int {
	switch {
	case err == nil,
		errors.Is(err, decision.ErrNotPending),
		errors.Is(err, challenge.ErrNotSubmittable),
		errors.Is(err, store.ErrDecisionExpired):
		return http.StatusAccepted
	case errors.Is(err, challenge.ErrNotTarget),
		errors.Is(err, challenge.ErrInvalidPayload),
		errors.Is(err, challenge.ErrUnsupportedSpec),
		errors.Is(err, challenge.ErrNoHandler),
		errors.Is(err, decision.ErrNoSuchChallenge),
		errors.Is(err, decision.ErrUnauthenticated),
		errors.Is(err, decision.ErrNotAuthorized),
		errors.Is(err, store.ErrNotFound):
		return http.StatusForbidden
	default:
		// An outage is the one thing a sender should retry, and the one thing
		// that is not a refusal. The error is not narrated: the audit chain is
		// where a database failure belongs, not a response to a stranger.
		return http.StatusInternalServerError
	}
}
