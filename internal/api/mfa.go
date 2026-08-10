package api

// mfa.go is where a delegated authentication comes back.
//
// It is on the callback listener and not the console one, and that is a
// deliberate exposure decision rather than a filing choice: the party that
// completes a step-up is a browser following an IdP redirect, and the browser
// may be nowhere near the operator network the console is bound to. The mount
// table admits only workload and public credentials there, so this route is
// public — and being public is exactly why the two things it does are worth
// stating.
//
// It verifies the completion token before anything else, through the same
// [identity.Verifier] every other surface uses. A public route is not an
// unauthenticated one here: it is one whose credential arrives in the body
// instead of a header, and the trust boundary it is checked against is the same
// pinned issuer set.
//
// It then hands the correlator down and judges nothing. Whether the `acr` is
// strong enough, whether the `auth_time` is recent enough, whether the
// correlator is this decision's and unspent — all of that belongs to the mfa
// handler, because a second copy of those rules living in an HTTP handler is a
// second copy that can drift from the first.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/challenge/mfa"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/store"
)

// MFACallbackPattern is where a completed delegated authentication is posted.
//
// The decision and the challenge are path segments because STAMP built the
// redirect target itself and therefore knows both; the correlator in the body
// is what proves the completion belongs to them.
const MFACallbackPattern = "POST /decisions/{id}/challenges/{ordinal}/mfa"

// MFACallbackPath renders the callback path for one challenge.
//
// It is exported because a step-up has to be told where to come back to before
// it starts, and the alternative is the challenge handler holding its own copy
// of the route pattern. Pass the result, joined to the deployment's callback
// base URL, as [mfa.Config].CallbackURL.
func MFACallbackPath(decisionID string, ordinal int) string {
	return "/decisions/" + url.PathEscape(decisionID) + "/challenges/" + strconv.Itoa(ordinal) + "/mfa"
}

// DefaultMaxMFACallbackBytes bounds a completion body. It holds a correlator
// and an ID token, and an ID token is the larger of the two by an order of
// magnitude.
const DefaultMaxMFACallbackBytes = 16 << 10

// MFATokenVerifier turns a completion credential into a caller.
//
// It is an interface so this surface can be exercised without a JWKS endpoint;
// [identity.Verifier] satisfies it, and it is the only implementation a
// deployment should have.
type MFATokenVerifier interface {
	Verify(ctx context.Context, raw string) (*identity.Subject, error)
}

// MFAConfig configures an [MFA] surface.
type MFAConfig struct {
	// Decisions collects the completion. Required.
	Decisions ApprovalSubmitter
	// Tokens verifies the completion credential. Required.
	Tokens MFATokenVerifier
	// MaxRequestBytes bounds a completion body. Zero selects
	// [DefaultMaxMFACallbackBytes].
	MaxRequestBytes int64
}

// MFA serves the delegated MFA callback.
type MFA struct {
	decisions ApprovalSubmitter
	tokens    MFATokenVerifier
	maxBytes  int64
}

var _ Provider = (*MFA)(nil)

// NewMFA builds the callback surface.
func NewMFA(cfg MFAConfig) (*MFA, error) {
	if cfg.Decisions == nil {
		return nil, errors.New("api: the mfa callback requires a decision service")
	}
	if cfg.Tokens == nil {
		return nil, errors.New("api: the mfa callback requires a token verifier")
	}
	m := &MFA{decisions: cfg.Decisions, tokens: cfg.Tokens, maxBytes: cfg.MaxRequestBytes}
	if m.maxBytes <= 0 {
		m.maxBytes = DefaultMaxMFACallbackBytes
	}
	return m, nil
}

// Routes implements [Provider].
func (m *MFA) Routes() []Route {
	return []Route{{
		Name:    "mfa-callback",
		Surface: SurfaceCallback,
		Pattern: MFACallbackPattern,
		Auth:    AuthPublic,
		Handler: http.HandlerFunc(m.complete),
	}}
}

// mfaCompletion is the callback body.
type mfaCompletion struct {
	// Correlator is the value the challenge was issued under, echoed back from
	// the authorization request's `state`.
	Correlator string `json:"correlator"`
	// IDToken is the credential the IdP minted for the authentication.
	IDToken string `json:"id_token"`
}

func (m *MFA) complete(w http.ResponseWriter, r *http.Request) {
	id, ordinal, err := challengeRef(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	body, err := readApprovalBody(w, r, m.maxBytes)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", err.Error())
		return
	}

	var completion mfaCompletion
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&completion); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "the completion body could not be read")
		return
	}
	if completion.Correlator == "" || completion.IDToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"a completion must carry both a correlator and an id_token")
		return
	}

	caller, err := m.tokens.Verify(r.Context(), completion.IDToken)
	if err != nil {
		// The verification reason is not narrated to an unauthenticated caller.
		// identity.ReasonFor is what puts it in the audit trail.
		writeError(w, http.StatusUnauthorized, "invalid_token",
			"the completion credential was not accepted")
		return
	}

	payload, err := json.Marshal(mfa.Submission{Correlator: completion.Correlator})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "the completion could not be processed")
		return
	}
	result, err := m.decisions.Submit(r.Context(), decision.Submission{
		Caller:     caller,
		DecisionID: id,
		Ordinal:    ordinal,
		Payload:    payload,
	})
	if err != nil {
		status, code, message := mfaError(err)
		writeError(w, status, code, message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// mfaError maps a completion failure to a status the IdP's redirect target can
// act on.
//
// Every refusal that says something about the strength of the authentication —
// a downgraded `acr`, a stale `auth_time`, an `amr` that does not match — is a
// 403 with a distinct code, because an operator staring at a challenge nobody
// can satisfy needs to know whether their IdP is misconfigured or their policy
// asks for something that IdP cannot do. The message text is not the error's,
// so a caller learns which check failed and nothing about the token that failed
// it.
func mfaError(err error) (status int, code, message string) {
	switch {
	case errors.Is(err, mfa.ErrCorrelatorMismatch):
		return http.StatusForbidden, "correlator_mismatch", "this completion does not belong to that challenge"
	case errors.Is(err, mfa.ErrCorrelatorConsumed):
		return http.StatusConflict, "correlator_consumed", "that authentication has already been used"
	case errors.Is(err, mfa.ErrCredentialMismatch):
		return http.StatusForbidden, "credential_mismatch", "the completion came from an unexpected party"
	case errors.Is(err, mfa.ErrACRNotAllowed):
		return http.StatusForbidden, "acr_not_allowed",
			"the authentication context class is not one this deployment admits"
	case errors.Is(err, mfa.ErrACRUnsatisfied):
		return http.StatusForbidden, "acr_unsatisfied",
			"the authentication is weaker than the policy requires"
	case errors.Is(err, mfa.ErrAMRMismatch):
		return http.StatusForbidden, "amr_mismatch", "the authentication methods are not the ones required"
	case errors.Is(err, mfa.ErrStaleAuthentication):
		return http.StatusForbidden, "stale_authentication",
			"the authentication predates the challenge; authenticate again"
	case errors.Is(err, mfa.ErrNonceMismatch):
		return http.StatusForbidden, "nonce_mismatch", "this completion answers a different request"
	case errors.Is(err, mfa.ErrContextChanged):
		return http.StatusConflict, "material_changed",
			"the decision changed since the challenge was issued; start again"
	case errors.Is(err, mfa.ErrDirectModeUnimplemented):
		return http.StatusNotImplemented, "unsupported_challenge",
			"this build does not implement the direct mfa mode"
	case errors.Is(err, challenge.ErrNotTarget):
		return http.StatusForbidden, "not_the_subject", "this challenge is not waiting on you"
	case errors.Is(err, decision.ErrNoSuchChallenge), errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound, "not_found", "no such decision or challenge"
	case errors.Is(err, store.ErrDecisionExpired):
		return http.StatusConflict, "expired", "this decision has expired"
	case errors.Is(err, decision.ErrNotPending):
		return http.StatusConflict, "not_collecting", "this challenge is not collecting completions"
	case errors.Is(err, challenge.ErrInvalidPayload):
		return http.StatusBadRequest, "invalid_submission", "the completion could not be read"
	default:
		return http.StatusInternalServerError, "internal_error", "the completion could not be processed"
	}
}
