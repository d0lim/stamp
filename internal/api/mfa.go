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
//
// # Two methods, one judgement
//
// The GET is the RFC 9470 step-up landing (D26's default demo path): an IdP
// redirects a browser here with `code` and `state`, the challenge redeems them
// for an ID token, and that token walks the same three lines the POST body's
// token does — verify, submit, judge. The POST stays because it is the shape a
// CIBA poll and the mock-OP tests hand a token back in, and because a deployment
// that resolves the challenge some other way has nothing to redeem.
//
// # The GET answers a person
//
// Everything else on this listener answers a machine, and [Callbacks.external]
// answers a stranger in one uniform 403 so that status codes cannot be read as a
// decision-identifier oracle. Neither policy fits by itself, so the GET splits
// the round in two at the point where the caller stops being a stranger.
//
// Before a `state` checks out, the party holding the link has proved nothing —
// so every refusal is one status and one page ([redemptionRefusal]), and
// [Callbacks.external]'s rule holds unchanged. After it checks out, the party is
// the subject: they hold 32 bytes this deployment minted for this challenge and
// an authorization code the IdP issued against it. Telling them "403" at that
// point is telling somebody who has just typed a password nothing they can act
// on, so the page names which of five things happened ([landingError]) — all of
// them about the strength of an authentication or the age of a link, none of
// them about which decisions exist.

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
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

// MFARedirectPattern is where an IdP returns the subject's browser.
//
// It is the same path as [MFACallbackPattern] because it is the same thing
// arriving by a different route, and because the redirect target a step-up
// registers with the IdP has to be a URL the IdP will redirect to — one path per
// challenge, which is what makes `state` free to be a CSRF token and nothing
// more (KTD2).
const MFARedirectPattern = "GET /decisions/{id}/challenges/{ordinal}/mfa"

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

// ChallengeRedeemer turns an IdP redirect into the makings of a submission.
//
// It is an interface for the reason [MFATokenVerifier] is: this surface is
// exercised without a database. [decision.Service] satisfies it.
type ChallengeRedeemer interface {
	Redeem(ctx context.Context, cb decision.Callback) (challenge.Redemption, error)
}

// MFAConfig configures an [MFA] surface.
type MFAConfig struct {
	// Decisions collects the completion. Required.
	Decisions ApprovalSubmitter
	// Tokens verifies the completion credential. Required.
	Tokens MFATokenVerifier
	// Redeemer redeems an IdP redirect. Required: without it the step-up that
	// D26 made the default path has no way back, which is the whole of #41.
	Redeemer ChallengeRedeemer
	// MaxRequestBytes bounds a completion body. Zero selects
	// [DefaultMaxMFACallbackBytes].
	MaxRequestBytes int64
}

// MFA serves the delegated MFA callback.
type MFA struct {
	decisions ApprovalSubmitter
	tokens    MFATokenVerifier
	redeemer  ChallengeRedeemer
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
	if cfg.Redeemer == nil {
		return nil, errors.New("api: the mfa callback requires a redeemer for the step-up redirect")
	}
	m := &MFA{
		decisions: cfg.Decisions,
		tokens:    cfg.Tokens,
		redeemer:  cfg.Redeemer,
		maxBytes:  cfg.MaxRequestBytes,
	}
	if m.maxBytes <= 0 {
		m.maxBytes = DefaultMaxMFACallbackBytes
	}
	return m, nil
}

// Routes implements [Provider].
func (m *MFA) Routes() []Route {
	return []Route{
		{
			Name:    "mfa-callback",
			Surface: SurfaceCallback,
			Pattern: MFACallbackPattern,
			Auth:    AuthPublic,
			Handler: http.HandlerFunc(m.complete),
		},
		{
			Name:    "mfa-redirect",
			Surface: SurfaceCallback,
			Pattern: MFARedirectPattern,
			Auth:    AuthPublic,
			Handler: http.HandlerFunc(m.land),
		},
	}
}

// land receives the IdP's redirect and finishes the step-up.
//
// Four steps and no shortcuts: route the callback to its challenge, let the
// challenge redeem the code for a token, verify that token against the pinned
// issuer set, and submit it. Nothing here decides what the authentication was
// worth — [mfa.Delegated.Submit] does, and the `acr` check inside it is the only
// thing standing between a silently downgraded login and a satisfied step-up.
func (m *MFA) land(w http.ResponseWriter, r *http.Request) {
	id, ordinal, err := challengeRef(r)
	if err != nil {
		// A malformed path is refused the way an unknown decision is: the page a
		// person sees must not be a way to find out which decisions exist.
		m.renderLanding(w, http.StatusForbidden, landingRefused)
		return
	}

	redeemed, err := m.redeemer.Redeem(r.Context(), decision.Callback{
		DecisionID: id, Ordinal: ordinal, Params: singleValued(r.URL.Query()),
	})
	if err != nil {
		status, kind := redemptionRefusal(err)
		m.renderLanding(w, status, kind)
		return
	}

	caller, err := m.tokens.Verify(r.Context(), redeemed.Credential)
	if err != nil {
		// The verification reason is not narrated. identity.ReasonFor is what
		// puts it in the audit trail.
		m.renderLanding(w, http.StatusUnauthorized, landingRefused)
		return
	}

	if _, err := m.decisions.Submit(r.Context(), decision.Submission{
		Caller:     caller,
		DecisionID: id,
		Ordinal:    ordinal,
		Payload:    redeemed.Payload,
	}); err != nil {
		status, kind := landingError(err)
		m.renderLanding(w, status, kind)
		return
	}
	m.renderLanding(w, http.StatusOK, landingDone)
}

// singleValued flattens a query to the first value of each parameter.
//
// A duplicated `state` or `code` is a request with two answers, and the
// comparison downstream must be against one of them rather than against a
// joined string. Taking the first is what net/url's own Get does, so the
// callback and every other reader of this query agree on which one it is.
func singleValued(values url.Values) map[string]string {
	out := make(map[string]string, len(values))
	for k, v := range values {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
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

// ---------------------------------------------------------------------------
// what the subject sees
// ---------------------------------------------------------------------------

// landingKind is one of the outcomes the landing page renders.
//
// There are five and there is no sixth, because a page a person reads is a page
// whose text somebody has to have written. Each one answers a different question
// about what to do next, which is the only reason to have more than one.
type landingKind int

const (
	// landingDone: the challenge is satisfied and there is nothing left to do.
	landingDone landingKind = iota
	// landingRetry: the authentication was fine but arrived too late, or the
	// link was opened twice. Going back and starting again may work.
	landingRetry
	// landingWeak: the IdP authenticated the person, and the authentication is
	// not the one the policy asked for. Starting again with the same method will
	// not help; an operator has to look.
	landingWeak
	// landingRefused: everything a stranger might be probing with — an unknown
	// decision, a wrong `state`, a code that would not exchange, a challenge that
	// belongs to somebody else. One text for all of them.
	landingRefused
	// landingUnavailable: STAMP failed, not the subject.
	landingUnavailable
)

// landingCopy is the text for each outcome, in the order of [landingKind].
//
// It says what happened and what the reader can do, and never why in terms of
// the deployment's state. "Start again from the application that sent you" is
// actionable; "decision d-4f2 has no challenge 1" is a probe's answer.
var landingCopy = [...]struct{ Title, Detail string }{
	landingDone: {
		"Verification complete",
		"You can close this page and return to the application that sent you here.",
	},
	landingRetry: {
		"This verification is no longer open",
		"The request may have expired, or this link may already have been used. " +
			"Start again from the application that sent you here.",
	},
	landingWeak: {
		"That sign-in was not strong enough",
		"You signed in, but not in the way this request requires. " +
			"Contact whoever asked you to approve this — the identity provider may need to be configured for it.",
	},
	landingRefused: {
		"This link cannot be used",
		"It may have been altered, or it may not belong to a request that is still open. " +
			"Start again from the application that sent you here.",
	},
	landingUnavailable: {
		"Something went wrong on our side",
		"Nothing was recorded. Try the link again in a moment.",
	},
}

// landingTemplate is the whole page.
//
// It has no scripts, no styles, no images and no links, so it needs nothing the
// CSP below permits — which is why that CSP can be `default-src 'none'` rather
// than a list of exceptions. Redirecting to the console instead was the other
// option (Open Question 1) and it was rejected: the console is a separate
// surface a deployment may not bind at all, its origin is not this listener's to
// know, and the subject of a decision is frequently not a console user. A person
// who has just authenticated is owed one sentence, not a second application.
var landingTemplate = template.Must(template.New("mfa-landing").Parse(
	`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{.Title}}</title>
</head>
<body>
<main>
<h1>{{.Title}}</h1>
<p>{{.Detail}}</p>
</main>
</body>
</html>
`))

// landingCSP is the page's own policy. It permits nothing because the page
// needs nothing.
const landingCSP = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// renderLanding writes the page.
//
// `Referrer-Policy: no-referrer` is the load-bearing header. The URL this page
// is served at carries the authorization code and the `state` in its query, and
// a referrer would hand both to anything the page reached out to. The page
// reaches out to nothing, which makes the header belt to the CSP's braces —
// and the browser's address bar and history still hold that URL, which is
// precisely why `state` is a throwaway and the correlator never travels (KTD2).
func (m *MFA) renderLanding(w http.ResponseWriter, status int, kind landingKind) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", landingCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Stamp-Component", "mfa-callback")
	w.WriteHeader(status)
	_ = landingTemplate.Execute(w, landingCopy[kind])
}

// redemptionRefusal answers everything that goes wrong before the callback has
// proved itself, and answers all of it the same way.
//
// This is [Callbacks.external]'s uniform-403 rule, applied where it belongs. A
// `state` is 32 random bytes this deployment minted for one challenge, so until
// one checks out the party holding the link has proved nothing — and a page that
// said "no such decision" here, or answered 404 rather than 403, would be a way
// to learn which decision identifiers are real by reading it. Every refusal
// before that point is one page and one status.
//
// The single exception is an outage, for the reason the webhook listener makes
// the same one: a database that is down is not a refusal, and reporting it as
// one would have STAMP tell somebody their link was bad when it was fine.
func redemptionRefusal(err error) (int, landingKind) {
	if _, code, _ := mfaError(err); code == "internal_error" {
		return http.StatusInternalServerError, landingUnavailable
	}
	return http.StatusForbidden, landingRefused
}

// landingError folds a completion failure into a status and one of five pages.
//
// It runs only after a redemption succeeded, which means the party reading the
// page holds a `state` this deployment minted and an authorization code the IdP
// issued against it. They are the subject, not a stranger, and the uniform
// refusal above has already done its work — so from here the page may say which
// of a handful of things went wrong.
//
// It reuses [mfaError]'s table rather than restating it, so that the operator's
// seven distinctions and the subject's five stay in step by construction: adding
// a refusal to that table and forgetting this one gives the subject the refused
// page, which is the fail-closed answer.
//
// The folding is where the two audiences differ. `acr_not_allowed` and
// `acr_unsatisfied` are separate for an operator because one is the deployment's
// allowlist and the other is the policy — and identical for the subject, who
// signed in and was told it was not enough either way.
func landingError(err error) (int, landingKind) {
	status, code, _ := mfaError(err)
	switch code {
	case "acr_not_allowed", "acr_unsatisfied", "amr_mismatch":
		return status, landingWeak
	case "correlator_consumed", "stale_authentication", "expired", "not_collecting", "material_changed":
		return status, landingRetry
	case "internal_error":
		return status, landingUnavailable
	default:
		// correlator_mismatch, credential_mismatch, nonce_mismatch, not_found,
		// not_the_subject, invalid_submission, unsupported_challenge — and
		// anything a later revision adds.
		return status, landingRefused
	}
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
	case errors.Is(err, challenge.ErrRedemptionRefused):
		// One code for the whole family — a `state` that is not this challenge's,
		// an authorization code the IdP would not exchange, an IdP that declined.
		// They are one thing from outside: a redirect this deployment will not
		// act on. The wrapped reason is what reaches the operator's logs.
		return http.StatusForbidden, "redemption_refused", "this redirect was not accepted"
	case errors.Is(err, challenge.ErrNotRedeemable):
		return http.StatusNotFound, "not_redeemable", "this challenge is not completed by a redirect"
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
