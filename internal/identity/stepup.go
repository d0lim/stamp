package identity

// stepup.go builds the request half of an RFC 9470 step-up.
//
// The rest of this package is the answer half: [Verifier.Verify] decides what a
// token that came back is worth. Both halves live here because they are one
// relying-party boundary — the endpoint, the client identifier and the redirect
// target are operator configuration in exactly the way the issuer set and the
// audience are, and a policy author must not be able to move any of them (D21).
//
// Two things about the request are worth stating out loud, because U0 found
// that neither does what it looks like it does.
//
// `acr_values` is a request and not a constraint. An IdP that cannot satisfy it
// returns a weaker class rather than an error, and so does an IdP asked for a
// class it has never heard of. The OIDC essential-claim form is sent alongside
// it because it is the more precise way to state the requirement and costs one
// query parameter — but U0 watched that be silently downgraded too. Neither
// form makes the response trustworthy; only checking the response does.
//
// `max_age=0` is not a preference. A delegated MFA challenge is satisfied by an
// `auth_time` later than the instant the challenge opened, so a request that
// let the IdP answer from an existing session would be a request whose answer
// can never satisfy the challenge it was sent for.
//
// # PKCE is not optional here
//
// U2 pointed the request this file builds at the demo realm and the IdP refused
// it outright — `error=invalid_request`, `Missing parameter:
// code_challenge_method` — because the client is registered with
// `pkce.code.challenge.method: S256`, which Keycloak reads as a requirement and
// not as a preference. A step-up client is a public client: it holds no secret,
// so the proof that the party redeeming the code is the party that asked for it
// is the verifier and nothing else. [NewPKCE] mints the pair and
// [StepUp.Exchange] spends it.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrStepUpRequest reports an authorization request that cannot be built.
var ErrStepUpRequest = errors.New("identity: step-up authorization request")

// Errors the token exchange adds.
var (
	// ErrStepUpExchange reports an authorization code that could not be
	// redeemed: the endpoint is unreachable, the response is unreadable, or the
	// OP refused for a reason that is not the code itself.
	ErrStepUpExchange = errors.New("identity: step-up code exchange")

	// ErrAuthorizationCodeRejected reports an `invalid_grant`: a code that was
	// never issued, was issued for another client or redirect target, has
	// already been spent, has expired, or came with the wrong verifier. The OP
	// answers all of those the same way and so does this — the distinction is
	// the OP's to keep, and a relying party that guessed at it would be guessing.
	ErrAuthorizationCodeRejected = errors.New("identity: the authorization code was not accepted")
)

// DefaultStepUpScopes is what a step-up asks for when the deployment says
// nothing: the ID token and nothing else. A step-up is an authentication, not
// an authorization grant, so it has no business collecting scopes.
var DefaultStepUpScopes = []string{"openid"}

// StepUpConfig pins where a step-up sends the subject.
//
// Every field is operator configuration. In particular RedirectURI is the
// deployment's own callback surface, so a completion can only ever come back to
// STAMP — an IdP asked to redirect somewhere a policy named would be an open
// redirect with a signed token in it.
type StepUpConfig struct {
	// AuthorizationEndpoint is the IdP's authorization endpoint. Required.
	AuthorizationEndpoint string
	// ClientID is the client the request is made as. Required.
	ClientID string
	// RedirectURI is where the IdP returns the subject. Required.
	RedirectURI string
	// Scopes is what to ask for. Empty selects [DefaultStepUpScopes].
	Scopes []string
	// ResponseType is the OAuth response type. Empty selects "code".
	ResponseType string
	// ExtraParams are additional query parameters every request carries, for a
	// deployment whose IdP needs one. They may not overwrite a parameter this
	// builder sets: a request that could have its `state` replaced from
	// configuration would have its binding replaced from configuration.
	ExtraParams map[string]string
	// TokenEndpoint is where an authorization code is redeemed. It is optional
	// only in the sense that a builder without one can still render URLs; a
	// deployment that sends anybody to an IdP and cannot redeem what comes back
	// has a challenge nobody can complete.
	TokenEndpoint string
	// ClientSecret authenticates the client at the token endpoint. Empty is the
	// normal case and not a degraded one: a step-up client is public, and PKCE
	// is what proves the redeemer is the requester. When a deployment does
	// register a confidential client, R42 says the value arrives from a file —
	// see the runtime's `STAMP_MFA_CLIENT_SECRET_FILE`.
	ClientSecret string
	// HTTPClient makes the token call. Nil selects a client with
	// [DefaultStepUpTimeout].
	HTTPClient *http.Client
	// AllowInsecureTransport permits a plaintext http endpoint or redirect
	// target. Without it they are refused: an authorization code delivered
	// over http is an authorization code delivered to whoever is on the path.
	AllowInsecureTransport bool
}

// DefaultStepUpTimeout bounds one token call.
const DefaultStepUpTimeout = 10 * time.Second

// maxTokenResponseBytes bounds what an OP can make this client allocate.
const maxTokenResponseBytes = 1 << 20

// StepUp builds authorization requests for one deployment, and redeems the
// codes they come back with.
//
// Both halves live on one type because they are one client: the token call has
// to repeat the `redirect_uri` and the `client_id` the authorization request
// used, and a second object holding a second copy of them is a second thing that
// can drift out of step with the first.
type StepUp struct {
	endpoint     *url.URL
	clientID     string
	redirectURI  string
	redirectBase *url.URL
	scope        string
	responseType string
	extra        map[string]string

	tokenEndpoint string
	clientSecret  string
	http          *http.Client
}

// NewStepUp validates a step-up configuration and returns a builder for it.
func NewStepUp(cfg StepUpConfig) (*StepUp, error) {
	if strings.TrimSpace(cfg.AuthorizationEndpoint) == "" {
		return nil, fmt.Errorf("%w: no authorization endpoint is configured", ErrStepUpRequest)
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, fmt.Errorf("%w: no client id is configured", ErrStepUpRequest)
	}
	if strings.TrimSpace(cfg.RedirectURI) == "" {
		return nil, fmt.Errorf("%w: no redirect uri is configured", ErrStepUpRequest)
	}
	endpoint, err := url.Parse(cfg.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: %q is not a url: %w", ErrStepUpRequest, cfg.AuthorizationEndpoint, err)
	}
	if err := checkTransport(cfg.AuthorizationEndpoint, cfg.AllowInsecureTransport); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStepUpRequest, err)
	}
	if err := checkTransport(cfg.RedirectURI, cfg.AllowInsecureTransport); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStepUpRequest, err)
	}
	if strings.TrimSpace(cfg.TokenEndpoint) != "" {
		if err := checkTransport(cfg.TokenEndpoint, cfg.AllowInsecureTransport); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrStepUpRequest, err)
		}
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = DefaultStepUpScopes
	}
	responseType := cfg.ResponseType
	if responseType == "" {
		responseType = "code"
	}
	redirectBase, err := url.Parse(cfg.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("%w: %q is not a url: %w", ErrStepUpRequest, cfg.RedirectURI, err)
	}
	s := &StepUp{
		endpoint:      endpoint,
		clientID:      cfg.ClientID,
		redirectURI:   cfg.RedirectURI,
		redirectBase:  redirectBase,
		scope:         strings.Join(scopes, " "),
		responseType:  responseType,
		extra:         make(map[string]string, len(cfg.ExtraParams)),
		tokenEndpoint: strings.TrimSpace(cfg.TokenEndpoint),
		clientSecret:  cfg.ClientSecret,
		http:          cfg.HTTPClient,
	}
	if s.http == nil {
		s.http = &http.Client{Timeout: DefaultStepUpTimeout}
	}
	for k, v := range cfg.ExtraParams {
		if reservedStepUpParams[k] {
			return nil, fmt.Errorf("%w: extra parameter %q would overwrite a parameter the request owns",
				ErrStepUpRequest, k)
		}
		s.extra[k] = v
	}
	return s, nil
}

// reservedStepUpParams are the parameters configuration may not supply.
var reservedStepUpParams = map[string]bool{
	"response_type":         true,
	"client_id":             true,
	"redirect_uri":          true,
	"scope":                 true,
	"state":                 true,
	"nonce":                 true,
	"acr_values":            true,
	"max_age":               true,
	"claims":                true,
	"code_challenge":        true,
	"code_challenge_method": true,
}

// StepUpRequest is one authorization request.
type StepUpRequest struct {
	// State is the value the IdP echoes back, and the value a challenge is
	// bound to. Required: a step-up with no state is a completion that could
	// belong to any decision.
	State string
	// Nonce is bound into the ID token by an IdP that supports it. Required
	// for the same reason.
	Nonce string
	// ACRValues is the authentication context classes to ask for, strongest
	// first. Empty asks for none, which is legitimate when the operator
	// allowlist is the whole requirement.
	ACRValues []string
	// LoginHint tells the IdP which account to authenticate, so a step-up does
	// not silently satisfy itself with whoever is already signed in.
	LoginHint string
	// RedirectURI narrows the configured redirect target for this one request,
	// so a completion can land on the challenge it belongs to rather than on a
	// single endpoint that would then have to look the challenge up.
	//
	// It is a narrowing and not a replacement: the value must sit under the
	// configured redirect URI, same scheme, same host, same path prefix. That
	// is what keeps this from being a way to have the IdP hand an authorization
	// code to somewhere else — the operator still owns the origin, and the IdP
	// still owns whether it will redirect there at all.
	RedirectURI string
	// CodeChallenge is the S256 challenge derived from the verifier that will
	// redeem the code. Required for any IdP that registers the client with a
	// challenge method — U2 measured the demo realm refusing the request
	// outright without it — and harmless for one that does not.
	CodeChallenge string
}

// AuthorizationURL renders the request as a URL to send the subject to.
//
// Any query already present on the configured endpoint is preserved; the
// parameters this builder owns are set rather than appended, so a mistake in
// configuration cannot end up as a second `state` the IdP picks between.
func (s *StepUp) AuthorizationURL(req StepUpRequest) (string, error) {
	if strings.TrimSpace(req.State) == "" {
		return "", fmt.Errorf("%w: a step-up must carry a state", ErrStepUpRequest)
	}
	if strings.TrimSpace(req.Nonce) == "" {
		return "", fmt.Errorf("%w: a step-up must carry a nonce", ErrStepUpRequest)
	}
	redirect, err := s.redirectFor(req.RedirectURI)
	if err != nil {
		return "", err
	}

	u := *s.endpoint
	q := u.Query()
	for k, v := range s.extra {
		q.Set(k, v)
	}
	q.Set("response_type", s.responseType)
	q.Set("client_id", s.clientID)
	q.Set("redirect_uri", redirect)
	q.Set("scope", s.scope)
	q.Set("state", req.State)
	q.Set("nonce", req.Nonce)
	// A step-up that an existing session could answer cannot produce an
	// auth_time later than the challenge it was opened for.
	q.Set("max_age", "0")
	if req.CodeChallenge != "" {
		q.Set("code_challenge", req.CodeChallenge)
		q.Set("code_challenge_method", PKCEMethod)
	}
	if req.LoginHint != "" {
		q.Set("login_hint", req.LoginHint)
	}
	if values := trimmedNonEmpty(req.ACRValues); len(values) > 0 {
		q.Set("acr_values", strings.Join(values, " "))
		claims, err := essentialACRClaims(values)
		if err != nil {
			return "", err
		}
		q.Set("claims", claims)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// redirectFor validates a per-request redirect target against the configured
// one and returns the value to send.
//
// Everything about it is a refusal except the empty case. A different host, a
// different scheme, a path outside the configured one, credentials in the
// authority, a value that does not parse — all of them are the same mistake
// with different spellings, and the consequence of getting any of them wrong is
// an IdP handing an authorization code to somebody else.
func (s *StepUp) redirectFor(requested string) (string, error) {
	if strings.TrimSpace(requested) == "" {
		return s.redirectURI, nil
	}
	u, err := url.Parse(requested)
	if err != nil {
		return "", fmt.Errorf("%w: redirect %q is not a url: %w", ErrStepUpRequest, requested, err)
	}
	if u.Scheme != s.redirectBase.Scheme || u.Host != s.redirectBase.Host || u.User != nil {
		return "", fmt.Errorf("%w: redirect %q is not under the configured target %q",
			ErrStepUpRequest, requested, s.redirectURI)
	}
	base := strings.TrimSuffix(s.redirectBase.EscapedPath(), "/")
	path := u.EscapedPath()
	if path != base && !strings.HasPrefix(path, base+"/") {
		return "", fmt.Errorf("%w: redirect %q is not under the configured target %q",
			ErrStepUpRequest, requested, s.redirectURI)
	}
	return requested, nil
}

// essentialACRClaims renders the OIDC essential-claim form of the same request.
//
// It is sent in addition to `acr_values` rather than instead of it: the two
// forms are understood by different IdPs, and U0 watched both be ignored, so
// sending both maximizes the chance the IdP does the right thing while changing
// nothing about the fact that the answer still has to be checked.
func essentialACRClaims(values []string) (string, error) {
	doc := map[string]any{
		"id_token": map[string]any{
			"acr": map[string]any{"essential": true, "values": values},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("%w: encoding essential acr claims: %w", ErrStepUpRequest, err)
	}
	return string(raw), nil
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

// PKCEMethod is the only challenge method this client offers.
//
// `plain` is not offered. It is a challenge equal to its own verifier, which
// buys nothing against anybody who can read the authorization request — and the
// authorization request is a URL that travels through a browser.
const PKCEMethod = "S256"

// pkceVerifierBytes is the entropy in a verifier. RFC 7636 permits 43 to 128
// characters; 32 bytes base64url-encodes to 43, which is the floor, and the
// verifier is a secret whose only job is to be unguessable for the seconds
// between an authorization request and its redemption.
const pkceVerifierBytes = 32

// NewPKCE mints a verifier and the S256 challenge that commits to it.
//
// The pair is split across a browser round trip: the challenge goes out in the
// authorization URL, the verifier stays on the challenge row (KTD3), and the
// token call presents the verifier to prove the party redeeming the code is the
// party that asked for it. A public client has nothing else to prove it with.
func NewPKCE() (verifier, challenge string, err error) {
	buf := make([]byte, pkceVerifierBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("%w: generating a pkce verifier: %w", ErrStepUpRequest, err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	return verifier, PKCEChallenge(verifier), nil
}

// PKCEChallenge derives the S256 challenge for a verifier.
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// token exchange
// ---------------------------------------------------------------------------

// CodeExchange is one authorization_code redemption.
type CodeExchange struct {
	// Code is the authorization code the IdP redirected back with.
	Code string
	// CodeVerifier is the PKCE verifier the request committed to.
	CodeVerifier string
	// RedirectURI must be byte-identical to the one the authorization request
	// carried. The OP checks it, and that check is load-bearing here: it is what
	// makes a code minted for one challenge unredeemable at another challenge's
	// path, because the path is the redirect target.
	RedirectURI string
}

// Exchange redeems an authorization code for the ID token it produced.
//
// It returns the raw token and judges nothing about it. Deciding what an
// authentication is worth is [Verifier.Verify] and then the challenge handler's
// conjunction of checks; a second opinion formed here would be a second place
// the trust boundary could be got wrong.
//
// The shape was taken from the CIBA client's form-POST helper — form-encoded
// body, credentials in the Authorization header rather than the body when there
// are any, and the OP's error document classified rather than pasted through.
// That client used to redeem an `auth_req_id` at a token endpoint too; it was
// deleted as dead code, because a CIBA verdict comes back on the callback POST
// and nothing ever polled. So this is now the repository's *only* token-endpoint
// client, and the shape has no second implementation to stay in step with.
func (s *StepUp) Exchange(ctx context.Context, req CodeExchange) (string, error) {
	if s.tokenEndpoint == "" {
		return "", fmt.Errorf("%w: no token endpoint is configured", ErrStepUpExchange)
	}
	if strings.TrimSpace(req.Code) == "" {
		return "", fmt.Errorf("%w: no authorization code to redeem", ErrStepUpExchange)
	}
	redirect, err := s.redirectFor(req.RedirectURI)
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", req.Code)
	form.Set("redirect_uri", redirect)
	// A public client names itself in the body; a confidential one names itself
	// in the Authorization header below and does not repeat it here.
	if s.clientSecret == "" {
		form.Set("client_id", s.clientID)
	}
	if req.CodeVerifier != "" {
		form.Set("code_verifier", req.CodeVerifier)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: building the token request: %w", ErrStepUpExchange, err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")
	if s.clientSecret != "" {
		// RFC 6749 form-encodes each half before base64.
		httpReq.SetBasicAuth(url.QueryEscape(s.clientID), url.QueryEscape(s.clientSecret))
	}

	resp, err := s.http.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrStepUpExchange, s.tokenEndpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if err != nil {
		return "", fmt.Errorf("%w: reading the token response: %w", ErrStepUpExchange, err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", tokenEndpointError(resp.StatusCode, body)
	}

	var out struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("%w: decoding the token response: %w", ErrStepUpExchange, err)
	}
	if out.IDToken == "" {
		// An OP that answered with an access token and no ID token answered a
		// different question than the one a step-up asked.
		return "", fmt.Errorf("%w: the token response carries no id_token", ErrStepUpExchange)
	}
	return out.IDToken, nil
}

// tokenEndpointError classifies an OP error document.
//
// `invalid_grant` is the one branch a caller acts on differently: it is the
// answer to a code that is spent, expired, forged, minted for another client or
// redirect target, or presented with the wrong verifier — the whole family of
// "this code is not yours to redeem". Everything else is the deployment's
// problem rather than the subject's, and is reported as one.
func tokenEndpointError(status int, body []byte) error {
	var doc struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &doc)
	detail := doc.Error
	if doc.Description != "" {
		detail = doc.Error + ": " + doc.Description
	}
	if detail == "" {
		detail = strings.TrimSpace(string(body))
	}
	if doc.Error == "invalid_grant" {
		return fmt.Errorf("%w: %s", ErrAuthorizationCodeRejected, detail)
	}
	return fmt.Errorf("%w: the op answered %d: %s", ErrStepUpExchange, status, detail)
}

func trimmedNonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
