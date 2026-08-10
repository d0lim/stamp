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

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrStepUpRequest reports an authorization request that cannot be built.
var ErrStepUpRequest = errors.New("identity: step-up authorization request")

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
	// AllowInsecureTransport permits a plaintext http endpoint or redirect
	// target. Without it they are refused: an authorization code delivered
	// over http is an authorization code delivered to whoever is on the path.
	AllowInsecureTransport bool
}

// StepUp builds authorization requests for one deployment.
type StepUp struct {
	endpoint     *url.URL
	clientID     string
	redirectURI  string
	scope        string
	responseType string
	extra        map[string]string
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

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = DefaultStepUpScopes
	}
	responseType := cfg.ResponseType
	if responseType == "" {
		responseType = "code"
	}
	s := &StepUp{
		endpoint:     endpoint,
		clientID:     cfg.ClientID,
		redirectURI:  cfg.RedirectURI,
		scope:        strings.Join(scopes, " "),
		responseType: responseType,
		extra:        make(map[string]string, len(cfg.ExtraParams)),
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
	"response_type": true,
	"client_id":     true,
	"redirect_uri":  true,
	"scope":         true,
	"state":         true,
	"nonce":         true,
	"acr_values":    true,
	"max_age":       true,
	"claims":        true,
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

	u := *s.endpoint
	q := u.Query()
	for k, v := range s.extra {
		q.Set(k, v)
	}
	q.Set("response_type", s.responseType)
	q.Set("client_id", s.clientID)
	q.Set("redirect_uri", s.redirectURI)
	q.Set("scope", s.scope)
	q.Set("state", req.State)
	q.Set("nonce", req.Nonce)
	// A step-up that an existing session could answer cannot produce an
	// auth_time later than the challenge it was opened for.
	q.Set("max_age", "0")
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

func trimmedNonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
