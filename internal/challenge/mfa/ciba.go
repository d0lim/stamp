package mfa

// ciba.go is the OIDC CIBA client. It is a contract and a client, verified
// against a mock OP, and it is not the demo's path.
//
// D26 explains why. U0 stood the IdP up and found a real CIBA grant surface —
// the discovery document advertises the grant type, the backchannel endpoint
// and both poll and ping delivery modes — behind an SPI whose only shipped
// implementation forwards the actual authentication to an external HTTP
// endpoint that the IdP does not include. A formally valid request reaches that
// point and returns `server_error`. Standing up the missing authentication
// device server would mean building an approval UI to make a demo convenient,
// so the demo redirects instead and this client stays verified against a mock.
//
// One constraint from U0 is enforced here rather than discovered at runtime:
// `binding_message` is capped at 50 characters, refuses spaces and accepts only
// basic plaintext. [ValidateBindingMessage] is checked before the request goes
// out, so a deployment that customizes the reference code learns at issue
// rather than when somebody is waiting for a prompt.
//
// # Where the verdict comes back
//
// Not here. This client only *starts* an authentication: it makes the
// backchannel request and returns the `auth_req_id` the OP minted. The verdict
// arrives on the callback surface, as `POST
// /decisions/{id}/challenges/{ordinal}/mfa` carrying the ID token, and is judged
// by [Delegated.Submit] — the same conjunction of checks a step-up redirect ends
// in, because there is one judgement of what satisfies a challenge and the
// transport does not get a second one.
//
// There used to be a `Poll` here that exchanged the `auth_req_id` at the token
// endpoint. Nothing ever called it. It was removed rather than wired, because
// wiring it is a feature and not a fix: a polling loop brings its own interval,
// its own backoff and its own `auth_req_id` lifetime, and D26 left this path
// verified against a mock OP precisely because no self-hostable IdP ships the
// authentication device server a real round trip needs. Aligning what the code
// promises with what the binary does was cheaper done by promising less.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrAuthorizationDeclined reports an OP that refused the backchannel request
// outright — `access_denied` or `expired_token` in its error document.
//
// It is the one outcome sentinel that survived the removal of the polling
// client. `authorization_pending` and `slow_down` had sentinels too, and both
// are answers only a token endpoint gives; with nothing polling one, they were
// names for states this binary cannot observe. Two exported errors that no code
// path can produce read as evidence of a polling loop, which is the confusion
// this package is trying not to leave behind.
var ErrAuthorizationDeclined = errors.New("mfa: the authentication request was declined or expired")

// DefaultCIBAPollInterval is the interval [CIBAAuthentication] reports when the
// OP names none.
//
// It describes the OP's answer and nothing this binary does — see the package
// doc: the verdict arrives on the callback POST, and no loop here spends this
// interval. It is kept because [CIBA.Authenticate] reports what the OP said
// faithfully, and an OP that named no interval said "five seconds" by RFC
// default rather than "zero".
const DefaultCIBAPollInterval = 5 * time.Second

// DefaultCIBATimeout bounds one backchannel or token call.
const DefaultCIBATimeout = 10 * time.Second

// CIBAConfig configures a [CIBA] client.
type CIBAConfig struct {
	// BackchannelEndpoint is the OP's backchannel authentication endpoint.
	// Required.
	BackchannelEndpoint string
	// TokenEndpoint is the OP's token endpoint. Optional, and this client never
	// calls it: the verdict comes back on the callback POST (see the package
	// doc). It is still accepted and still transport-checked, because a
	// deployment configures its OP's endpoints as a set and a plaintext one is
	// worth refusing at construction whether or not this client dials it.
	TokenEndpoint string
	// ClientID and ClientSecret authenticate the client. CIBA has no public
	// clients, so both are required.
	ClientID     string
	ClientSecret string
	// Scope is what to request. Empty selects "openid".
	Scope string
	// RequestedExpiry, when set, asks the OP to expire the request after it.
	RequestedExpiry time.Duration
	// HTTPClient makes the calls. Nil selects a client with
	// [DefaultCIBATimeout].
	HTTPClient *http.Client
	// AllowInsecureTransport permits plaintext http endpoints, for tests and
	// loopback development.
	AllowInsecureTransport bool
}

// CIBA is an OIDC CIBA client.
type CIBA struct {
	backchannel string
	clientID    string
	secret      string
	scope       string
	expiry      time.Duration
	http        *http.Client
}

var _ Initiator = (*CIBA)(nil)

// NewCIBA builds the client.
func NewCIBA(cfg CIBAConfig) (*CIBA, error) {
	if strings.TrimSpace(cfg.BackchannelEndpoint) == "" {
		return nil, errors.New("mfa: a ciba client needs a backchannel authentication endpoint")
	}
	if strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(cfg.ClientSecret) == "" {
		return nil, errors.New("mfa: a ciba client needs client credentials: the grant has no public clients")
	}
	for _, endpoint := range []string{cfg.BackchannelEndpoint, cfg.TokenEndpoint} {
		if endpoint == "" {
			continue
		}
		if err := checkCIBATransport(endpoint, cfg.AllowInsecureTransport); err != nil {
			return nil, err
		}
	}
	c := &CIBA{
		backchannel: cfg.BackchannelEndpoint,
		clientID:    cfg.ClientID,
		secret:      cfg.ClientSecret,
		scope:       cfg.Scope,
		expiry:      cfg.RequestedExpiry,
		http:        cfg.HTTPClient,
	}
	if c.scope == "" {
		c.scope = "openid"
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: DefaultCIBATimeout}
	}
	return c, nil
}

// CIBAAuthentication is what a successful backchannel request returned.
type CIBAAuthentication struct {
	AuthReqID string
	ExpiresIn time.Duration
	Interval  time.Duration
}

// Initiate implements [Initiator] by making a backchannel authentication
// request.
//
// The reference code travels as `binding_message` and the correlator does not
// travel at all: the correlator is what binds the completion to the decision,
// and a value the OP prints on a phone screen is not a place to put a secret.
func (c *CIBA) Initiate(ctx context.Context, req InitiateRequest) (InitiateResult, error) {
	auth, err := c.Authenticate(ctx, req)
	if err != nil {
		return InitiateResult{}, err
	}
	return InitiateResult{Method: MethodCIBA, AuthReqID: auth.AuthReqID}, nil
}

// Authenticate makes the backchannel authentication request.
func (c *CIBA) Authenticate(ctx context.Context, req InitiateRequest) (CIBAAuthentication, error) {
	if err := ValidateBindingMessage(req.Reference); err != nil {
		return CIBAAuthentication{}, err
	}
	form := url.Values{}
	form.Set("scope", c.scope)
	form.Set("binding_message", req.Reference)
	if req.SubjectID != "" {
		form.Set("login_hint", req.SubjectID)
	}
	if values := normalizeACR(req.ACRValues); len(values) > 0 {
		form.Set("acr_values", strings.Join(values, " "))
	}
	if c.expiry > 0 {
		form.Set("requested_expiry", fmt.Sprintf("%d", int64(c.expiry.Seconds())))
	}

	var out struct {
		AuthReqID string `json:"auth_req_id"`
		ExpiresIn int64  `json:"expires_in"`
		Interval  int64  `json:"interval"`
	}
	if err := c.post(ctx, c.backchannel, form, &out); err != nil {
		return CIBAAuthentication{}, err
	}
	if out.AuthReqID == "" {
		return CIBAAuthentication{}, errors.New("mfa: the op returned no auth_req_id")
	}
	interval := time.Duration(out.Interval) * time.Second
	if interval <= 0 {
		interval = DefaultCIBAPollInterval
	}
	return CIBAAuthentication{
		AuthReqID: out.AuthReqID,
		ExpiresIn: time.Duration(out.ExpiresIn) * time.Second,
		Interval:  interval,
	}, nil
}

// post makes one form-encoded call and decodes the answer, turning the OP's
// error document into this package's sentinels.
//
// One caller, [CIBA.Authenticate], since the polling client was removed. It
// stays a function of its own because the shape it holds — form body,
// credentials in a header, error document classified rather than pasted through
// — is the thing [identity.StepUp.Exchange] was written to match, and inlining
// it would leave that correspondence with nothing to point at.
func (c *CIBA) post(ctx context.Context, endpoint string, form url.Values, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("mfa: building a ciba request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// Client credentials go in the Authorization header rather than the body: a
	// secret in a form field ends up in access logs that a header does not. RFC
	// 6749 form-encodes each half before base64, which is why they are escaped.
	req.SetBasicAuth(url.QueryEscape(c.clientID), url.QueryEscape(c.secret))

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("mfa: ciba request to %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCIBAResponseBytes))
	if err != nil {
		return fmt.Errorf("mfa: reading the ciba response: %w", err)
	}
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		if err := json.Unmarshal(body, into); err != nil {
			return fmt.Errorf("mfa: decoding the ciba response: %w", err)
		}
		return nil
	}
	return cibaError(resp.StatusCode, body)
}

// maxCIBAResponseBytes bounds what an OP can make this client allocate.
const maxCIBAResponseBytes = 1 << 20

// cibaError classifies an OP error document.
//
// The `server_error` case is the one U0 actually met: a formally valid request
// that the IdP accepted and then could not route to any authentication device.
// It is mapped to [ErrInitiationUnsupported] so that a fallback chain treats it
// as "this OP cannot do CIBA" — which is exactly what it means — rather than as
// a transient failure to retry forever.
func cibaError(status int, body []byte) error {
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

	switch doc.Error {
	case "access_denied", "expired_token":
		return fmt.Errorf("%w: %s", ErrAuthorizationDeclined, detail)
	case "invalid_binding_message":
		return fmt.Errorf("%w: %s", ErrBindingMessage, detail)
	case "server_error", "unsupported_grant_type", "invalid_grant_type":
		return fmt.Errorf("%w: %s", ErrInitiationUnsupported, detail)
	}
	if status == http.StatusNotFound || status == http.StatusNotImplemented {
		return fmt.Errorf("%w: the op answered %d", ErrInitiationUnsupported, status)
	}
	return fmt.Errorf("mfa: the op refused the request with %d: %s", status, detail)
}

func checkCIBATransport(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("mfa: %q is not a url: %w", raw, err)
	}
	if u.Scheme == "https" || allowInsecure {
		return nil
	}
	return fmt.Errorf("mfa: %q must use https, or the deployment must allow insecure transport", raw)
}
