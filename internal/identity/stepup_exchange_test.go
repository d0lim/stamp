package identity

// stepup_exchange_test.go covers the half of the step-up U2 added: the PKCE
// commitment that goes out with the authorization request, and the token call
// that spends it.
//
// The shapes asserted here are measured rather than assumed. U2 pointed the
// request this package builds at the demo bundle's Keycloak and got
// `error=invalid_request&error_description=Missing+parameter:+
// code_challenge_method` back as a redirect to the callback; the same request
// carrying the two PKCE parameters rendered the login form, the code that came
// back exchanged for an ID token against a public client with `client_id` and
// `code_verifier` in the body and no secret anywhere, and both a replayed code
// and a wrong verifier came back `{"error":"invalid_grant"}`.

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestPKCEChallengeIsTheS256DigestOfTheVerifier pins the derivation against
// RFC 7636's own definition rather than against this package's implementation.
func TestPKCEChallengeIsTheS256DigestOfTheVerifier(t *testing.T) {
	t.Parallel()
	verifier, challenge, err := NewPKCE()
	if err != nil {
		t.Fatalf("mint a pkce pair: %v", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); challenge != want {
		t.Fatalf("challenge = %q, want %q", challenge, want)
	}
	// 43 characters is RFC 7636's floor for a verifier, and base64url of 32
	// bytes is exactly that.
	if len(verifier) != 43 {
		t.Fatalf("verifier is %d characters, want the 43 that 32 bytes encodes to", len(verifier))
	}
	other, _, err := NewPKCE()
	if err != nil {
		t.Fatalf("mint a second pair: %v", err)
	}
	if other == verifier {
		t.Fatal("two verifiers are the same value")
	}
}

// TestAuthorizationURLCarriesThePKCEChallenge is the measured defect stated as
// a test: without these two parameters the demo realm refuses the request
// outright, because the client is registered with a challenge method and
// Keycloak reads that as a requirement.
func TestAuthorizationURLCarriesThePKCEChallenge(t *testing.T) {
	t.Parallel()
	verifier, challenge, err := NewPKCE()
	if err != nil {
		t.Fatalf("mint a pkce pair: %v", err)
	}
	raw, err := testStepUp(t, nil).AuthorizationURL(StepUpRequest{
		State:         "csrf-token",
		Nonce:         "nonce-value",
		CodeChallenge: challenge,
	})
	if err != nil {
		t.Fatalf("authorization url: %v", err)
	}
	q := parsedQuery(t, raw)
	if got := q.Get("code_challenge"); got != challenge {
		t.Fatalf("code_challenge = %q, want %q", got, challenge)
	}
	if got := q.Get("code_challenge_method"); got != PKCEMethod {
		t.Fatalf("code_challenge_method = %q, want %q", got, PKCEMethod)
	}
	if strings.Contains(raw, verifier) {
		t.Fatalf("the verifier travels in the authorization url: %s", raw)
	}
}

// TestAuthorizationURLOmitsPKCEWhenNoneWasMinted keeps the parameter honest: an
// empty `code_challenge` would be a commitment to nothing, and an IdP that
// requires PKCE must refuse the request rather than accept an empty one.
func TestAuthorizationURLOmitsPKCEWhenNoneWasMinted(t *testing.T) {
	t.Parallel()
	raw, err := testStepUp(t, nil).AuthorizationURL(StepUpRequest{State: "s", Nonce: "n"})
	if err != nil {
		t.Fatalf("authorization url: %v", err)
	}
	q := parsedQuery(t, raw)
	if _, present := q["code_challenge"]; present {
		t.Fatal("an empty code_challenge was sent")
	}
	if _, present := q["code_challenge_method"]; present {
		t.Fatal("a code_challenge_method was sent with no challenge")
	}
}

// TestConfigurationCannotSupplyThePKCEParameters: a deployment that could set
// `code_challenge` from configuration could set every challenge's commitment to
// one value it knows, which is PKCE removed by another name.
func TestConfigurationCannotSupplyThePKCEParameters(t *testing.T) {
	t.Parallel()
	for _, param := range []string{"code_challenge", "code_challenge_method"} {
		_, err := NewStepUp(StepUpConfig{
			AuthorizationEndpoint: "https://idp.example.test/auth",
			ClientID:              "stamp-stepup",
			RedirectURI:           "https://stamp.example.test/decisions/",
			ExtraParams:           map[string]string{param: "anything"},
		})
		if !errors.Is(err, ErrStepUpRequest) {
			t.Errorf("extra param %q was accepted: err = %v", param, err)
		}
	}
}

// exchangeOP is a token endpoint that records the call.
type exchangeOP struct {
	forms      []url.Values
	authHeader string
	status     int
	body       string
}

func (o *exchangeOP) start(t *testing.T) string {
	t.Helper()
	if o.status == 0 {
		o.status = http.StatusOK
	}
	if o.body == "" {
		o.body = `{"id_token":"header.payload.signature","token_type":"Bearer"}`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse token request: %v", err)
		}
		o.forms = append(o.forms, r.PostForm)
		o.authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(o.status)
		_, _ = w.Write([]byte(o.body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func exchangingStepUp(t *testing.T, endpoint, secret string) *StepUp {
	t.Helper()
	return testStepUp(t, func(cfg *StepUpConfig) {
		cfg.TokenEndpoint = endpoint
		cfg.ClientSecret = secret
		cfg.AllowInsecureTransport = true
	})
}

// TestExchangePresentsThePublicClientForm is the shape the measured OP accepted:
// the grant type, the code, the same redirect target, the verifier, and the
// client identifier in the body. A public client has no secret, so there is no
// Authorization header at all.
func TestExchangePresentsThePublicClientForm(t *testing.T) {
	t.Parallel()
	op := &exchangeOP{}
	s := exchangingStepUp(t, op.start(t), "")

	token, err := s.Exchange(t.Context(), CodeExchange{
		Code:         "the-code",
		CodeVerifier: "the-verifier",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if token != "header.payload.signature" {
		t.Fatalf("token = %q", token)
	}
	form := op.forms[0]
	for _, want := range []struct{ key, value string }{
		{"grant_type", "authorization_code"},
		{"code", "the-code"},
		{"code_verifier", "the-verifier"},
		{"redirect_uri", "https://stamp.example.test/decisions/dec-A/challenges/0/mfa"},
		{"client_id", "stamp-console"},
	} {
		if got := form.Get(want.key); got != want.value {
			t.Errorf("%s = %q, want %q", want.key, got, want.value)
		}
	}
	if op.authHeader != "" {
		t.Errorf("a public client sent an Authorization header: %q", op.authHeader)
	}
	if form.Has("client_secret") {
		t.Error("a secret was put in the form body")
	}
}

// TestExchangePutsAConfidentialClientsSecretInTheHeader follows the CIBA
// client's rule for the reason its comment gives: a secret in a form field ends
// up in access logs that a header does not.
func TestExchangePutsAConfidentialClientsSecretInTheHeader(t *testing.T) {
	t.Parallel()
	op := &exchangeOP{}
	s := exchangingStepUp(t, op.start(t), "s3cret")

	if _, err := s.Exchange(t.Context(), CodeExchange{Code: "c", CodeVerifier: "v"}); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if !strings.HasPrefix(op.authHeader, "Basic ") {
		t.Fatalf("Authorization = %q, want basic credentials", op.authHeader)
	}
	form := op.forms[0]
	if form.Has("client_secret") {
		t.Error("the secret was also put in the body")
	}
	// A confidential client names itself in the header and does not repeat it.
	if form.Has("client_id") {
		t.Error("client_id was repeated in the body of an authenticated call")
	}
}

// TestExchangeNarrowsTheRedirectTheSameWayTheRequestDid: the token call has to
// repeat the authorization request's `redirect_uri`, and a per-challenge one
// must be narrowed by the same rule — otherwise this would be a way to have the
// OP validate a code against a target the operator never configured.
func TestExchangeNarrowsTheRedirect(t *testing.T) {
	t.Parallel()
	op := &exchangeOP{}
	s := exchangingStepUp(t, op.start(t), "")

	if _, err := s.Exchange(t.Context(), CodeExchange{
		Code:        "c",
		RedirectURI: "https://stamp.example.test/decisions/dec-A/challenges/0/mfa",
	}); err != nil {
		t.Fatalf("exchange with a narrowed redirect: %v", err)
	}
	_, err := s.Exchange(t.Context(), CodeExchange{
		Code:        "c",
		RedirectURI: "https://attacker.example.test/decisions/dec-A/challenges/0/mfa",
	})
	if !errors.Is(err, ErrStepUpRequest) {
		t.Fatalf("err = %v, want the redirect refused", err)
	}
	if len(op.forms) != 1 {
		t.Fatalf("the token endpoint was called %d times, want 1", len(op.forms))
	}
}

// TestExchangeClassifiesTheOPsRefusal separates the one answer a caller acts on
// differently. `invalid_grant` is the whole family of "this code is not yours to
// redeem" — spent, expired, forged, minted for another client or another
// redirect target, or presented with the wrong verifier — and the measured OP
// returned exactly that for a replayed code and for a wrong verifier alike.
func TestExchangeClassifiesTheOPsRefusal(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		status int
		body   string
		want   error
	}{
		"replayed code": {
			http.StatusBadRequest, `{"error":"invalid_grant","error_description":"Code not valid"}`,
			ErrAuthorizationCodeRejected,
		},
		"wrong verifier": {
			http.StatusBadRequest, `{"error":"invalid_grant","error_description":"PKCE verification failed"}`,
			ErrAuthorizationCodeRejected,
		},
		"unknown client": {
			http.StatusUnauthorized, `{"error":"invalid_client"}`, ErrStepUpExchange,
		},
		"op is broken": {
			http.StatusInternalServerError, `{"error":"server_error"}`, ErrStepUpExchange,
		},
		"unreadable answer": {
			http.StatusOK, `not json`, ErrStepUpExchange,
		},
		"no id token": {
			http.StatusOK, `{"access_token":"a","token_type":"Bearer"}`, ErrStepUpExchange,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			op := &exchangeOP{status: tc.status, body: tc.body}
			s := exchangingStepUp(t, op.start(t), "")
			_, err := s.Exchange(t.Context(), CodeExchange{Code: "c", CodeVerifier: "v"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestExchangeRefusesWithoutWhatItNeeds: a builder with no token endpoint and a
// callback with no code are both configuration mistakes that must not become a
// silent no-op.
func TestExchangeRefusesWithoutWhatItNeeds(t *testing.T) {
	t.Parallel()
	if _, err := testStepUp(t, nil).Exchange(t.Context(), CodeExchange{Code: "c"}); !errors.Is(err, ErrStepUpExchange) {
		t.Fatalf("err = %v, want ErrStepUpExchange for a builder with no token endpoint", err)
	}
	op := &exchangeOP{}
	s := exchangingStepUp(t, op.start(t), "")
	if _, err := s.Exchange(t.Context(), CodeExchange{}); !errors.Is(err, ErrStepUpExchange) {
		t.Fatalf("err = %v, want ErrStepUpExchange for a callback with no code", err)
	}
	if len(op.forms) != 0 {
		t.Fatal("the token endpoint was called with no code")
	}
}

// TestNewStepUpRefusesAPlaintextTokenEndpoint: an authorization code redeemed
// over http is an authorization code redeemed by whoever is on the path, which
// is the reason the other two endpoints are checked.
func TestNewStepUpRefusesAPlaintextTokenEndpoint(t *testing.T) {
	t.Parallel()
	_, err := NewStepUp(StepUpConfig{
		AuthorizationEndpoint: "https://idp.example.test/auth",
		ClientID:              "stamp-stepup",
		RedirectURI:           "https://stamp.example.test/decisions/",
		TokenEndpoint:         "http://idp.example.test/token",
	})
	if !errors.Is(err, ErrStepUpRequest) {
		t.Fatalf("err = %v, want a plaintext token endpoint refused", err)
	}
}
