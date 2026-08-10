package identity

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
)

func testStepUp(t *testing.T, mutate func(*StepUpConfig)) *StepUp {
	t.Helper()
	cfg := StepUpConfig{
		AuthorizationEndpoint:  "https://idp.example.test/realms/stamp/protocol/openid-connect/auth",
		ClientID:               "stamp-console",
		RedirectURI:            "https://stamp.example.test/decisions/dec-A/challenges/0/mfa",
		AllowInsecureTransport: false,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := NewStepUp(cfg)
	if err != nil {
		t.Fatalf("build step-up: %v", err)
	}
	return s
}

func parsedQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse authorization url: %v", err)
	}
	return u.Query()
}

// TestAuthorizationURLCarriesTheACRRequest is the plan's step-up scenario. Both
// forms of the request go out, and U0's finding is why the essential-claim form
// is not sent instead of `acr_values`: the IdP silently downgraded both, so
// sending both costs one parameter and buys whichever form this IdP reads.
func TestAuthorizationURLCarriesTheACRRequest(t *testing.T) {
	t.Parallel()
	raw, err := testStepUp(t, nil).AuthorizationURL(StepUpRequest{
		State:     "correlator-value",
		Nonce:     "nonce-value",
		ACRValues: []string{"gold", "silver"},
		LoginHint: "alice",
	})
	if err != nil {
		t.Fatalf("authorization url: %v", err)
	}
	q := parsedQuery(t, raw)

	if got := q.Get("acr_values"); got != "gold silver" {
		t.Fatalf("acr_values = %q, want %q", got, "gold silver")
	}
	var claims struct {
		IDToken struct {
			ACR struct {
				Essential bool     `json:"essential"`
				Values    []string `json:"values"`
			} `json:"acr"`
		} `json:"id_token"`
	}
	if err := json.Unmarshal([]byte(q.Get("claims")), &claims); err != nil {
		t.Fatalf("decode claims parameter: %v", err)
	}
	if !claims.IDToken.ACR.Essential {
		t.Fatal("the acr claim was not requested as essential")
	}
	if strings.Join(claims.IDToken.ACR.Values, " ") != "gold silver" {
		t.Fatalf("essential acr values = %v", claims.IDToken.ACR.Values)
	}

	if got := q.Get("state"); got != "correlator-value" {
		t.Fatalf("state = %q", got)
	}
	if got := q.Get("nonce"); got != "nonce-value" {
		t.Fatalf("nonce = %q", got)
	}
	if got := q.Get("login_hint"); got != "alice" {
		t.Fatalf("login_hint = %q", got)
	}
	if got := q.Get("scope"); got != "openid" {
		t.Fatalf("scope = %q, want openid: a step-up is an authentication, not a grant", got)
	}
}

// TestAuthorizationURLAlwaysForcesReauthentication states the one thing about
// this request that is not configurable. A delegated MFA challenge is satisfied
// by an auth_time later than its own issuance, so a request an existing session
// could answer is a request whose answer can never satisfy it.
func TestAuthorizationURLAlwaysForcesReauthentication(t *testing.T) {
	t.Parallel()
	raw, err := testStepUp(t, nil).AuthorizationURL(StepUpRequest{State: "s", Nonce: "n"})
	if err != nil {
		t.Fatalf("authorization url: %v", err)
	}
	if got := parsedQuery(t, raw).Get("max_age"); got != "0" {
		t.Fatalf("max_age = %q, want 0", got)
	}
}

func TestAuthorizationURLPreservesTheEndpointsOwnQuery(t *testing.T) {
	t.Parallel()
	s := testStepUp(t, func(c *StepUpConfig) {
		c.AuthorizationEndpoint += "?kc_idp_hint=corp"
	})
	raw, err := s.AuthorizationURL(StepUpRequest{State: "s", Nonce: "n"})
	if err != nil {
		t.Fatalf("authorization url: %v", err)
	}
	q := parsedQuery(t, raw)
	if got := q.Get("kc_idp_hint"); got != "corp" {
		t.Fatalf("kc_idp_hint = %q, want corp", got)
	}
	// Set rather than appended: a second `state` would let the IdP choose which
	// binding the completion carries.
	if len(q["state"]) != 1 {
		t.Fatalf("state appears %d times, want 1", len(q["state"]))
	}
}

func TestAuthorizationURLRequiresStateAndNonce(t *testing.T) {
	t.Parallel()
	s := testStepUp(t, nil)
	for name, req := range map[string]StepUpRequest{
		"no state": {Nonce: "n"},
		"no nonce": {State: "s"},
		"blank":    {State: "  ", Nonce: "  "},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := s.AuthorizationURL(req); !errors.Is(err, ErrStepUpRequest) {
				t.Fatalf("err = %v, want ErrStepUpRequest", err)
			}
		})
	}
}

// TestNewStepUpRefusesPlaintextTransport keeps an authorization code from being
// delivered to whoever is on the path.
func TestNewStepUpRefusesPlaintextTransport(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*StepUpConfig){
		"endpoint": func(c *StepUpConfig) { c.AuthorizationEndpoint = "http://idp.example.test/auth" },
		"redirect": func(c *StepUpConfig) { c.RedirectURI = "http://stamp.example.test/mfa" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := StepUpConfig{
				AuthorizationEndpoint: "https://idp.example.test/auth",
				ClientID:              "stamp-console",
				RedirectURI:           "https://stamp.example.test/mfa",
			}
			mutate(&cfg)
			if _, err := NewStepUp(cfg); !errors.Is(err, ErrStepUpRequest) {
				t.Fatalf("err = %v, want ErrStepUpRequest", err)
			}
			cfg.AllowInsecureTransport = true
			if _, err := NewStepUp(cfg); err != nil {
				t.Fatalf("an explicit opt-in was still refused: %v", err)
			}
		})
	}
}

// TestNewStepUpRefusesExtraParamsThatOverwriteTheRequest is the reason
// ExtraParams is a closed door rather than a merge: a deployment that could set
// `state` from configuration could replace the binding from configuration.
func TestNewStepUpRefusesExtraParamsThatOverwriteTheRequest(t *testing.T) {
	t.Parallel()
	for _, param := range []string{"state", "nonce", "acr_values", "redirect_uri", "max_age", "claims"} {
		t.Run(param, func(t *testing.T) {
			t.Parallel()
			_, err := NewStepUp(StepUpConfig{
				AuthorizationEndpoint: "https://idp.example.test/auth",
				ClientID:              "stamp-console",
				RedirectURI:           "https://stamp.example.test/mfa",
				ExtraParams:           map[string]string{param: "anything"},
			})
			if !errors.Is(err, ErrStepUpRequest) {
				t.Fatalf("err = %v, want ErrStepUpRequest", err)
			}
		})
	}
}

func TestNewStepUpRequiresItsPins(t *testing.T) {
	t.Parallel()
	for name, cfg := range map[string]StepUpConfig{
		"no endpoint": {ClientID: "c", RedirectURI: "https://stamp.example.test/mfa"},
		"no client":   {AuthorizationEndpoint: "https://idp.example.test/auth", RedirectURI: "https://s.example.test/m"},
		"no redirect": {AuthorizationEndpoint: "https://idp.example.test/auth", ClientID: "c"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewStepUp(cfg); !errors.Is(err, ErrStepUpRequest) {
				t.Fatalf("err = %v, want ErrStepUpRequest", err)
			}
		})
	}
}

// TestNewSubjectCarriesClaimsWithoutVerifying documents the narrow constructor
// this unit added, including the part that matters: it verifies nothing, and the
// only reason it exists is that Claims reads an unexported field.
func TestNewSubjectCarriesClaimsWithoutVerifying(t *testing.T) {
	t.Parallel()
	s := NewSubject(Subject{
		Kind:   SubjectUser,
		Issuer: "https://idp.example.test",
		ID:     "alice",
		AMR:    []string{"otp"},
	}, []byte(`{"nonce":"n","acr":"gold"}`))

	var claims struct {
		Nonce string `json:"nonce"`
		ACR   string `json:"acr"`
	}
	if err := s.Claims(&claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if claims.Nonce != "n" || claims.ACR != "gold" {
		t.Fatalf("claims = %+v", claims)
	}

	// A subject built with no claims behaves exactly like one from a client
	// certificate: Claims reports that there are none rather than returning an
	// empty set that a caller would read as "the IdP said nothing".
	bare := NewSubject(Subject{Kind: SubjectUser, ID: "bob"}, nil)
	if err := bare.Claims(&claims); err == nil {
		t.Fatal("a subject with no claims answered Claims")
	}
}

// TestAuthorizationURLNarrowsTheRedirectTarget is what lets a completion land
// on the challenge it answers instead of on one endpoint that would then have
// to look the challenge up. The narrowing is the whole safety property: the
// operator still owns the origin.
func TestAuthorizationURLNarrowsTheRedirectTarget(t *testing.T) {
	t.Parallel()
	s := testStepUp(t, func(c *StepUpConfig) {
		c.RedirectURI = "https://stamp.example.test/decisions"
	})
	raw, err := s.AuthorizationURL(StepUpRequest{
		State:       "s",
		Nonce:       "n",
		RedirectURI: "https://stamp.example.test/decisions/dec-A/challenges/0/mfa",
	})
	if err != nil {
		t.Fatalf("authorization url: %v", err)
	}
	if got := parsedQuery(t, raw).Get("redirect_uri"); got != "https://stamp.example.test/decisions/dec-A/challenges/0/mfa" {
		t.Fatalf("redirect_uri = %q", got)
	}

	// A request that names none falls back to the configured target.
	fallback, err := s.AuthorizationURL(StepUpRequest{State: "s", Nonce: "n"})
	if err != nil {
		t.Fatalf("authorization url: %v", err)
	}
	if got := parsedQuery(t, fallback).Get("redirect_uri"); got != "https://stamp.example.test/decisions" {
		t.Fatalf("redirect_uri = %q, want the configured target", got)
	}
}

// TestAuthorizationURLRefusesARedirectOutsideTheConfiguredTarget is the reason
// the override is a narrowing. Every row here is the same mistake spelled
// differently, and the consequence of any of them is an IdP handing an
// authorization code to somebody else.
func TestAuthorizationURLRefusesARedirectOutsideTheConfiguredTarget(t *testing.T) {
	t.Parallel()
	s := testStepUp(t, func(c *StepUpConfig) {
		c.RedirectURI = "https://stamp.example.test/decisions"
	})
	for name, redirect := range map[string]string{
		"another host":   "https://evil.example.test/decisions/dec-A",
		"another scheme": "http://stamp.example.test/decisions/dec-A",
		"a sibling path": "https://stamp.example.test/decisionsX/dec-A",
		"a parent path":  "https://stamp.example.test/",
		"userinfo":       "https://user@stamp.example.test/decisions/dec-A",
		"not a url":      "://nonsense",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := s.AuthorizationURL(StepUpRequest{State: "s", Nonce: "n", RedirectURI: redirect})
			if !errors.Is(err, ErrStepUpRequest) {
				t.Fatalf("redirect %q was accepted: err = %v", redirect, err)
			}
		})
	}
}
