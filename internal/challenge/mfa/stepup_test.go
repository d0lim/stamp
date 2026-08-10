package mfa

import (
	"errors"
	"net/url"
	"testing"

	"github.com/d0lim/stamp/internal/identity"
)

func testStepUpInitiator(t *testing.T) *StepUp {
	t.Helper()
	requests, err := identity.NewStepUp(identity.StepUpConfig{
		AuthorizationEndpoint: "https://idp.example.test/realms/stamp/protocol/openid-connect/auth",
		ClientID:              "stamp-console",
		RedirectURI:           "https://stamp.example.test/decisions/dec-A/challenges/0/mfa",
	})
	if err != nil {
		t.Fatalf("build step-up requests: %v", err)
	}
	init, err := NewStepUp(requests)
	if err != nil {
		t.Fatalf("build step-up initiator: %v", err)
	}
	return init
}

// TestStepUpCarriesTheCorrelatorAsStateAndTheACRValues is the demo path's half
// of the plan's initiation scenario (D26): the correlator rides in `state`,
// where the IdP hands it straight back to the callback, and the classes ride in
// `acr_values`, where U0 proved the IdP may ignore them.
func TestStepUpCarriesTheCorrelatorAsStateAndTheACRValues(t *testing.T) {
	t.Parallel()
	out, err := testStepUpInitiator(t).Initiate(t.Context(), testInitiateRequest("correlator-value"))
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	if out.Method != MethodStepUp {
		t.Fatalf("method = %q, want %q", out.Method, MethodStepUp)
	}
	u, err := url.Parse(out.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse authorization url: %v", err)
	}
	q := u.Query()
	if got := q.Get("state"); got != "correlator-value" {
		t.Fatalf("state = %q, want the correlator", got)
	}
	if got := q.Get("nonce"); got != NonceFor("correlator-value") {
		t.Fatalf("nonce = %q, want the derived nonce", got)
	}
	if got := q.Get("acr_values"); got != acrGold {
		t.Fatalf("acr_values = %q, want %q", got, acrGold)
	}
	if got := q.Get("login_hint"); got != testSubject {
		t.Fatalf("login_hint = %q, want %q", got, testSubject)
	}
	// The reference code is a display value with no place in a redirect: there
	// is no `binding_message` in an authorization request, and the amount and
	// payee come from the decision lookup the approval screen does.
	if got := q.Get("binding_message"); got != "" {
		t.Fatalf("binding_message = %q, want it absent from a step-up request", got)
	}
}

func TestNewStepUpRequiresARequestBuilder(t *testing.T) {
	t.Parallel()
	if _, err := NewStepUp(nil); err == nil {
		t.Fatal("a step-up initiator was built with no request builder")
	}
}

func TestNewFallbackRequiresTwoInitiators(t *testing.T) {
	t.Parallel()
	if _, err := NewFallback(nil, &recordingInitiator{}); err == nil {
		t.Fatal("a fallback chain was built with one initiator")
	}
	if _, err := NewFallback(&recordingInitiator{}, nil); err == nil {
		t.Fatal("a fallback chain was built with one initiator")
	}
}

// TestIssueSurfacesAnInitiatorFailure keeps a challenge from opening that
// nobody was asked to complete: a decision waiting on a prompt that was never
// sent can only ever expire.
func TestIssueSurfacesAnInitiatorFailure(t *testing.T) {
	t.Parallel()
	boom := errors.New("the idp is down")
	h := newTestHandler(t, testConfig(&recordingInitiator{failing: true, err: boom}))
	dec := testDecision(t)
	_, err := h.Issue(t.Context(), issueRequestFor(dec))
	if !errors.Is(err, boom) {
		t.Fatalf("issue err = %v, want the initiator's failure", err)
	}
}
