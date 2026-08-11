package mfa

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
)

const testRedirectURI = "https://stamp.example.test/decisions/dec-A/challenges/0/mfa"

func testStepUpInitiator(t *testing.T) *StepUp {
	t.Helper()
	return stepUpAgainst(t, "")
}

// stepUpAgainst builds a step-up whose token endpoint is the given URL, or none.
func stepUpAgainst(t *testing.T, tokenEndpoint string) *StepUp {
	t.Helper()
	requests, err := identity.NewStepUp(identity.StepUpConfig{
		AuthorizationEndpoint:  "https://idp.example.test/realms/stamp/protocol/openid-connect/auth",
		ClientID:               "stamp-console",
		RedirectURI:            testRedirectURI,
		TokenEndpoint:          tokenEndpoint,
		AllowInsecureTransport: true,
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

// TestStepUpCarriesACSRFStateAndNotTheCorrelator is KTD2 stated as a test.
//
// The callback path names the decision and the ordinal, so `state` has exactly
// one job: proving the redirect answers a request this deployment made. Sending
// the correlator instead would put a binding secret in an address bar, a
// `Referer` and a browser history entry in exchange for nothing — and would put
// it there at the moment U1 made the authorization URL travel in a response.
func TestStepUpCarriesACSRFStateAndNotTheCorrelator(t *testing.T) {
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
	state := q.Get("state")
	switch {
	case state == "":
		t.Fatal("the authorization request carries no state")
	case state == "correlator-value":
		t.Fatal("state is the correlator: a binding secret must not travel in a url (KTD2)")
	case state != out.State:
		t.Fatalf("state = %q, want the value the initiator reported for storage (%q)", state, out.State)
	}
	// The whole URL, not just `state`: the point is that the correlator is
	// nowhere in what a browser will hold.
	if strings.Contains(out.AuthorizationURL, "correlator-value") {
		t.Fatalf("the correlator appears in the authorization url: %s", out.AuthorizationURL)
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

// TestEveryStepUpGetsItsOwnState: two challenges must not share a CSRF token,
// or a link legitimately obtained for one would be usable to drive another.
func TestEveryStepUpGetsItsOwnState(t *testing.T) {
	t.Parallel()
	init := testStepUpInitiator(t)
	first, err := init.Initiate(t.Context(), testInitiateRequest("correlator-one"))
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	second, err := init.Initiate(t.Context(), testInitiateRequest("correlator-two"))
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	if first.State == second.State {
		t.Fatal("two step-ups share a state")
	}
	if first.CodeVerifier == second.CodeVerifier {
		t.Fatal("two step-ups share a pkce verifier")
	}
}

// TestStepUpCommitsToAPKCEVerifierThatDoesNotTravel is the measured defect.
//
// U2 pointed the request this package builds at the demo realm and Keycloak
// answered `error=invalid_request&error_description=Missing+parameter:+
// code_challenge_method`, because `stamp-stepup` is registered with
// `pkce.code.challenge.method: S256` and Keycloak reads that as a requirement.
// The same request with the two parameters below rendered the login form.
func TestStepUpCommitsToAPKCEVerifierThatDoesNotTravel(t *testing.T) {
	t.Parallel()
	out, err := testStepUpInitiator(t).Initiate(t.Context(), testInitiateRequest("correlator-value"))
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	u, err := url.Parse(out.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse authorization url: %v", err)
	}
	q := u.Query()
	if got := q.Get("code_challenge_method"); got != identity.PKCEMethod {
		t.Fatalf("code_challenge_method = %q, want %q", got, identity.PKCEMethod)
	}
	if out.CodeVerifier == "" {
		t.Fatal("the initiator reported no verifier to store")
	}
	if got := q.Get("code_challenge"); got != identity.PKCEChallenge(out.CodeVerifier) {
		t.Fatalf("code_challenge = %q, want the S256 digest of the verifier", got)
	}
	// The verifier is the secret half. A challenge that carried it would be a
	// challenge worth nothing.
	if strings.Contains(out.AuthorizationURL, out.CodeVerifier) {
		t.Fatalf("the pkce verifier travels in the authorization url: %s", out.AuthorizationURL)
	}
}

// tokenOP is a bare token endpoint that answers the way the measured Keycloak
// did. It is not [mockOP], which speaks CIBA: this is the one call a step-up
// makes, and the shape of that call is what these tests are about.
type tokenOP struct {
	forms   []url.Values
	idToken string
	// refuse, when set, is the OAuth error code to answer with.
	refuse string
}

func (m *tokenOP) endpoint(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse token request: %v", err)
		}
		m.forms = append(m.forms, r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		if m.refuse != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"` + m.refuse + `","error_description":"Code not valid"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id_token":"` + m.idToken + `","token_type":"Bearer"}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestRedeemSpendsTheVerifierAndRepeatsTheRedirect fixes the token call's shape
// against what the measured OP required: `authorization_code`, the verifier, the
// same `redirect_uri` the authorization request named, and — for a public client
// — the client identifier in the body rather than a secret in a header.
func TestRedeemSpendsTheVerifierAndRepeatsTheRedirect(t *testing.T) {
	t.Parallel()
	op := &tokenOP{idToken: "the.id.token"}
	init := stepUpAgainst(t, op.endpoint(t))
	out, err := init.Initiate(t.Context(), testInitiateRequest("correlator-value"))
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}

	token, err := init.Redeem(t.Context(), RedeemRequest{
		Instance:      challenge.Instance{DecisionID: "dec-A", Kind: policy.ChallengeMFA},
		Params:        map[string]string{"code": "the-code", "state": out.State},
		ExpectedState: out.State,
		CodeVerifier:  out.CodeVerifier,
		RedirectURI:   testRedirectURI,
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if token != "the.id.token" {
		t.Fatalf("token = %q, want the op's id_token", token)
	}
	if len(op.forms) != 1 {
		t.Fatalf("token endpoint called %d times, want 1", len(op.forms))
	}
	form := op.forms[0]
	for _, want := range []struct{ key, value string }{
		{"grant_type", "authorization_code"},
		{"code", "the-code"},
		{"code_verifier", out.CodeVerifier},
		{"redirect_uri", testRedirectURI},
		{"client_id", "stamp-console"},
	} {
		if got := form.Get(want.key); got != want.value {
			t.Errorf("token request %s = %q, want %q", want.key, got, want.value)
		}
	}
}

// TestRedeemRefusesAWrongStateBeforeCallingTheOP is the CSRF check, and the
// "before" is half of it: an unsolicited redirect must not be able to make this
// deployment spend a token call.
func TestRedeemRefusesAWrongStateBeforeCallingTheOP(t *testing.T) {
	t.Parallel()
	op := &tokenOP{idToken: "the.id.token"}
	init := stepUpAgainst(t, op.endpoint(t))
	out, err := init.Initiate(t.Context(), testInitiateRequest("correlator-value"))
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}

	for _, tc := range []struct {
		name  string
		state string
	}{
		{"forged", "not-the-state"},
		{"absent", ""},
		{"the correlator, which is what KTD2 removed", "correlator-value"},
	} {
		_, err := init.Redeem(t.Context(), RedeemRequest{
			Params:        map[string]string{"code": "the-code", "state": tc.state},
			ExpectedState: out.State,
			CodeVerifier:  out.CodeVerifier,
			RedirectURI:   testRedirectURI,
		})
		if !errors.Is(err, challenge.ErrRedemptionRefused) {
			t.Errorf("%s: redeem err = %v, want ErrRedemptionRefused", tc.name, err)
		}
	}
	if len(op.forms) != 0 {
		t.Fatalf("the token endpoint was called %d times for a forged state, want 0", len(op.forms))
	}
}

// TestRedeemRefusesACodeTheOPWillNotExchange covers the second challenge's code
// presented at the first challenge's path. The OP refuses it because the
// verifier and the `redirect_uri` are both this challenge's, and both are part
// of what it checks — which is why this needs no comparison of its own.
func TestRedeemRefusesACodeTheOPWillNotExchange(t *testing.T) {
	t.Parallel()
	op := &tokenOP{refuse: "invalid_grant"}
	init := stepUpAgainst(t, op.endpoint(t))
	out, err := init.Initiate(t.Context(), testInitiateRequest("correlator-value"))
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	_, err = init.Redeem(t.Context(), RedeemRequest{
		Params:        map[string]string{"code": "another-challenges-code", "state": out.State},
		ExpectedState: out.State,
		CodeVerifier:  out.CodeVerifier,
		RedirectURI:   testRedirectURI,
	})
	if !errors.Is(err, challenge.ErrRedemptionRefused) {
		t.Fatalf("redeem err = %v, want ErrRedemptionRefused", err)
	}
	if !errors.Is(err, identity.ErrAuthorizationCodeRejected) {
		t.Fatalf("redeem err = %v, want the op's refusal preserved for the audit trail", err)
	}
}

// TestRedeemReportsAnIdPRefusal: the measured Keycloak answered a request with
// no PKCE by redirecting *to the callback* with `error=invalid_request`, so this
// is a shape the callback actually receives rather than a hypothetical one.
func TestRedeemReportsAnIdPRefusal(t *testing.T) {
	t.Parallel()
	op := &tokenOP{idToken: "the.id.token"}
	init := stepUpAgainst(t, op.endpoint(t))
	out, err := init.Initiate(t.Context(), testInitiateRequest("correlator-value"))
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	_, err = init.Redeem(t.Context(), RedeemRequest{
		Params: map[string]string{
			"state":             out.State,
			"error":             "invalid_request",
			"error_description": "Missing parameter: code_challenge_method",
		},
		ExpectedState: out.State,
		CodeVerifier:  out.CodeVerifier,
		RedirectURI:   testRedirectURI,
	})
	if !errors.Is(err, challenge.ErrRedemptionRefused) {
		t.Fatalf("redeem err = %v, want ErrRedemptionRefused", err)
	}
	if !strings.Contains(err.Error(), "invalid_request") {
		t.Fatalf("redeem err = %v, want the idp's error code in it", err)
	}
	if len(op.forms) != 0 {
		t.Fatalf("the token endpoint was called for a redirect that carried no code")
	}
}

// TestFallbackRedeemsThroughTheRedirectHalf: a chain whose primary is CIBA still
// has to be able to finish the step-up it fell through to.
func TestFallbackRedeemsThroughTheRedirectHalf(t *testing.T) {
	t.Parallel()
	op := &tokenOP{idToken: "the.id.token"}
	stepUp := stepUpAgainst(t, op.endpoint(t))
	chain, err := NewFallback(&recordingInitiator{}, stepUp)
	if err != nil {
		t.Fatalf("build fallback: %v", err)
	}
	out, err := stepUp.Initiate(t.Context(), testInitiateRequest("correlator-value"))
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	token, err := chain.Redeem(t.Context(), RedeemRequest{
		Params:        map[string]string{"code": "the-code", "state": out.State},
		ExpectedState: out.State,
		CodeVerifier:  out.CodeVerifier,
		RedirectURI:   testRedirectURI,
	})
	if err != nil {
		t.Fatalf("redeem through the chain: %v", err)
	}
	if token != "the.id.token" {
		t.Fatalf("token = %q, want the op's id_token", token)
	}
}

// TestFallbackWithNoRedirectHalfIsNotRedeemable keeps the fail-closed answer:
// two transports that neither redirect leave nothing to redeem, and the
// lifecycle must hear that rather than a nil token.
func TestFallbackWithNoRedirectHalfIsNotRedeemable(t *testing.T) {
	t.Parallel()
	chain, err := NewFallback(&recordingInitiator{}, &recordingInitiator{})
	if err != nil {
		t.Fatalf("build fallback: %v", err)
	}
	if _, err := chain.Redeem(t.Context(), RedeemRequest{}); !errors.Is(err, challenge.ErrNotRedeemable) {
		t.Fatalf("redeem err = %v, want ErrNotRedeemable", err)
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

// TestIssueTellsTheInitiatorWhereToComeBack closes the loop between the
// challenge and the callback route: a browser redirect has to land somewhere
// that knows which challenge it answers, and the route pattern belongs to the
// API layer, so the composition root supplies the URL rather than this package
// building a second copy of it.
func TestIssueTellsTheInitiatorWhereToComeBack(t *testing.T) {
	t.Parallel()
	init := &recordingInitiator{}
	cfg := testConfig(init)
	cfg.CallbackURL = func(in challenge.Instance) string {
		return "https://stamp.example.test/decisions/" + in.DecisionID +
			"/challenges/" + strconv.Itoa(in.Ordinal) + "/mfa"
	}
	h := newTestHandler(t, cfg)
	issue(t, h, policy.MFA{Mode: policy.MFADelegated}, testDecision(t), testNow)

	if len(init.calls) != 1 {
		t.Fatalf("initiator called %d times, want 1", len(init.calls))
	}
	want := "https://stamp.example.test/decisions/dec-A/challenges/0/mfa"
	if init.calls[0].RedirectURI != want {
		t.Fatalf("redirect uri = %q, want %q", init.calls[0].RedirectURI, want)
	}
}

// TestIssueLeavesTheRedirectEmptyWithoutASeam keeps the default harmless: a
// deployment with one fixed callback says nothing and gets the configured one.
func TestIssueLeavesTheRedirectEmptyWithoutASeam(t *testing.T) {
	t.Parallel()
	init := &recordingInitiator{}
	h := newTestHandler(t, testConfig(init))
	issue(t, h, policy.MFA{Mode: policy.MFADelegated}, testDecision(t), testNow)
	if init.calls[0].RedirectURI != "" {
		t.Fatalf("redirect uri = %q, want empty", init.calls[0].RedirectURI)
	}
}

// ---------------------------------------------------------------------------
// the handler's half of the redemption
// ---------------------------------------------------------------------------

// redeemableHandler is a handler whose initiator really redeems, with the
// token endpoint it will call.
func redeemableHandler(t *testing.T, op *tokenOP) *Delegated {
	t.Helper()
	cfg := testConfig(stepUpAgainst(t, op.endpoint(t)))
	cfg.CallbackURL = func(in challenge.Instance) string {
		return "https://stamp.example.test/decisions/" + in.DecisionID +
			"/challenges/" + strconv.Itoa(in.Ordinal) + "/mfa"
	}
	return newTestHandler(t, cfg)
}

// TestRedeemHandsBackTheCorrelatorAndNeverThePayload is the seam KTD2 made
// possible: the browser carries `code` and `state` and nothing else, so the
// correlator has to come off the challenge row rather than out of a request.
func TestRedeemHandsBackTheCorrelatorAndNeverThePayload(t *testing.T) {
	t.Parallel()
	op := &tokenOP{idToken: "the.id.token"}
	h := redeemableHandler(t, op)
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{acrGold}}, dec, testNow)

	out, err := h.Redeem(t.Context(), challenge.RedeemRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Ordinal: 0, Kind: policy.ChallengeMFA},
		Decision: dec,
		Detail:   raw,
		Params:   map[string]string{"code": "the-code", "state": detail.State},
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if out.Credential != "the.id.token" {
		t.Fatalf("credential = %q, want the op's id_token", out.Credential)
	}
	var body Submission
	if err := json.Unmarshal(out.Payload, &body); err != nil {
		t.Fatalf("decode the redeemed payload: %v", err)
	}
	if body.Correlator != detail.Correlator {
		t.Fatalf("payload correlator = %q, want the frozen one", body.Correlator)
	}
	// The token call has to name the challenge's own callback path: it is the
	// redirect the authorization request registered, and the OP checks it.
	if got := op.forms[0].Get("redirect_uri"); got != "https://stamp.example.test/decisions/dec-A/challenges/0/mfa" {
		t.Fatalf("redirect_uri = %q, want this challenge's callback path", got)
	}
}

// TestRedeemThenSubmitSatisfiesTheChallenge walks the whole round the way the
// surface does: redeem, verify (stubbed here by assembling the subject the
// verifier would have produced), submit.
func TestRedeemThenSubmitSatisfiesTheChallenge(t *testing.T) {
	t.Parallel()
	op := &tokenOP{idToken: "the.id.token"}
	h := redeemableHandler(t, op)
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{acrGold}}, dec, testNow)

	redeemed, err := h.Redeem(t.Context(), challenge.RedeemRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Ordinal: 0, Kind: policy.ChallengeMFA},
		Decision: dec,
		Detail:   raw,
		Params:   map[string]string{"code": "the-code", "state": detail.State},
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	var body Submission
	if err := json.Unmarshal(redeemed.Payload, &body); err != nil {
		t.Fatalf("decode the redeemed payload: %v", err)
	}
	at := testNow.Add(time.Minute)
	out, err := submit(t, h, raw, dec, goodCompletion(detail, at), body.Correlator, at)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if out.State != challenge.StateSatisfied {
		t.Fatalf("state = %q, want satisfied", out.State)
	}
}

// TestRedeemRefusesASpentChallengeBeforeSpendingACode: a correlator that has
// already been consumed cannot become more satisfied, and redeeming would burn
// a real authorization code to reach a refusal that was already certain.
func TestRedeemRefusesASpentChallengeBeforeSpendingACode(t *testing.T) {
	t.Parallel()
	op := &tokenOP{idToken: "the.id.token"}
	h := redeemableHandler(t, op)
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{acrGold}}, dec, testNow)

	at := testNow.Add(time.Minute)
	out, err := submit(t, h, raw, dec, goodCompletion(detail, at), detail.Correlator, at)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	spent, err := json.Marshal(out.Detail)
	if err != nil {
		t.Fatalf("encode the spent detail: %v", err)
	}
	before := len(op.forms)
	_, err = h.Redeem(t.Context(), challenge.RedeemRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Ordinal: 0, Kind: policy.ChallengeMFA},
		Decision: dec,
		Detail:   spent,
		Params:   map[string]string{"code": "the-code", "state": detail.State},
		Now:      at,
	})
	if !errors.Is(err, ErrCorrelatorConsumed) {
		t.Fatalf("redeem err = %v, want ErrCorrelatorConsumed", err)
	}
	if len(op.forms) != before {
		t.Fatalf("the token endpoint was called for a spent challenge")
	}
}

// TestRedeemIsNotAvailableWithoutARedirectTransport keeps the fail-closed
// answer for a challenge that was opened by a backchannel push: there is no
// redirect to redeem, and inventing one would be inventing a completion.
func TestRedeemIsNotAvailableWithoutARedirectTransport(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{method: MethodCIBA}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)
	_, err := h.Redeem(t.Context(), challenge.RedeemRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Ordinal: 0, Kind: policy.ChallengeMFA},
		Decision: dec,
		Detail:   raw,
		Params:   map[string]string{"code": "the-code", "state": detail.State},
		Now:      testNow,
	})
	if !errors.Is(err, challenge.ErrNotRedeemable) {
		t.Fatalf("redeem err = %v, want ErrNotRedeemable", err)
	}
}

// TestRedeemRefusesAnUnreadableDetail: the redemption path decodes the same row
// every other verb decodes, and answers a corrupt one the same way.
func TestRedeemRefusesAnUnreadableDetail(t *testing.T) {
	t.Parallel()
	h := redeemableHandler(t, &tokenOP{idToken: "t"})
	_, err := h.Redeem(t.Context(), challenge.RedeemRequest{
		Instance: challenge.Instance{DecisionID: "dec-A", Ordinal: 0, Kind: policy.ChallengeMFA},
		Decision: testDecision(t),
		Detail:   json.RawMessage(`{"mode":`),
		Now:      testNow,
	})
	if !errors.Is(err, challenge.ErrInvalidPayload) {
		t.Fatalf("redeem err = %v, want ErrInvalidPayload", err)
	}
}
