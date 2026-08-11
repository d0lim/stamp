package api_test

// mfa_test.go exercises the callback surface and nothing below it: that it
// lands on the callback listener rather than the console one, that it verifies
// the completion credential before anything else, that it forwards the
// correlator and takes the caller from the token, and that it turns the mfa
// handler's sentinels into statuses an operator can act on. What satisfies a
// challenge is decided in internal/challenge/mfa and tested there.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/challenge/mfa"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/store"
)

const mfaPath = "/decisions/" + testDecisionID + "/challenges/0/mfa"

// stubVerifier stands in for identity.Verifier: this surface's job is to call
// one, not to be one.
type stubVerifier struct {
	mu      sync.Mutex
	tokens  []string
	subject *identity.Subject
	err     error
}

func (s *stubVerifier) Verify(_ context.Context, raw string) (*identity.Subject, error) {
	s.mu.Lock()
	s.tokens = append(s.tokens, raw)
	s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return s.subject, nil
}

// stubRedeemer stands in for the decision service's redemption path: this
// surface's job is to route a redirect to one, not to be one.
type stubRedeemer struct {
	mu         sync.Mutex
	calls      []decision.Callback
	redemption challenge.Redemption
	err        error
}

func (s *stubRedeemer) Redeem(_ context.Context, cb decision.Callback) (challenge.Redemption, error) {
	s.mu.Lock()
	s.calls = append(s.calls, cb)
	s.mu.Unlock()
	if s.err != nil {
		return challenge.Redemption{}, s.err
	}
	return s.redemption, nil
}

func (s *stubRedeemer) redeemed() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *stubRedeemer) lastCallback(t *testing.T) decision.Callback {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		t.Fatal("no redemption was attempted")
	}
	return s.calls[len(s.calls)-1]
}

type mfaFixture struct {
	server    *api.Server
	collector *recordingCollector
	verifier  *stubVerifier
	redeemer  *stubRedeemer
}

func newMFAFixture(t *testing.T) *mfaFixture {
	t.Helper()
	idp := newMockIdP(t)
	sink := identity.AuditSinkFunc(func(context.Context, identity.AuthRecord) {})
	server, err := api.New(api.Config{
		Identity: idp.middleware(t, sink, func() time.Time { return fixedNow }),
		Addresses: map[api.Surface]string{
			api.SurfaceConsole:  "127.0.0.1:0",
			api.SurfaceCallback: "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	collector := &recordingCollector{
		result: decision.Result{ID: testDecisionID, State: store.DecisionPending},
	}
	verifier := &stubVerifier{subject: identity.NewSubject(identity.Subject{
		Kind:     identity.SubjectUser,
		Issuer:   "https://idp.example.test",
		ID:       "alice",
		ClientID: "console",
		Audience: []string{"stamp"},
		ACR:      "gold",
	}, []byte(`{"sub":"alice","acr":"gold"}`))}

	redeemer := &stubRedeemer{redemption: challenge.Redemption{
		Credential: "the.redeemed.token",
		Payload:    []byte(`{"correlator":"correlator-value"}`),
	}}

	surface, err := api.NewMFA(api.MFAConfig{Decisions: collector, Tokens: verifier, Redeemer: redeemer})
	if err != nil {
		t.Fatalf("build mfa surface: %v", err)
	}
	if err := server.Mount(surface); err != nil {
		t.Fatalf("mount mfa surface: %v", err)
	}
	return &mfaFixture{server: server, collector: collector, verifier: verifier, redeemer: redeemer}
}

// land drives the IdP redirect: a GET with a query and no body.
func (f *mfaFixture) land(t *testing.T, surface api.Surface, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, mfaPath+"?"+query, http.NoBody)
	rec := httptest.NewRecorder()
	f.server.Handler(surface).ServeHTTP(rec, req)
	return rec
}

func (f *mfaFixture) post(t *testing.T, surface api.Surface, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader = http.NoBody
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(http.MethodPost, mfaPath, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.server.Handler(surface).ServeHTTP(rec, req)
	return rec
}

func completionBody(correlator, token string) string {
	return fmt.Sprintf(`{"correlator":%q,"id_token":%q}`, correlator, token)
}

// TestMFACallbackIsOnTheCallbackListenerOnly is the separation stated as a
// test: a browser following an IdP redirect may be nowhere near the operator
// network the console is bound to, and a route mounted on one listener is not
// reachable on another because the other router has never heard of it.
func TestMFACallbackIsOnTheCallbackListenerOnly(t *testing.T) {
	t.Parallel()
	f := newMFAFixture(t)

	if rec := f.post(t, api.SurfaceCallback, completionBody("c", "a.b.c")); rec.Code != http.StatusOK {
		t.Fatalf("callback surface returned %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec := f.post(t, api.SurfaceConsole, completionBody("c", "a.b.c")); rec.Code != http.StatusNotFound {
		t.Fatalf("console surface returned %d for the mfa callback, want 404", rec.Code)
	}

	if rec := f.land(t, api.SurfaceCallback, "code=c&state=s"); rec.Code != http.StatusOK {
		t.Fatalf("callback surface returned %d for the redirect, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec := f.land(t, api.SurfaceConsole, "code=c&state=s"); rec.Code != http.StatusNotFound {
		t.Fatalf("console surface returned %d for the mfa redirect, want 404", rec.Code)
	}

	mounted := f.server.Mounted(api.SurfaceCallback)
	if len(mounted) != 2 {
		t.Fatalf("mounted %d routes on the callback surface, want 2", len(mounted))
	}
	for _, route := range mounted {
		if route.Auth != api.AuthPublic {
			t.Fatalf("route %s auth = %q, want public", route.Name, route.Auth)
		}
	}
}

// TestMFACallbackForwardsTheCorrelatorAndTheVerifiedCaller is the whole of what
// this layer contributes: the token becomes the caller, the correlator becomes
// the payload, and nothing in the request says who authenticated.
func TestMFACallbackForwardsTheCorrelatorAndTheVerifiedCaller(t *testing.T) {
	t.Parallel()
	f := newMFAFixture(t)
	rec := f.post(t, api.SurfaceCallback, completionBody("correlator-value", "the.id.token"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	sub := f.collector.lastSubmission(t)
	if sub.DecisionID != testDecisionID || sub.Ordinal != 0 {
		t.Fatalf("submission named %s#%d", sub.DecisionID, sub.Ordinal)
	}
	if sub.Caller == nil || sub.Caller.ID != "alice" {
		t.Fatalf("caller = %+v, want the verified subject", sub.Caller)
	}
	var payload mfa.Submission
	if err := json.Unmarshal(sub.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Correlator != "correlator-value" {
		t.Fatalf("correlator = %q", payload.Correlator)
	}
	if len(f.verifier.tokens) != 1 || f.verifier.tokens[0] != "the.id.token" {
		t.Fatalf("verifier saw %v", f.verifier.tokens)
	}
}

// TestMFACallbackRefusesAnUnverifiableToken is why a public route is not an
// unauthenticated one: the credential arrives in the body instead of a header
// and is checked against the same pinned issuer set.
func TestMFACallbackRefusesAnUnverifiableToken(t *testing.T) {
	t.Parallel()
	f := newMFAFixture(t)
	f.verifier.err = identity.ErrSignatureInvalid

	rec := f.post(t, api.SurfaceCallback, completionBody("c", "forged.id.token"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if f.collector.submitted() != 0 {
		t.Fatal("an unverifiable completion reached the decision service")
	}
	// The verification reason is not narrated back to an unauthenticated
	// caller; identity's audit sink is where it belongs.
	if strings.Contains(rec.Body.String(), "signature") {
		t.Fatalf("the refusal narrated the verification failure: %s", rec.Body.String())
	}
}

func TestMFACallbackRefusesAnIncompleteBody(t *testing.T) {
	t.Parallel()
	f := newMFAFixture(t)
	for name, body := range map[string]string{
		"no correlator": `{"id_token":"a.b.c"}`,
		"no token":      `{"correlator":"c"}`,
		"empty":         `{}`,
		"not json":      `{`,
		// A client that believes it can name the subject should find out.
		"names a subject": `{"correlator":"c","id_token":"a.b.c","subject":"mallory"}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rec := f.post(t, api.SurfaceCallback, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for %s", rec.Code, name)
			}
		})
	}
	if f.collector.submitted() != 0 {
		t.Fatal("an incomplete completion reached the decision service")
	}
}

// TestMFACallbackDistinguishesTheRefusals is the table an operator reads. A
// downgraded `acr` and a stale `auth_time` are different diagnoses — the first
// says the IdP is not configured the way the deployment believes, the second
// says the subject answered from a session that was already open — so they are
// different codes rather than one "denied".
func TestMFACallbackDistinguishesTheRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		err    error
		status int
		code   string
	}{
		"downgraded acr":  {mfa.ErrACRNotAllowed, http.StatusForbidden, "acr_not_allowed"},
		"weak acr":        {mfa.ErrACRUnsatisfied, http.StatusForbidden, "acr_unsatisfied"},
		"stale auth_time": {mfa.ErrStaleAuthentication, http.StatusForbidden, "stale_authentication"},
		"amr mismatch":    {mfa.ErrAMRMismatch, http.StatusForbidden, "amr_mismatch"},
		"wrong decision":  {mfa.ErrCorrelatorMismatch, http.StatusForbidden, "correlator_mismatch"},
		"replayed":        {mfa.ErrCorrelatorConsumed, http.StatusConflict, "correlator_consumed"},
		"wrong party":     {mfa.ErrCredentialMismatch, http.StatusForbidden, "credential_mismatch"},
		"wrong nonce":     {mfa.ErrNonceMismatch, http.StatusForbidden, "nonce_mismatch"},
		"context moved":   {mfa.ErrContextChanged, http.StatusConflict, "material_changed"},
		"direct mode":     {mfa.ErrDirectModeUnimplemented, http.StatusNotImplemented, "unsupported_challenge"},
		"not the subject": {challenge.ErrNotTarget, http.StatusForbidden, "not_the_subject"},
		"no challenge":    {decision.ErrNoSuchChallenge, http.StatusNotFound, "not_found"},
		"expired":         {store.ErrDecisionExpired, http.StatusConflict, "expired"},
		"resolved":        {decision.ErrNotPending, http.StatusConflict, "not_collecting"},
		"bad payload":     {challenge.ErrInvalidPayload, http.StatusBadRequest, "invalid_submission"},
		"database down":   {errors.New("connection refused"), http.StatusInternalServerError, "internal_error"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newMFAFixture(t)
			f.collector.submitErr = fmt.Errorf("decision: submit: %w", tc.err)
			rec := f.post(t, api.SurfaceCallback, completionBody("c", "a.b.c"))
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.status, rec.Body.String())
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode error body: %v", err)
			}
			if body.Error != tc.code {
				t.Fatalf("error code = %q, want %q", body.Error, tc.code)
			}
			// A database failure is not narrated to a caller who reached a
			// public endpoint.
			if tc.code == "internal_error" && strings.Contains(rec.Body.String(), "connection refused") {
				t.Fatalf("the refusal narrated the failure: %s", rec.Body.String())
			}
		})
	}
}

// TestTheMFAForbiddenCodesStayDistinct is the exception to #38, held down so
// that a later pass at "one refusal, one answer" does not take this table with
// it.
//
// Everywhere else, a caller who may not have a thing is told what a caller
// asking about a thing that does not exist is told — the audience there is a
// stranger probing for existence, and the difference between the two answers is
// the leak. Here the audience is an operator with a challenge nobody can satisfy,
// and every one of these codes is a different diagnosis they have to reach:
// `acr_not_allowed` says the deployment's allowlist does not admit what the IdP
// asserts, `acr_unsatisfied` says the policy asks for more than the subject did,
// `stale_authentication` says they answered from a session that was already
// open. Folding them together would leave a deployment with a step-up that never
// completes and no way to learn why.
//
// Nothing is leaked by the split that the split is meant to protect: none of
// these is reached before the `state` check, so none of them answers "does this
// decision exist" — that question is already one uniform 403 (see the landing
// tests), and this table's forbidden codes are what the *operator* reads out of
// the logs behind it.
func TestTheMFAForbiddenCodesStayDistinct(t *testing.T) {
	t.Parallel()
	// The seven strength-and-binding refusals the table has always separated.
	// Named individually rather than counted from the code, because a test that
	// derived the list from the thing it is pinning would agree with any change
	// to it.
	forbidden := map[string]error{
		"acr_not_allowed":      mfa.ErrACRNotAllowed,
		"acr_unsatisfied":      mfa.ErrACRUnsatisfied,
		"amr_mismatch":         mfa.ErrAMRMismatch,
		"stale_authentication": mfa.ErrStaleAuthentication,
		"correlator_mismatch":  mfa.ErrCorrelatorMismatch,
		"credential_mismatch":  mfa.ErrCredentialMismatch,
		"nonce_mismatch":       mfa.ErrNonceMismatch,
	}

	seen := make(map[string]string, len(forbidden))
	for want, sentinel := range forbidden {
		f := newMFAFixture(t)
		f.collector.submitErr = fmt.Errorf("decision: submit: %w", sentinel)
		rec := f.post(t, api.SurfaceCallback, completionBody("c", "a.b.c"))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s = %d, want 403: %s", want, rec.Code, rec.Body.String())
			continue
		}
		var body api.ErrorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Errorf("%s: decode %q: %v", want, rec.Body.String(), err)
			continue
		}
		if body.Error != want {
			t.Errorf("code = %q, want %q", body.Error, want)
		}
		if other, dup := seen[body.Error]; dup {
			t.Errorf("%s and %s now answer with the same code %q", want, other, body.Error)
		}
		seen[body.Error] = want
	}
	if len(seen) != len(forbidden) {
		t.Errorf("%d distinct forbidden codes remain, want %d", len(seen), len(forbidden))
	}
}

func TestMFACallbackBoundsTheBody(t *testing.T) {
	t.Parallel()
	f := newMFAFixture(t)
	huge := completionBody("c", strings.Repeat("A", api.DefaultMaxMFACallbackBytes+1))
	rec := f.post(t, api.SurfaceCallback, huge)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if f.collector.submitted() != 0 {
		t.Fatal("an oversized completion reached the decision service")
	}
}

// TestMFACallbackPathMatchesTheMountedPattern is the seam between the challenge
// handler and this route stated as a test: the URL a step-up is told to come
// back to has to be a URL this router actually serves.
func TestMFACallbackPathMatchesTheMountedPattern(t *testing.T) {
	t.Parallel()
	f := newMFAFixture(t)
	path := api.MFACallbackPath(testDecisionID, 0)
	if path != mfaPath {
		t.Fatalf("MFACallbackPath = %q, want %q", path, mfaPath)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(completionBody("c", "a.b.c")))
	rec := httptest.NewRecorder()
	f.server.Handler(api.SurfaceCallback).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d for the rendered callback path, want 200: %s", rec.Code, rec.Body.String())
	}
	// A decision identifier carrying a path separator must not escape the route
	// it was rendered for.
	if got := api.MFACallbackPath("a/b", 3); got != "/decisions/a%2Fb/challenges/3/mfa" {
		t.Fatalf("MFACallbackPath escaped as %q", got)
	}
}

func TestNewMFARequiresItsCollaborators(t *testing.T) {
	t.Parallel()
	if _, err := api.NewMFA(api.MFAConfig{Tokens: &stubVerifier{}}); err == nil {
		t.Fatal("an mfa surface was built with no decision service")
	}
	if _, err := api.NewMFA(api.MFAConfig{
		Decisions: &recordingCollector{}, Redeemer: &stubRedeemer{},
	}); err == nil {
		t.Fatal("an mfa surface was built with no token verifier")
	}
	// Without a redeemer the step-up D26 made the default path has no way back,
	// which is the whole of #41. It is refused at wiring time rather than at the
	// moment somebody has finished authenticating and is waiting for a page.
	if _, err := api.NewMFA(api.MFAConfig{
		Decisions: &recordingCollector{}, Tokens: &stubVerifier{},
	}); err == nil {
		t.Fatal("an mfa surface was built with no redeemer")
	}
}

// ---------------------------------------------------------------------------
// the IdP redirect
// ---------------------------------------------------------------------------

// TestMFARedirectCompletesTheStepUp is #41's second seam closed: the IdP sends a
// browser, the challenge redeems the code, and the token that comes back walks
// the same three lines the POST body's token does.
func TestMFARedirectCompletesTheStepUp(t *testing.T) {
	t.Parallel()
	f := newMFAFixture(t)
	rec := f.land(t, api.SurfaceCallback, "code=the-code&state=the-state&session_state=x")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	cb := f.redeemer.lastCallback(t)
	if cb.DecisionID != testDecisionID || cb.Ordinal != 0 {
		t.Fatalf("redemption named %s#%d", cb.DecisionID, cb.Ordinal)
	}
	// The whole query is passed through: the transport's vocabulary is the
	// transport's, and a surface that named fields would have to keep the list
	// in step with whichever transports exist.
	for k, want := range map[string]string{"code": "the-code", "state": "the-state", "session_state": "x"} {
		if cb.Params[k] != want {
			t.Errorf("callback param %s = %q, want %q", k, cb.Params[k], want)
		}
	}
	// The credential the redemption produced is what gets verified. The surface
	// does not invent one, and the browser did not carry one.
	if len(f.verifier.tokens) != 1 || f.verifier.tokens[0] != "the.redeemed.token" {
		t.Fatalf("verifier saw %v, want the redeemed token", f.verifier.tokens)
	}
	sub := f.collector.lastSubmission(t)
	if sub.Caller == nil || sub.Caller.ID != "alice" {
		t.Fatalf("caller = %+v, want the verified subject", sub.Caller)
	}
	var payload mfa.Submission
	if err := json.Unmarshal(sub.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Correlator != "correlator-value" {
		t.Fatalf("correlator = %q, want the one the redemption supplied", payload.Correlator)
	}
}

// TestMFARedirectAnswersAPersonInHTML is Open Question 1 answered.
//
// The other callback on this listener answers a machine in JSON; this one
// answers somebody who has just typed a password because they were asked to.
// The headers are the load-bearing part: `Referrer-Policy: no-referrer` keeps
// the authorization code in this URL's query from travelling anywhere, and the
// CSP can be `default-src 'none'` because the page needs nothing.
func TestMFARedirectAnswersAPersonInHTML(t *testing.T) {
	t.Parallel()
	f := newMFAFixture(t)
	rec := f.land(t, api.SurfaceCallback, "code=the-code&state=the-state")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	h := rec.Header()
	for name, want := range map[string]string{
		"Content-Type":            "text/html; charset=utf-8",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
		"Cache-Control":           "no-store",
		"Content-Security-Policy": "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
	} {
		if got := h.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Verification complete") {
		t.Errorf("the page does not say the verification succeeded: %s", body)
	}
	// A page with no scripts, no styles and no external references is what makes
	// the CSP above a statement rather than a wish.
	for _, forbidden := range []string{"<script", "<style", "<img", "http://", "https://"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the landing page contains %q, which its own CSP forbids: %s", forbidden, body)
		}
	}
}

// TestMFARedirectRefusesUniformlyBeforeTheStateIsProved is the oracle closed.
//
// Until a `state` checks out, the party holding the link has proved nothing — so
// an unknown decision, a forged state, a code the IdP would not exchange and a
// challenge that is no longer collecting are one status and one page. The
// external webhook listener makes the same choice for the same reason; the
// difference here is only that the one page is readable.
func TestMFARedirectRefusesUniformlyBeforeTheStateIsProved(t *testing.T) {
	t.Parallel()
	var bodies []string
	for name, err := range map[string]error{
		"no such decision":  store.ErrNotFound,
		"no such challenge": decision.ErrNoSuchChallenge,
		"forged state":      fmt.Errorf("decision: redeem: %w", challenge.ErrRedemptionRefused),
		"already resolved":  decision.ErrNotPending,
		"expired":           store.ErrDecisionExpired,
		"already spent":     mfa.ErrCorrelatorConsumed,
		"not a redirect":    challenge.ErrNotRedeemable,
	} {
		f := newMFAFixture(t)
		f.redeemer.err = err
		rec := f.land(t, api.SurfaceCallback, "code=c&state=s")
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want a uniform 403", name, rec.Code)
		}
		if f.collector.submitted() != 0 {
			t.Errorf("%s: an unredeemed callback reached the decision service", name)
		}
		bodies = append(bodies, rec.Body.String())
	}
	for i := range bodies {
		if bodies[i] != bodies[0] {
			t.Fatalf("the refusals differ in their bodies:\n%s\n---\n%s", bodies[0], bodies[i])
		}
	}
	if strings.Contains(bodies[0], testDecisionID) {
		t.Fatalf("the refusal names the decision: %s", bodies[0])
	}
}

// TestMFARedirectReportsAnOutageAsAnOutage: a database that is down is not a
// refusal, and telling somebody their link was bad when it was fine would have
// them start over against a system that cannot answer.
func TestMFARedirectReportsAnOutageAsAnOutage(t *testing.T) {
	t.Parallel()
	f := newMFAFixture(t)
	f.redeemer.err = errors.New("connection refused")
	rec := f.land(t, api.SurfaceCallback, "code=c&state=s")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "connection refused") {
		t.Fatalf("the page narrated the failure: %s", rec.Body.String())
	}
}

// TestMFARedirectTellsTheSubjectWhatTheyCanActOnAfterRedeeming is the other half
// of the answer to Open Question 1. Once the state has checked out, the party
// reading the page is the subject — and folding every refusal into one message
// would tell somebody to try again when trying again cannot work.
func TestMFARedirectTellsTheSubjectWhatTheyCanActOnAfterRedeeming(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		err    error
		status int
		says   string
	}{
		"downgraded acr": {mfa.ErrACRNotAllowed, http.StatusForbidden, "not strong enough"},
		"weak acr":       {mfa.ErrACRUnsatisfied, http.StatusForbidden, "not strong enough"},
		"stale session":  {mfa.ErrStaleAuthentication, http.StatusForbidden, "no longer open"},
		"replayed":       {mfa.ErrCorrelatorConsumed, http.StatusConflict, "no longer open"},
		"context moved":  {mfa.ErrContextChanged, http.StatusConflict, "no longer open"},
		"wrong nonce":    {mfa.ErrNonceMismatch, http.StatusForbidden, "cannot be used"},
		"not the target": {challenge.ErrNotTarget, http.StatusForbidden, "cannot be used"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newMFAFixture(t)
			f.collector.submitErr = fmt.Errorf("decision: submit: %w", tc.err)
			rec := f.land(t, api.SurfaceCallback, "code=c&state=s")
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			if !strings.Contains(rec.Body.String(), tc.says) {
				t.Fatalf("the page does not say %q: %s", tc.says, rec.Body.String())
			}
			// Whatever else it says, it never names the deployment's state.
			if strings.Contains(rec.Body.String(), testDecisionID) {
				t.Fatalf("the page names the decision: %s", rec.Body.String())
			}
		})
	}
}

// TestMFARedirectRefusesAnUnverifiableRedemption: a token the pinned issuer set
// does not accept ends the round, and the reason is not narrated.
func TestMFARedirectRefusesAnUnverifiableRedemption(t *testing.T) {
	t.Parallel()
	f := newMFAFixture(t)
	f.verifier.err = identity.ErrSignatureInvalid
	rec := f.land(t, api.SurfaceCallback, "code=c&state=s")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if f.collector.submitted() != 0 {
		t.Fatal("an unverifiable redemption reached the decision service")
	}
	if strings.Contains(rec.Body.String(), "signature") {
		t.Fatalf("the page narrated the verification failure: %s", rec.Body.String())
	}
}

// TestMFARedirectTakesAParameterOnceEvenWhenItIsSentTwice: a duplicated `state`
// is a request with two answers, and the comparison downstream has to be against
// one of them rather than against a joined string.
func TestMFARedirectTakesAParameterOnceEvenWhenItIsSentTwice(t *testing.T) {
	t.Parallel()
	f := newMFAFixture(t)
	if rec := f.land(t, api.SurfaceCallback, "code=c&state=first&state=second"); rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if got := f.redeemer.lastCallback(t).Params["state"]; got != "first" {
		t.Fatalf("state = %q, want the first value", got)
	}
}

// TestMFARedirectRefusesAMalformedPath: the ordinal is part of what identifies
// the challenge, so a path that does not name one is refused the way an unknown
// decision is rather than reported as a different kind of wrong.
func TestMFARedirectRefusesAMalformedPath(t *testing.T) {
	t.Parallel()
	f := newMFAFixture(t)
	req := httptest.NewRequest(http.MethodGet,
		"/decisions/"+testDecisionID+"/challenges/not-a-number/mfa?code=c&state=s", http.NoBody)
	rec := httptest.NewRecorder()
	f.server.Handler(api.SurfaceCallback).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want a uniform 403", rec.Code)
	}
	if f.redeemer.redeemed() != 0 {
		t.Fatal("a malformed path reached the redemption path")
	}
}

// TestMFAPostDoesNotGoThroughTheRedemptionSeam keeps the CIBA path intact: D26
// left the CIBA client as a contract verified against a mock OP, and that mock
// hands its token back through the POST route with nothing to redeem.
func TestMFAPostDoesNotGoThroughTheRedemptionSeam(t *testing.T) {
	t.Parallel()
	f := newMFAFixture(t)
	if rec := f.post(t, api.SurfaceCallback, completionBody("c", "a.b.c")); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if f.redeemer.redeemed() != 0 {
		t.Fatal("the post path went through the redemption seam")
	}
}
