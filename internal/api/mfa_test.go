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

type mfaFixture struct {
	server    *api.Server
	collector *recordingCollector
	verifier  *stubVerifier
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

	surface, err := api.NewMFA(api.MFAConfig{Decisions: collector, Tokens: verifier})
	if err != nil {
		t.Fatalf("build mfa surface: %v", err)
	}
	if err := server.Mount(surface); err != nil {
		t.Fatalf("mount mfa surface: %v", err)
	}
	return &mfaFixture{server: server, collector: collector, verifier: verifier}
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

	mounted := f.server.Mounted(api.SurfaceCallback)
	if len(mounted) != 1 {
		t.Fatalf("mounted %d routes on the callback surface, want 1", len(mounted))
	}
	if mounted[0].Auth != api.AuthPublic {
		t.Fatalf("route auth = %q, want public: the credential arrives in the body", mounted[0].Auth)
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
	if _, err := api.NewMFA(api.MFAConfig{Decisions: &recordingCollector{}}); err == nil {
		t.Fatal("an mfa surface was built with no token verifier")
	}
}
