package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/store"
)

// The callback surface has one job and two properties.
//
// The job is to hand a signed body to the challenge handler. It performs no
// verification of its own — the secret and the correlator live with the handler
// that issued them — and it establishes no identity, because the caller has no
// credential to establish one from.
//
// The properties are that it answers a retransmission the same way it answers a
// first delivery, and that it tells an unauthenticated caller nothing about
// which decisions exist. Those two pull in opposite directions from the usual
// REST reflex, so they are asserted rather than assumed.

const callbackPath = "/external/" + testDecisionID + "/0"

// callbackFixture is a callback listener with the external route mounted.
type callbackFixture struct {
	server    *api.Server
	collector *recordingCollector
}

func newCallbackFixture(t *testing.T) *callbackFixture {
	t.Helper()
	return newCallbackFixtureWith(t, 0)
}

func newCallbackFixtureWith(t *testing.T, maxBytes int64) *callbackFixture {
	t.Helper()
	idp := newMockIdP(t)
	sink := identity.AuditSinkFunc(func(_ context.Context, _ identity.AuthRecord) {})
	server, err := api.New(api.Config{
		Identity: idp.middleware(t, sink, func() time.Time { return fixedNow }),
		Addresses: map[api.Surface]string{
			api.SurfacePEP:      "127.0.0.1:0",
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
	callbacks, err := api.NewCallbacks(api.CallbacksConfig{Decisions: collector, MaxRequestBytes: maxBytes})
	if err != nil {
		t.Fatalf("build callbacks: %v", err)
	}
	if err := server.Mount(callbacks); err != nil {
		t.Fatalf("mount callbacks: %v", err)
	}
	return &callbackFixture{server: server, collector: collector}
}

func (f *callbackFixture) post(t *testing.T, surface api.Surface, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader = http.NoBody
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(http.MethodPost, path, reader)
	rec := httptest.NewRecorder()
	f.server.Handler(surface).ServeHTTP(rec, req)
	return rec
}

// The callback endpoint belongs on the listener a deployment may have to expose
// beyond its own perimeter, and it takes no credential there. The mount table
// is what makes both true.
func TestCallbackRouteIsOnTheCallbackSurfaceAndTakesNoCredential(t *testing.T) {
	t.Parallel()
	callbacks, err := api.NewCallbacks(api.CallbacksConfig{Decisions: &recordingCollector{}})
	if err != nil {
		t.Fatalf("build callbacks: %v", err)
	}
	routes := callbacks.Routes()
	if len(routes) != 1 {
		t.Fatalf("the callback surface offers %d routes, want 1", len(routes))
	}
	if routes[0].Surface != api.SurfaceCallback {
		t.Errorf("route %q is on the %s surface, want callback", routes[0].Name, routes[0].Surface)
	}
	if routes[0].Auth != api.AuthPublic {
		t.Errorf("route %q asks for %q, want public", routes[0].Name, routes[0].Auth)
	}
}

func TestCallbackIsNotReachableOnTheOtherSurfaces(t *testing.T) {
	t.Parallel()
	f := newCallbackFixture(t)
	for _, surface := range []api.Surface{api.SurfacePEP, api.SurfaceConsole} {
		rec := f.post(t, surface, callbackPath, `{"nonce":"aa"}`)
		if rec.Code != http.StatusNotFound {
			t.Errorf("the %s surface answered %d for a callback path, want 404", surface, rec.Code)
		}
	}
	if f.collector.submitted() != 0 {
		t.Fatal("a request to the wrong surface reached the collector")
	}
}

// The body is forwarded verbatim and the principal is not a credential the
// caller supplied: the caller supplied none.
func TestCallbackForwardsTheBodyAndNamesAWorkloadPrincipal(t *testing.T) {
	t.Parallel()
	f := newCallbackFixture(t)
	body := `{"nonce":"c0ffee","verdict":"approved","signature":"abcd"}`

	rec := f.post(t, api.SurfaceCallback, callbackPath, body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}

	sub := f.collector.lastSubmission(t)
	if sub.DecisionID != testDecisionID || sub.Ordinal != 0 {
		t.Fatalf("submission named %s#%d", sub.DecisionID, sub.Ordinal)
	}
	if string(sub.Payload) != body {
		t.Fatalf("payload = %s, want it forwarded verbatim", sub.Payload)
	}
	if sub.Caller == nil {
		t.Fatal("the submission carried no principal at all")
	}
	// A workload-kind principal is what makes every human-target handler
	// refuse this path: an approver is a person, and a callback is not one.
	if sub.Caller.Kind != identity.SubjectWorkload {
		t.Fatalf("callback principal kind = %q, want %q", sub.Caller.Kind, identity.SubjectWorkload)
	}
}

// A retransmission must not look like an error worth retrying, and a probe must
// not learn which decisions exist. Both come out of one table.
func TestCallbackAnswersWithoutTellingAStrangerAnything(t *testing.T) {
	t.Parallel()

	accepted := []struct {
		name string
		err  error
	}{
		{"a first delivery", nil},
		{"a challenge that already transitioned", decision.ErrNotPending},
		{"a decision that expired first", store.ErrDecisionExpired},
		{"a challenge that is not collecting", challenge.ErrNotSubmittable},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newCallbackFixture(t)
			f.collector.submitErr = tc.err
			rec := f.post(t, api.SurfaceCallback, callbackPath, `{"nonce":"c0ffee"}`)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want 202 so a sender stops retrying", rec.Code)
			}
		})
	}

	refused := []struct {
		name string
		err  error
	}{
		{"a forged signature", challenge.ErrNotTarget},
		{"a decision nobody has heard of", store.ErrNotFound},
		{"a challenge that is not there", decision.ErrNoSuchChallenge},
		{"an unreadable body", challenge.ErrInvalidPayload},
		{"a challenge kind this build cannot serve", challenge.ErrNoHandler},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newCallbackFixture(t)
			f.collector.submitErr = tc.err
			rec := f.post(t, api.SurfaceCallback, callbackPath, `{"nonce":"c0ffee"}`)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			// One body for every refusal: the difference between "no such
			// decision" and "bad signature" is exactly the difference a
			// prober is looking for.
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode error body: %v", err)
			}
			if fmt.Sprint(body["error"]) != "rejected" {
				t.Fatalf("error body = %v, want a uniform refusal", body)
			}
		})
	}
}

// An internal failure is the one case the caller should retry, and it is the
// one case that is not a 4xx.
func TestCallbackReportsAnInternalFailureAsOne(t *testing.T) {
	t.Parallel()
	f := newCallbackFixture(t)
	f.collector.submitErr = errors.New("the database is on fire")
	rec := f.post(t, api.SurfaceCallback, callbackPath, `{"nonce":"c0ffee"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "on fire") {
		t.Fatalf("the error narrated itself to an unauthenticated caller: %s", rec.Body.String())
	}
}

func TestCallbackRefusesAMalformedPathAndAnOversizedBody(t *testing.T) {
	t.Parallel()
	f := newCallbackFixtureWith(t, 32)

	rec := f.post(t, api.SurfaceCallback, "/external/"+testDecisionID+"/-1", `{}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a negative ordinal answered %d, want 403", rec.Code)
	}
	if f.collector.submitted() != 0 {
		t.Fatal("a malformed path reached the collector")
	}

	rec = f.post(t, api.SurfaceCallback, callbackPath, `{"nonce":"`+strings.Repeat("a", 128)+`"}`)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized body answered %d, want 413", rec.Code)
	}
	if f.collector.submitted() != 0 {
		t.Fatal("an oversized body reached the collector")
	}
}
