package api_test

import (
	"bytes"
	"context"
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

// The cancellation endpoint is the delay's console side. What it owns is small
// and each piece is asserted here: it is a console route behind an end-user
// credential, the canceller is the token's subject, and the action the handler
// receives is the one the path already stated rather than one a body claimed.

const cancelPath = "/decisions/" + testDecisionID + "/challenges/0/cancellation"

type cancelFixture struct {
	server    *api.Server
	idp       *mockIdP
	collector *recordingCollector
}

func newCancelFixture(t *testing.T) *cancelFixture {
	t.Helper()
	idp := newMockIdP(t)
	sink := identity.AuditSinkFunc(func(_ context.Context, _ identity.AuthRecord) {})
	server, err := api.New(api.Config{
		Identity: idp.middleware(t, sink, func() time.Time { return fixedNow }),
		Addresses: map[api.Surface]string{
			api.SurfacePEP:     "127.0.0.1:0",
			api.SurfaceConsole: "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	collector := &recordingCollector{
		result: decision.Result{ID: testDecisionID, State: store.DecisionDenied},
	}
	cancellations, err := api.NewCancellations(api.CancellationsConfig{Decisions: collector})
	if err != nil {
		t.Fatalf("build cancellations: %v", err)
	}
	if err := server.Mount(cancellations); err != nil {
		t.Fatalf("mount cancellations: %v", err)
	}
	return &cancelFixture{server: server, idp: idp, collector: collector}
}

func (f *cancelFixture) post(t *testing.T, surface api.Surface, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader = http.NoBody
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(http.MethodPost, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.server.Handler(surface).ServeHTTP(rec, req)
	return rec
}

func TestCancellationRouteIsConsoleOnlyAndUserAuthenticated(t *testing.T) {
	t.Parallel()
	cancellations, err := api.NewCancellations(api.CancellationsConfig{Decisions: &recordingCollector{}})
	if err != nil {
		t.Fatalf("build cancellations: %v", err)
	}
	routes := cancellations.Routes()
	if len(routes) != 1 {
		t.Fatalf("the cancellation surface offers %d routes, want 1", len(routes))
	}
	if routes[0].Surface != api.SurfaceConsole || routes[0].Auth != api.AuthUser {
		t.Fatalf("route %q is %s/%s, want console/user", routes[0].Name, routes[0].Surface, routes[0].Auth)
	}
}

// The endpoint states the action, so the handler is never asked to work out
// what an empty or surprising body meant.
func TestCancellationSendsTheCancelActionAndTheTokensSubject(t *testing.T) {
	t.Parallel()
	f := newCancelFixture(t)

	rec := f.post(t, api.SurfaceConsole, cancelPath, f.idp.token(t, "carol", "console"),
		`{"action":"approve","approver":"mallory"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	sub := f.collector.lastSubmission(t)
	if sub.DecisionID != testDecisionID || sub.Ordinal != 0 {
		t.Fatalf("submission named %s#%d", sub.DecisionID, sub.Ordinal)
	}
	if string(sub.Payload) != string(challenge.DelayCancelPayload()) {
		t.Fatalf("payload = %s, want the cancel action the route stands for", sub.Payload)
	}
	if sub.Caller == nil || sub.Caller.ID != "carol" {
		t.Fatalf("canceller = %+v, want the token's subject", sub.Caller)
	}
}

func TestUnauthenticatedCancellationIsRefusedBeforeTheCollector(t *testing.T) {
	t.Parallel()
	f := newCancelFixture(t)

	rec := f.post(t, api.SurfaceConsole, cancelPath, "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if f.collector.submitted() != 0 {
		t.Fatal("an unauthenticated cancellation reached the collector")
	}
}

// A workload credential cannot cancel, and the refusal happens at the door
// rather than in the handler: the console listener admits end-user tokens only.
func TestWorkloadCredentialCannotCancel(t *testing.T) {
	t.Parallel()
	f := newCancelFixture(t)

	rec := f.post(t, api.SurfaceConsole, cancelPath, f.idp.token(t, "pep-1", testClientID), "")
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want the workload turned away", rec.Code)
	}
	if f.collector.submitted() != 0 {
		t.Fatal("a workload credential reached the collector")
	}
}

// Somebody who does not hold the authority is told the same thing they would be
// told about a decision that does not exist — and "the same thing" is the whole
// response, not the same shape of one.
//
// The cancellation surface borrows the approval surface's table, so this is the
// second place #38's answer had to hold. It matters here in its own right: a
// cancellation authority is named by the policy, so telling a stranger "not you"
// would confirm both that the decision exists and that it is waiting on
// somebody.
func TestCancellationByANonAuthorityIsIndistinguishableFromAMissingDecision(t *testing.T) {
	t.Parallel()

	cancel := func(t *testing.T, err error) *httptest.ResponseRecorder {
		t.Helper()
		f := newCancelFixture(t)
		f.collector.submitErr = err
		return f.post(t, api.SurfaceConsole, cancelPath, f.idp.token(t, "mallory", "console"), "")
	}

	base := cancel(t, store.ErrNotFound)
	if base.Code != http.StatusNotFound {
		t.Fatalf("a decision that does not exist = %d, want 404: %s", base.Code, base.Body.String())
	}
	refused := cancel(t, challenge.ErrNotTarget)
	if refused.Code != base.Code {
		t.Errorf("a non-authority = %d, a missing decision = %d", refused.Code, base.Code)
	}
	if !bytes.Equal(refused.Body.Bytes(), base.Body.Bytes()) {
		t.Errorf("body\n got %q\nwant %q", refused.Body.String(), base.Body.String())
	}
}

// A wait whose timer already ran out is not cancellable, and the lifecycle says
// so before the handler is reached. The surface has to turn that into something
// a console can act on rather than a 500.
func TestCancellationAfterTheWaitEndedIsAConflict(t *testing.T) {
	t.Parallel()
	f := newCancelFixture(t)
	f.collector.submitErr = store.ErrDecisionExpired

	rec := f.post(t, api.SurfaceConsole, cancelPath, f.idp.token(t, "carol", "console"), "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

func TestCancellationPathIsNotReachableOnThePEPSurface(t *testing.T) {
	t.Parallel()
	f := newCancelFixture(t)
	rec := f.post(t, api.SurfacePEP, cancelPath, f.idp.token(t, "carol", "console"), "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("the PEP surface answered %d for a console path, want 404", rec.Code)
	}
}
