package api_test

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/d0lim/stamp/internal/stream"
)

// The cancellation endpoint is the delay's console side. What it owns is small
// and each piece is asserted here: it is a console route behind an end-user
// credential, the canceller is the token's subject, the action the handler
// receives is the one the path already stated rather than one a body claimed,
// and — since U1 — an authority's attempts are charged against a budget before
// any of that happens.

const cancelPath = "/decisions/" + testDecisionID + "/challenges/0/cancellation"

type cancelFixture struct {
	server    *api.Server
	idp       *mockIdP
	collector *recordingCollector
	audit     *recordingEvents
	clock     *decideClock
}

// cancelOptions are the knobs a test turns. A zero rate is the deployment
// default, which is what the tests about the default exercise.
type cancelOptions struct {
	rate stream.RateLimit
}

func newCancelFixture(t *testing.T) *cancelFixture {
	t.Helper()
	// A budget large enough not to be the limit under test, so that a test about
	// the authority boundary is not silently also a test about the rate.
	return newCancelFixtureWith(t, cancelOptions{rate: generous})
}

func newCancelFixtureWith(t *testing.T, opts cancelOptions) *cancelFixture {
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
	audit := &recordingEvents{}
	clock := &decideClock{at: fixedNow}
	cancellations, err := api.NewCancellations(api.CancellationsConfig{
		Decisions: collector,
		Rate:      opts.rate,
		Audit:     audit,
		Now:       clock.Now,
	})
	if err != nil {
		t.Fatalf("build cancellations: %v", err)
	}
	if err := server.Mount(cancellations); err != nil {
		t.Fatalf("mount cancellations: %v", err)
	}
	return &cancelFixture{server: server, idp: idp, collector: collector, audit: audit, clock: clock}
}

// cancel posts one cancellation as an end-user.
func (f *cancelFixture) cancel(t *testing.T, subject string) *httptest.ResponseRecorder {
	t.Helper()
	return f.post(t, api.SurfaceConsole, cancelPath, f.idp.token(t, subject, "console"), "")
}

// rateEvents is the rate-limit refusals this surface recorded.
func (f *cancelFixture) rateEvents() []api.Event {
	var out []api.Event
	for _, e := range f.audit.snapshot() {
		if e.Kind == api.EventRateLimited {
			out = append(out, e)
		}
	}
	return out
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

// ---------------------------------------------------------------------------
// the cancellation budget (R43)
// ---------------------------------------------------------------------------

// TestCancellationsAreRefusedOverTheAuthorityBudget is R43's fifth surface.
//
// The refusal is a 429 and not the decide path's 200 carrying a denied decision,
// because there is no decision here to carry one: a cancellation resolves a
// decision that already exists and creates nothing. What is on the other end is
// a person at a console, over a request they made themselves, about an action
// they can simply do again.
func TestCancellationsAreRefusedOverTheAuthorityBudget(t *testing.T) {
	t.Parallel()
	const burst = 3
	f := newCancelFixtureWith(t, cancelOptions{rate: stream.RateLimit{PerSecond: 1, Burst: burst}})

	for i := range burst {
		if rec := f.cancel(t, "carol"); rec.Code != http.StatusOK {
			t.Fatalf("attempt %d within the burst = %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	rec := f.cancel(t, "carol")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the attempt past the burst = %d, want 429: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if body.Error != api.CancellationRateLimitedCode {
		t.Errorf("error code = %q, want %q", body.Error, api.CancellationRateLimitedCode)
	}

	// And it says when to come back. The header is in the place RFC 9110 defines
	// it — this is a 429 — so a console with a retry button and everything
	// between it and here read the same number: one token a second is this
	// budget's refill interval.
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want %q — this budget's refill interval", got, "1")
	}
}

// TestARefusedCancellationIsAuditedUnderItsOwnGround is what an operator reading
// the chain needs. Five write surfaces can shed and the record has to say which
// one did: the settings that raise them are five different variables and a
// reader who cannot tell an authority hammering a cancellation from an approver
// submitting too often will reach for the wrong one.
func TestARefusedCancellationIsAuditedUnderItsOwnGround(t *testing.T) {
	t.Parallel()
	const burst = 1
	f := newCancelFixtureWith(t, cancelOptions{rate: stream.RateLimit{PerSecond: 1, Burst: burst}})

	if rec := f.cancel(t, "carol"); rec.Code != http.StatusOK {
		t.Fatalf("the first attempt = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := f.cancel(t, "carol"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the attempt past the burst = %d, want 429", rec.Code)
	}

	refusals := f.rateEvents()
	if len(refusals) != 1 {
		t.Fatalf("%d rate-limit events were recorded, want 1", len(refusals))
	}
	got := refusals[0]
	switch {
	case got.Reason != api.CancellationRateLimitedReason:
		t.Errorf("audited reason = %q, want %q", got.Reason, api.CancellationRateLimitedReason)
	case got.Reason == api.ApprovalRateLimitedReason:
		t.Error("the cancellation refusal is indistinguishable from the approval surface's")
	case got.Reason == string(decision.ReasonRateLimited):
		t.Error("the cancellation refusal is indistinguishable from the decide path's")
	}
	if got.CallerID == "" || !strings.Contains(got.CallerID, "carol") {
		t.Errorf("audited caller = %q, want the authority's identifier", got.CallerID)
	}
	if got.Path != cancelPath || got.Method != http.MethodPost {
		t.Errorf("audited request = %s %s, want POST %s", got.Method, got.Path, cancelPath)
	}
	if got.Limit == "" || got.Scope == "" {
		t.Errorf("audited scope/limit = %q/%q, want both: a reader cannot tell which budget bound",
			got.Scope, got.Limit)
	}
}

// TestACancellationOverTheBudgetNeverReachesTheLifecycle is the pair of this
// unit's red, at the surface where the charge is made.
//
// The collector stands in for decision.Service, and the error it answers with is
// the one a stranger gets: no standing on a decision that exists. Behind that
// call the lifecycle writes an access-refused entry through a synchronous chain
// append, so one call that reaches it is one append on the serialized write
// path — which is why the count that matters is how many calls got through and
// not how many requests arrived.
//
// The budget must be charged before the path is even parsed. A limit applied
// after the lifecycle has been asked has limited nothing.
func TestACancellationOverTheBudgetNeverReachesTheLifecycle(t *testing.T) {
	t.Parallel()
	const burst = 2
	f := newCancelFixtureWith(t, cancelOptions{rate: stream.RateLimit{PerSecond: 1, Burst: burst}})
	f.collector.submitErr = store.ErrNotFound

	const attempts = 10
	for i := range attempts {
		switch code := f.cancel(t, "mallory").Code; code {
		case http.StatusNotFound, http.StatusTooManyRequests:
		default:
			t.Fatalf("attempt %d answered %d, want 404 or 429", i, code)
		}
	}
	if got := f.collector.submitted(); got != burst {
		t.Fatalf("%d of %d attempts reached the lifecycle, want %d: each one past the "+
			"budget is a synchronous audit-chain append a console user got for free",
			got, attempts, burst)
	}
}

// TestTheCancellationBudgetIsPerAuthorityAndRefills guards the key and the
// recovery. A budget shared across authorities would let one flooding console
// user stop everybody else cancelling, and a cancellation is the thing that
// stops something already in motion — the direction of that coupling is exactly
// wrong.
func TestTheCancellationBudgetIsPerAuthorityAndRefills(t *testing.T) {
	t.Parallel()
	const burst = 2
	f := newCancelFixtureWith(t, cancelOptions{rate: stream.RateLimit{PerSecond: 1, Burst: burst}})

	for range burst {
		if rec := f.cancel(t, "carol"); rec.Code != http.StatusOK {
			t.Fatalf("an attempt within the burst = %d", rec.Code)
		}
	}
	if rec := f.cancel(t, "carol"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the attempt past the burst = %d, want 429", rec.Code)
	}
	if rec := f.cancel(t, "dave"); rec.Code != http.StatusOK {
		t.Fatalf("a second authority's first attempt = %d: one authority spent another's budget", rec.Code)
	}

	f.clock.Advance(time.Second)
	if rec := f.cancel(t, "carol"); rec.Code != http.StatusOK {
		t.Fatalf("a full refill window later the attempt = %d, want 200", rec.Code)
	}
}

// TestTheDefaultCancellationBudgetIsTighterThanTheApprovalOne is the one
// assertion that keeps the reasoning in DefaultCancellationRate's comment true.
//
// The claim there is that this surface is charged more tightly than approval
// submission because the action is rarer: an approver works a queue, an
// authority stops one wait once. A later edit that raised this to match approval
// submission would leave that paragraph describing a distinction the code no
// longer draws, and nothing else in the suite would notice.
//
// The behavioural half of it is below the constants: a deployment that
// configured nothing still has a budget, and it binds.
func TestTheDefaultCancellationBudgetIsTighterThanTheApprovalOne(t *testing.T) {
	t.Parallel()
	if api.DefaultCancellationRate.PerSecond >= api.DefaultApprovalRate.PerSecond {
		t.Errorf("the default cancellation rate is %g/s and the approval one is %g/s, want tighter",
			api.DefaultCancellationRate.PerSecond, api.DefaultApprovalRate.PerSecond)
	}
	if api.DefaultCancellationRate.Burst >= api.DefaultApprovalRate.Burst {
		t.Errorf("the default cancellation burst is %g and the approval one is %g, want tighter",
			api.DefaultCancellationRate.Burst, api.DefaultApprovalRate.Burst)
	}

	// A zero rate is a deployment that configured nothing, and it gets the
	// default rather than no limit.
	f := newCancelFixtureWith(t, cancelOptions{})
	attempts := int(api.DefaultCancellationRate.Burst) + 1
	var shed int
	for range attempts {
		if f.cancel(t, "carol").Code == http.StatusTooManyRequests {
			shed++
		}
	}
	if shed != 1 {
		t.Fatalf("%d of %d attempts were shed under the default budget, want 1: an "+
			"unconfigured deployment has no budget on this surface", shed, attempts)
	}
}
