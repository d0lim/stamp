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
	"sync"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/store"
	"github.com/d0lim/stamp/internal/stream"
)

// The approval surface owns three things and no more: it puts the endpoint on
// the console listener behind an end-user credential, it takes the approver
// from the verified token rather than from the body, and it turns the
// collection layer's sentinels into statuses a console can act on. These tests
// exercise exactly that, against a real token boundary and a recording
// collector — what the quorum handler does with a submission is tested where
// the database is.

const (
	testDecisionID = "3f1b0f2a-0000-4000-8000-000000000001"
	approvalPath   = "/decisions/" + testDecisionID + "/challenges/0/approvals"
	reviewPath     = "/decisions/" + testDecisionID + "/challenges/0/approval"
)

// recordingCollector stands in for the decision service. It records what
// arrived and answers with whatever the test set.
type recordingCollector struct {
	mu sync.Mutex

	submissions []decision.Submission
	reviews     []challenge.QuorumReviewRequest

	result    decision.Result
	submitErr error

	review    challenge.QuorumReview
	reviewErr error
}

func (c *recordingCollector) Submit(_ context.Context, sub decision.Submission) (decision.Result, error) {
	c.mu.Lock()
	c.submissions = append(c.submissions, sub)
	c.mu.Unlock()
	if c.submitErr != nil {
		return decision.Result{}, c.submitErr
	}
	return c.result, nil
}

func (c *recordingCollector) Review(_ context.Context, req challenge.QuorumReviewRequest) (challenge.QuorumReview, error) {
	c.mu.Lock()
	c.reviews = append(c.reviews, req)
	c.mu.Unlock()
	if c.reviewErr != nil {
		return challenge.QuorumReview{}, c.reviewErr
	}
	return c.review, nil
}

func (c *recordingCollector) lastSubmission(t *testing.T) decision.Submission {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.submissions) == 0 {
		t.Fatal("nothing reached the collector")
	}
	return c.submissions[len(c.submissions)-1]
}

func (c *recordingCollector) submitted() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.submissions)
}

// approvalFixture is a console surface with the approval routes mounted.
type approvalFixture struct {
	server    *api.Server
	idp       *mockIdP
	collector *recordingCollector
	audit     *recordingEvents
	clock     *decideClock
}

// approvalOptions are the knobs a test turns. Zero is the deployment default
// for each, which is what most of these tests want to exercise.
type approvalOptions struct {
	maxBytes int64
	rate     stream.RateLimit
}

func newApprovalFixture(t *testing.T) *approvalFixture {
	t.Helper()
	// A budget large enough not to be the limit under test, so that a test about
	// the approver boundary is not silently also a test about the rate.
	return newApprovalFixtureWith(t, approvalOptions{rate: generous})
}

func newApprovalFixtureWith(t *testing.T, opts approvalOptions) *approvalFixture {
	t.Helper()
	idp := newMockIdP(t)
	sink := identity.AuditSinkFunc(func(context.Context, identity.AuthRecord) {})
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
		result: decision.Result{ID: testDecisionID, State: store.DecisionPending},
	}
	audit := &recordingEvents{}
	clock := &decideClock{at: fixedNow}
	approvals, err := api.NewApprovals(api.ApprovalsConfig{
		Decisions:       collector,
		Reviews:         collector,
		MaxRequestBytes: opts.maxBytes,
		Rate:            opts.rate,
		Audit:           audit,
		Now:             clock.Now,
	})
	if err != nil {
		t.Fatalf("build approvals: %v", err)
	}
	if err := server.Mount(approvals); err != nil {
		t.Fatalf("mount approvals: %v", err)
	}
	return &approvalFixture{server: server, idp: idp, collector: collector, audit: audit, clock: clock}
}

// userToken mints an end-user token: a client the operator did not declare as a
// workload client is a person.
func (f *approvalFixture) userToken(t *testing.T, subject string) string {
	t.Helper()
	return f.idp.token(t, subject, "console")
}

func (f *approvalFixture) do(t *testing.T, surface api.Surface, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader = http.NoBody
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.server.Handler(surface).ServeHTTP(rec, req)
	return rec
}

func (f *approvalFixture) approve(t *testing.T, subject, body string) *httptest.ResponseRecorder {
	t.Helper()
	return f.do(t, api.SurfaceConsole, http.MethodPost, approvalPath, f.userToken(t, subject), body)
}

// The approval endpoint is a console endpoint behind an end-user credential.
// The mount table is what makes that true, so the assertion is on the routes.
func TestApprovalRoutesAreConsoleOnlyAndUserAuthenticated(t *testing.T) {
	t.Parallel()
	approvals, err := api.NewApprovals(api.ApprovalsConfig{
		Decisions: &recordingCollector{},
		Reviews:   &recordingCollector{},
	})
	if err != nil {
		t.Fatalf("build approvals: %v", err)
	}
	routes := approvals.Routes()
	if len(routes) == 0 {
		t.Fatal("the approval surface offers no routes")
	}
	for _, route := range routes {
		if route.Surface != api.SurfaceConsole {
			t.Errorf("route %q is on the %s surface, want console", route.Name, route.Surface)
		}
		if route.Auth != api.AuthUser {
			t.Errorf("route %q asks for %q, want an end-user credential", route.Name, route.Auth)
		}
	}
}

// A route mounted on the console is not reachable on the PEP listener. That is
// the surface split: another router has simply never heard of the path.
func TestApprovalPathIsNotReachableOnThePEPSurface(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	rec := f.do(t, api.SurfacePEP, http.MethodPost, approvalPath, f.userToken(t, "bob"), "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("the PEP surface answered %d for a console path, want 404", rec.Code)
	}
	if f.collector.submitted() != 0 {
		t.Fatal("a request to the wrong surface reached the collector")
	}
}

// R40 at the door: no credential, no submission.
func TestUnauthenticatedSubmissionIsRefusedBeforeTheCollector(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	rec := f.do(t, api.SurfaceConsole, http.MethodPost, approvalPath, "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated submission answered %d, want 401", rec.Code)
	}
	if f.collector.submitted() != 0 {
		t.Fatal("an unauthenticated submission reached the collector")
	}
}

// A workload credential is not an approver, and the console listener is where
// that is settled — before any handler runs.
func TestWorkloadCredentialCannotApprove(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	rec := f.do(t, api.SurfaceConsole, http.MethodPost, approvalPath,
		f.idp.token(t, "bob", testClientID), "")
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("workload credential on the console answered %d, want a refusal", rec.Code)
	}
	if f.collector.submitted() != 0 {
		t.Fatal("a workload submission reached the collector")
	}
}

// The approver is the token's subject. A body naming somebody else changes
// nothing about who the collector is told is approving.
func TestApproverComesFromTheTokenNotTheBody(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	rec := f.approve(t, "bob", `{"approver":"carol"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("submission answered %d: %s", rec.Code, rec.Body.String())
	}
	sub := f.collector.lastSubmission(t)
	if sub.Caller == nil || sub.Caller.ID != "bob" {
		t.Fatalf("the collector was told the approver is %#v, want the token's sub", sub.Caller)
	}
	if sub.Caller.Kind != identity.SubjectUser {
		t.Fatalf("the approver reached the collector as a %s", sub.Caller.Kind)
	}
	// The body is forwarded verbatim: judging it is the handler's job, and the
	// handler is the thing that knows an unknown member is a refusal.
	if !strings.Contains(string(sub.Payload), "carol") {
		t.Fatalf("the payload the collector saw was %q, want the body verbatim", sub.Payload)
	}
}

// The path names the decision and the challenge.
func TestSubmissionCarriesTheDecisionAndOrdinalFromThePath(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	rec := f.do(t, api.SurfaceConsole, http.MethodPost,
		"/decisions/"+testDecisionID+"/challenges/3/approvals", f.userToken(t, "bob"), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("submission answered %d: %s", rec.Code, rec.Body.String())
	}
	sub := f.collector.lastSubmission(t)
	if sub.DecisionID != testDecisionID {
		t.Fatalf("collector saw decision %q", sub.DecisionID)
	}
	if sub.Ordinal != 3 {
		t.Fatalf("collector saw ordinal %d, want 3", sub.Ordinal)
	}
}

func TestNonNumericOrdinalIsRefused(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	for _, ordinal := range []string{"first", "-1", "1.5"} {
		rec := f.do(t, api.SurfaceConsole, http.MethodPost,
			"/decisions/"+testDecisionID+"/challenges/"+ordinal+"/approvals", f.userToken(t, "bob"), "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("ordinal %q answered %d, want 400", ordinal, rec.Code)
		}
	}
	if f.collector.submitted() != 0 {
		t.Fatal("a malformed ordinal reached the collector")
	}
}

// Every refusal the collection layer can produce has to reach a console as
// something it can act on. A 500 for "you are not an approver" would tell an
// operator to page somebody.
func TestCollectorErrorsBecomeActionableStatuses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{name: "not a target", err: fmt.Errorf("wrapped: %w", challenge.ErrNotTarget), want: http.StatusForbidden},
		{name: "not entitled", err: decision.ErrNotAuthorized, want: http.StatusForbidden},
		{name: "no such challenge", err: decision.ErrNoSuchChallenge, want: http.StatusNotFound},
		{name: "no such decision", err: store.ErrNotFound, want: http.StatusNotFound},
		{name: "already resolved", err: decision.ErrNotPending, want: http.StatusConflict},
		{name: "expired", err: store.ErrDecisionExpired, want: http.StatusConflict},
		{name: "material changed", err: challenge.ErrBindingChanged, want: http.StatusConflict},
		{name: "unreadable payload", err: challenge.ErrInvalidPayload, want: http.StatusBadRequest},
		{name: "rejection verdict", err: challenge.ErrVerdictUnsupported, want: http.StatusBadRequest},
		{name: "takes no submissions", err: challenge.ErrNotSubmittable, want: http.StatusConflict},
		{name: "group source", err: challenge.ErrGroupSourceUnsupported, want: http.StatusNotImplemented},
		{name: "no handler", err: challenge.ErrNoHandler, want: http.StatusNotImplemented},
		{name: "anything else", err: errors.New("the database fell over"), want: http.StatusInternalServerError},
	} {
		f := newApprovalFixture(t)
		f.collector.submitErr = tc.err
		rec := f.approve(t, "bob", "")
		if rec.Code != tc.want {
			t.Errorf("%s: answered %d, want %d", tc.name, rec.Code, tc.want)
		}
		var body api.ErrorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Errorf("%s: response %q is not an error body: %v", tc.name, rec.Body.String(), err)
			continue
		}
		if body.Error == "" {
			t.Errorf("%s: error body carries no code", tc.name)
		}
		// An internal failure must not narrate itself to a console user.
		if tc.want == http.StatusInternalServerError && strings.Contains(body.Message, "database fell over") {
			t.Errorf("%s: the response leaked the internal error: %q", tc.name, body.Message)
		}
	}
}

// A successful submission answers with the decision as it now stands, because
// the approver's next question is whether that was the last one needed.
func TestSuccessfulSubmissionReturnsTheDecision(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	f.collector.result = decision.Result{
		ID:    testDecisionID,
		State: store.DecisionAllowed,
		Challenges: []decision.ChallengeView{
			{Ordinal: 0, Kind: "quorum", State: challenge.StateSatisfied, Have: 2, Need: 2},
		},
	}
	rec := f.approve(t, "bob", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("submission answered %d: %s", rec.Code, rec.Body.String())
	}
	var got decision.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	if got.State != store.DecisionAllowed {
		t.Fatalf("response state %q, want allowed", got.State)
	}
	if len(got.Challenges) != 1 || got.Challenges[0].Have != 2 {
		t.Fatalf("response challenges %#v", got.Challenges)
	}
}

// The review is what hands the approver the hash their approval will be
// recorded against (R31).
func TestReviewHandsTheApproverTheBindingHash(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	f.collector.review = challenge.QuorumReview{
		Ordinal:     0,
		State:       challenge.StatePending,
		Have:        1,
		Need:        2,
		Approvers:   []string{"bob", "carol"},
		Mode:        challenge.ResolveMembers,
		BindingHash: "b0a1",
		Decision:    challenge.QuorumReviewDecision{ID: testDecisionID, Action: "transfer"},
	}
	rec := f.do(t, api.SurfaceConsole, http.MethodGet, reviewPath, f.userToken(t, "bob"), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("review answered %d: %s", rec.Code, rec.Body.String())
	}
	var got challenge.QuorumReview
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode review %q: %v", rec.Body.String(), err)
	}
	if got.BindingHash != "b0a1" {
		t.Fatalf("review handed over hash %q", got.BindingHash)
	}
	if got.Need != 2 || got.Have != 1 {
		t.Fatalf("review reported %d/%d", got.Have, got.Need)
	}
	if len(f.collector.reviews) != 1 || f.collector.reviews[0].Subject.ID != "bob" {
		t.Fatalf("the reviewer the collector saw was %#v", f.collector.reviews)
	}
}

// A reader the challenge is not waiting on gets nothing, including no hint that
// the decision exists.
func TestReviewRefusedToANonTarget(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	f.collector.reviewErr = challenge.ErrNotTarget
	rec := f.do(t, api.SurfaceConsole, http.MethodGet, reviewPath, f.userToken(t, "mallory"), "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("review answered %d, want 403", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// the submission budget (R43)
// ---------------------------------------------------------------------------

// TestSubmissionsAreRefusedOverTheApproverBudget is R43's submission half.
//
// Its refusal is a 4xx, which the other two budgets this unit added are not, and
// that difference is deliberate. A challenge issue has no HTTP response of its
// own to carry a status code — the caller there is a PEP asking for a decision —
// so a refusal can only be challenge state. This one is answering a console over
// a request the approver made themselves, so it is answered where they asked.
//
// The refusal must also happen before the lifecycle is touched, because what a
// submission costs behind this door is a row lock on the decision; a limit
// applied after that has limited nothing.
func TestSubmissionsAreRefusedOverTheApproverBudget(t *testing.T) {
	t.Parallel()
	const burst = 3
	f := newApprovalFixtureWith(t, approvalOptions{
		rate: stream.RateLimit{PerSecond: 1, Burst: burst},
	})

	for i := range burst {
		if rec := f.approve(t, "bob", ""); rec.Code != http.StatusOK {
			t.Fatalf("submission %d within the burst = %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	rec := f.approve(t, "bob", "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the submission past the burst = %d, want 429: %s", rec.Code, rec.Body.String())
	}
	if f.collector.submitted() != burst {
		t.Errorf("%d submissions reached the lifecycle, want %d: the refusal happened behind the row lock",
			f.collector.submitted(), burst)
	}

	// The code is the console's, and it is its own code: a caller has to be able
	// to tell "slow down" from "you are not an approver" and from "the decision
	// changed", both of which are also refusals with a body.
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if body.Error != api.ApprovalRateLimitedCode {
		t.Errorf("error code = %q, want %q", body.Error, api.ApprovalRateLimitedCode)
	}

	// And it is audited, with its own ground: an operator reading the chain has
	// to be able to tell an approver who was shed from a PEP that was.
	var refusals []api.Event
	for _, e := range f.audit.snapshot() {
		if e.Kind == api.EventRateLimited {
			refusals = append(refusals, e)
		}
	}
	if len(refusals) != 1 {
		t.Fatalf("%d rate-limit events were recorded, want 1", len(refusals))
	}
	got := refusals[0]
	switch {
	case got.Reason != api.ApprovalRateLimitedReason:
		t.Errorf("audited reason = %q, want %q", got.Reason, api.ApprovalRateLimitedReason)
	case got.Reason == string(decision.ReasonRateLimited):
		t.Error("the approval refusal is indistinguishable from the decide path's")
	}
	if got.CallerID == "" || !strings.Contains(got.CallerID, "bob") {
		t.Errorf("audited caller = %q, want the approver's identifier", got.CallerID)
	}
	if got.Path != approvalPath || got.Method != http.MethodPost {
		t.Errorf("audited request = %s %s, want POST %s", got.Method, got.Path, approvalPath)
	}
	if got.Limit == "" || got.Scope == "" {
		t.Errorf("audited scope/limit = %q/%q, want both: a reader cannot tell which budget bound", got.Scope, got.Limit)
	}
}

// TestTheApprovalBudgetIsPerApproverAndRefills guards the key and the recovery.
// A budget shared across approvers would let one flooding console user stop
// everybody else approving, which is the limit becoming the incident.
func TestTheApprovalBudgetIsPerApproverAndRefills(t *testing.T) {
	t.Parallel()
	const burst = 2
	f := newApprovalFixtureWith(t, approvalOptions{
		rate: stream.RateLimit{PerSecond: 1, Burst: burst},
	})

	for range burst {
		if rec := f.approve(t, "bob", ""); rec.Code != http.StatusOK {
			t.Fatalf("submission within the burst = %d", rec.Code)
		}
	}
	if rec := f.approve(t, "bob", ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the submission past the burst = %d, want 429", rec.Code)
	}
	if rec := f.approve(t, "carol", ""); rec.Code != http.StatusOK {
		t.Fatalf("a second approver's first submission = %d: one approver spent another's budget", rec.Code)
	}

	f.clock.Advance(time.Second)
	if rec := f.approve(t, "bob", ""); rec.Code != http.StatusOK {
		t.Fatalf("a full refill window later the submission = %d, want 200", rec.Code)
	}
}

// A body big enough to be an attack is refused before it is parsed.
func TestOversizedSubmissionIsRefused(t *testing.T) {
	t.Parallel()
	f := newApprovalFixtureWith(t, approvalOptions{maxBytes: 64, rate: generous})
	rec := f.approve(t, "bob", `{"binding_hash":"`+strings.Repeat("a", 200)+`"}`)
	if rec.Code != http.StatusRequestEntityTooLarge && rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body answered %d, want a refusal", rec.Code)
	}
	if f.collector.submitted() != 0 {
		t.Fatal("an oversized body reached the collector")
	}
}
