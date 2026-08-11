package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
	"github.com/d0lim/stamp/internal/stream"
)

// The decide surface owns four things and no more: it puts the two endpoints on
// the PEP listener behind a workload credential, it turns an AuthZEN body plus a
// lifetime into the input the check surface would have built from the same body,
// it takes the caller from the verified token, and it answers every refusal of a
// read with one indistinguishable answer.
//
// What the lifecycle does with a request — the outstanding cap, the challenges,
// the audit rows, R40's rule itself — is tested where the database is. These
// tests are about the surface, so the lifecycle is a recorder.

const (
	// testDecideID is a well-formed decision identifier: the surface reads the
	// shape of one, so a made-up string would exercise the wrong branch.
	testDecideID  = "3f1b0f2a-0000-4000-8000-0000000000d1"
	otherDecideID = "3f1b0f2a-0000-4000-8000-0000000000d2"
)

// recordingDecider stands in for the decision lifecycle. It records what
// arrived and answers with whatever the test set.
type recordingDecider struct {
	mu sync.Mutex

	requests []decision.Request
	reads    []readCall

	result    decision.Result
	decideErr error

	view    decision.Result
	viewErr error
}

type readCall struct {
	callerID string
	id       string
}

func (d *recordingDecider) Decide(_ context.Context, req decision.Request) (decision.Result, error) {
	d.mu.Lock()
	d.requests = append(d.requests, req)
	d.mu.Unlock()
	if d.decideErr != nil {
		return decision.Result{}, d.decideErr
	}
	return d.result, nil
}

func (d *recordingDecider) Get(_ context.Context, caller *identity.Subject, id string) (decision.Result, error) {
	d.mu.Lock()
	d.reads = append(d.reads, readCall{callerID: caller.CallerID(), id: id})
	d.mu.Unlock()
	if d.viewErr != nil {
		return decision.Result{}, d.viewErr
	}
	return d.view, nil
}

func (d *recordingDecider) decided() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.requests)
}

func (d *recordingDecider) lastRequest(t *testing.T) decision.Request {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.requests) == 0 {
		t.Fatal("nothing reached the decision lifecycle")
	}
	return d.requests[len(d.requests)-1]
}

func (d *recordingDecider) lastRead(t *testing.T) readCall {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.reads) == 0 {
		t.Fatal("no read reached the decision lifecycle")
	}
	return d.reads[len(d.reads)-1]
}

// countingSchema is a policy schema source that answers with whatever it holds,
// including nothing — an instance that has not loaded a policy set yet is a
// state the surface has to answer for — and counts how often it was asked.
//
// The count is what lets a test assert that a refused request did no work: the
// schema read is the first step of turning a body into an evaluation input, so
// a request that never reached it never built one.
type countingSchema struct {
	schema *policy.Schema
	reads  atomic.Int64
}

func (s *countingSchema) Schema() *policy.Schema {
	s.reads.Add(1)
	return s.schema
}

// decideSchema declares the vocabulary these tests are written against: an
// account with a string number, an int amount and an `id`, so that the envelope
// identifier, a declared conversion and an undeclared property are all
// reachable in one request.
func decideSchema() *policy.Schema {
	return &policy.Schema{
		Entities: []policy.EntityType{
			{
				Name: "account",
				Attributes: []policy.Attribute{
					{Name: "id", Type: policy.TypeString},
					{Name: "number", Type: policy.TypeString},
					{Name: "amount", Type: policy.TypeInt},
				},
			},
			{
				Name: "request",
				Attributes: []policy.Attribute{
					{Name: "channel", Type: policy.TypeString},
				},
			},
		},
		Actions: []policy.Action{{Name: "transfer"}, {Name: "close"}},
	}
}

// recordingEvents is the audit seam the decide surface writes rate-limit
// refusals through. It is the interface and not an [api.AuditBuffer] so that a
// test reads back the event itself rather than a Merkle root it would have to
// recompute to say anything about.
type recordingEvents struct {
	mu     sync.Mutex
	events []api.Event
}

func (r *recordingEvents) Record(_ context.Context, e api.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recordingEvents) snapshot() []api.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]api.Event(nil), r.events...)
}

// decideClock is a hand-wound clock, so that a test about a budget refilling
// does not have to wait for it.
type decideClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *decideClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *decideClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

type decideFixture struct {
	server *api.Server
	idp    *mockIdP
	life   *recordingDecider
	audit  *recordingEvents
	clock  *decideClock
	schema *countingSchema
}

type decideOptions struct {
	schema        *policy.Schema
	noSchema      bool
	contextEntity string
	aliases       map[string]string
	maxBytes      int64
	maxTTL        time.Duration

	// The rate limits under test. A zero value takes the surface's defaults,
	// which is what every test that is not about rate limiting wants.
	rate           stream.RateLimit
	subjectRate    stream.RateLimit
	maxRateEntries int
}

func newDecideFixture(t *testing.T, opts decideOptions) *decideFixture {
	t.Helper()
	idp := newMockIdP(t)
	sink := identity.AuditSinkFunc(func(context.Context, identity.AuthRecord) {})
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

	life := &recordingDecider{
		result: decision.Result{ID: testDecideID, State: store.DecisionPending},
		view:   decision.Result{ID: testDecideID, State: store.DecisionPending},
	}
	schema := opts.schema
	if schema == nil && !opts.noSchema {
		schema = decideSchema()
	}
	schemas := &countingSchema{schema: schema}
	audit := &recordingEvents{}
	clock := &decideClock{at: fixedNow}
	decisions, err := api.NewDecisions(api.DecisionsConfig{
		Decisions:       life,
		Access:          life,
		Schema:          schemas,
		ContextEntity:   opts.contextEntity,
		PropertyAliases: opts.aliases,
		MaxRequestBytes: opts.maxBytes,
		MaxTTL:          opts.maxTTL,
		Audit:           audit,
		Rate:            opts.rate,
		SubjectRate:     opts.subjectRate,
		MaxRateEntries:  opts.maxRateEntries,
		Now:             clock.Now,
	})
	if err != nil {
		t.Fatalf("build decide api: %v", err)
	}
	if err := server.Mount(decisions); err != nil {
		t.Fatalf("mount: %v", err)
	}
	return &decideFixture{server: server, idp: idp, life: life, audit: audit, clock: clock, schema: schemas}
}

func (f *decideFixture) workload(t *testing.T, id string) string {
	t.Helper()
	return f.idp.token(t, id, testClientID)
}

// do issues one request against a surface and returns the recorder, so a test
// can compare whole responses rather than fields of them.
func (f *decideFixture) do(surface api.Surface, method, path, token, body string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	var req *http.Request
	if reader == nil {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, reader)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	f.server.Handler(surface).ServeHTTP(rec, req)
	return rec
}

func (f *decideFixture) create(t *testing.T, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	return f.do(api.SurfacePEP, http.MethodPost, api.DecisionsPath, token, body)
}

func (f *decideFixture) read(t *testing.T, token, id string) *httptest.ResponseRecorder {
	t.Helper()
	return f.do(api.SurfacePEP, http.MethodGet, api.DecisionsPath+"/"+id, token, "")
}

// decideBody is one decide request: the AuthZEN body the check surface takes,
// with whatever extra members the test adds.
func decideBody(extra string) string {
	body := `{
		"subject":  {"type": "account", "id": "acct-src", "properties": {"number": "1001"}},
		"resource": {"type": "account", "id": "acct-dst", "properties": {"amount": 5000}},
		"action":   {"name": "close"}`
	if extra != "" {
		body += ",\n\t\t" + extra
	}
	return body + "\n\t}"
}

// decideBodyFor is the same request about a named subject, for the tests that
// are about which budget a request spends.
func decideBodyFor(subjectID string) string {
	return `{
		"subject":  {"type": "account", "id": "` + subjectID + `", "properties": {"number": "1001"}},
		"resource": {"type": "account", "id": "acct-dst", "properties": {"amount": 5000}},
		"action":   {"name": "close"}
	}`
}

// ---------------------------------------------------------------------------
// R2: the decision object a create returns
// ---------------------------------------------------------------------------

// TestDecideReturnsTheWholeDecisionObject is R2 at the surface: the response
// carries the state, the challenges with their collection progress, the expiry
// and the obligations — everything a PEP needs to decide what to do next and to
// come back for the rest.
func TestDecideReturnsTheWholeDecisionObject(t *testing.T) {
	f := newDecideFixture(t, decideOptions{})
	deadline := fixedNow.Add(30 * time.Minute)
	f.life.result = decision.Result{
		ID:            testDecideID,
		State:         store.DecisionPending,
		Reason:        engine.ReasonChallengeRequired,
		PolicyID:      "closure-approval",
		PolicyVersion: 3,
		Obligations:   []decision.Obligation{{Type: "notify", Attributes: map[string]any{"channel": "ops"}}},
		Challenges: []decision.ChallengeView{{
			Ordinal: 0, Kind: policy.ChallengeQuorum, State: challenge.StatePending,
			Have: 0, Need: 2, Deadline: &deadline,
		}},
		CreatedAt: fixedNow,
		ExpiresAt: fixedNow.Add(time.Hour),
	}

	rec := f.create(t, f.workload(t, "svc-payments"), decideBody(""))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST %s = %d: %s", api.DecisionsPath, rec.Code, rec.Body.String())
	}
	// The identifier is followable without the caller having to build the path.
	if got := rec.Header().Get("Location"); got != api.DecisionsPath+"/"+testDecideID {
		t.Errorf("Location = %q, want the created decision's path", got)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	for _, field := range []string{"id", "state", "reason", "policy_id", "obligations", "challenges", "expires_at"} {
		if _, ok := body[field]; !ok {
			t.Errorf("the decision object carries no %q: %v", field, body)
		}
	}
	if body["state"] != string(store.DecisionPending) {
		t.Errorf("state = %v, want %q", body["state"], store.DecisionPending)
	}
	challenges, _ := body["challenges"].([]any)
	if len(challenges) != 1 {
		t.Fatalf("challenges = %v, want the one the decision is waiting on", body["challenges"])
	}
	first, _ := challenges[0].(map[string]any)
	if first["have"] != float64(0) || first["need"] != float64(2) {
		t.Errorf("collection progress = %v of %v, want 0 of 2", first["have"], first["need"])
	}
	if first["kind"] != string(policy.ChallengeQuorum) {
		t.Errorf("challenge kind = %v, want %q", first["kind"], policy.ChallengeQuorum)
	}
	// The response is a decision object and not an AuthZEN response: a pending
	// decision is neither of that contract's two answers, so it must not be
	// wearing that contract's boolean.
	if _, wearsAuthZEN := body["decision"]; wearsAuthZEN {
		t.Errorf("the decide response carries AuthZEN's boolean verdict: %v", body)
	}
}

// TestTheDecideResponseSaysWhereToSendTheSubject is R28 at the surface. A
// delegated MFA challenge is completed in a browser, so a response that names
// the challenge without naming its destination has told the PEP that something
// must happen and not what.
func TestTheDecideResponseSaysWhereToSendTheSubject(t *testing.T) {
	const authorizationURL = "https://idp.test/authorize?client_id=stamp-stepup&state=csrf-0f0f0f"
	f := newDecideFixture(t, decideOptions{})
	f.life.result = decision.Result{
		ID:          testDecideID,
		State:       store.DecisionPending,
		Reason:      engine.ReasonChallengeRequired,
		PolicyID:    "ledger-export",
		Obligations: []decision.Obligation{},
		Challenges: []decision.ChallengeView{{
			Ordinal: 0, Kind: policy.ChallengeMFA, State: challenge.StatePending,
			Have: 0, Need: 1, AuthorizationURL: authorizationURL,
		}},
		CreatedAt: fixedNow,
		ExpiresAt: fixedNow.Add(time.Hour),
	}

	rec := f.create(t, f.workload(t, "svc-payments"), decideBody(""))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST %s = %d: %s", api.DecisionsPath, rec.Code, rec.Body.String())
	}
	var body struct {
		Challenges []map[string]any `json:"challenges"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if len(body.Challenges) != 1 {
		t.Fatalf("challenges = %v, want the mfa challenge", body.Challenges)
	}
	if got := body.Challenges[0]["authorization_url"]; got != authorizationURL {
		t.Errorf("authorization_url = %v, want %q", got, authorizationURL)
	}
}

// TestAChallengeViewCarriesOnlyItsDeclaredFields fixes the wire shape of a
// challenge view by its whole field set rather than by the presence of the
// fields a test happens to care about.
//
// This is the assertion a future field has to argue with. A challenge's stored
// detail holds correlators, nonces and PKCE verifiers; the way those reach a
// caller is somebody widening this struct, and widening it turns this test red
// before it turns a deployment into a leak.
//
// The first half reads the type and not a value, because `omitempty` means a
// field can be added, be left unset by every fixture in the suite, and ship.
func TestAChallengeViewCarriesOnlyItsDeclaredFields(t *testing.T) {
	declared := []string{"ordinal", "kind", "state", "have", "need", "deadline", "authorization_url"}
	rt := reflect.TypeOf(decision.ChallengeView{})
	fields := make([]string, 0, rt.NumField())
	for i := range rt.NumField() {
		name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
		if name == "" {
			name = rt.Field(i).Name
		}
		fields = append(fields, name)
	}
	sort.Strings(fields)
	want := append([]string(nil), declared...)
	sort.Strings(want)
	if !slices.Equal(fields, want) {
		t.Fatalf("decision.ChallengeView declares %v, want %v — a new field on this type is a "+
			"new thing a caller is told about a challenge, and challenge details hold secrets", fields, want)
	}

	deadline := fixedNow.Add(30 * time.Minute)
	for _, tc := range []struct {
		name string
		view decision.ChallengeView
		want []string
	}{
		{
			name: "a kind that publishes nothing",
			view: decision.ChallengeView{
				Ordinal: 0, Kind: policy.ChallengeQuorum, State: challenge.StatePending,
				Have: 0, Need: 2, Deadline: &deadline,
			},
			want: []string{"ordinal", "kind", "state", "have", "need", "deadline"},
		},
		{
			name: "a kind that publishes a destination",
			view: decision.ChallengeView{
				Ordinal: 1, Kind: policy.ChallengeMFA, State: challenge.StatePending,
				Have: 0, Need: 1, AuthorizationURL: "https://idp.test/authorize",
			},
			want: []string{"ordinal", "kind", "state", "have", "need", "authorization_url"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.view)
			if err != nil {
				t.Fatalf("encode challenge view: %v", err)
			}
			var got map[string]any
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("decode challenge view: %v", err)
			}
			keys := make([]string, 0, len(got))
			for k := range got {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if !slices.Equal(keys, want) {
				t.Errorf("challenge view fields = %v, want %v: %s", keys, want, raw)
			}
		})
	}
}

// TestADecideThatNeedsNothingIsStillADecision: an immediate allow is an object
// with an identifier, because a decision that needed no challenge is still
// something an auditor has to be able to find.
func TestADecideThatNeedsNothingIsStillADecision(t *testing.T) {
	f := newDecideFixture(t, decideOptions{})
	f.life.result = decision.Result{
		ID:          testDecideID,
		State:       store.DecisionAllowed,
		Reason:      engine.ReasonPolicyMatched,
		PolicyID:    "whitelist-transfer",
		Obligations: []decision.Obligation{},
		CreatedAt:   fixedNow,
		ExpiresAt:   fixedNow.Add(time.Hour),
	}

	rec := f.create(t, f.workload(t, "svc-payments"), decideBody(""))
	if rec.Code != http.StatusCreated {
		t.Fatalf("an immediate allow = %d: %s", rec.Code, rec.Body.String())
	}
	var result decision.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if !result.Allowed() || result.ID != testDecideID {
		t.Errorf("result = %+v, want an allowed decision with an identifier to read back", result)
	}
}

// TestADenyIsAnsweredHonestlyAndCreatesNothing: a deny has no decision row —
// there is no policy version to pin one to — so the response carries no
// identifier to follow, and does not pretend one exists.
func TestADenyIsAnsweredHonestlyAndCreatesNothing(t *testing.T) {
	f := newDecideFixture(t, decideOptions{})
	f.life.result = decision.Result{
		State:       store.DecisionDenied,
		Outcome:     engine.Deny,
		Reason:      engine.ReasonNoMatchingPolicy,
		Obligations: []decision.Obligation{},
	}

	rec := f.create(t, f.workload(t, "svc-payments"), decideBody(""))
	// Not 201: nothing was created.
	if rec.Code != http.StatusOK {
		t.Fatalf("a denied decide = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if location := rec.Header().Get("Location"); location != "" {
		t.Errorf("a deny points at %q, want nowhere", location)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if id, present := body["id"]; present {
		t.Errorf("a deny carries the identifier %v of a decision that was never created", id)
	}
	if body["state"] != string(store.DecisionDenied) {
		t.Errorf("state = %v, want %q", body["state"], store.DecisionDenied)
	}
	if body["reason"] != string(engine.ReasonNoMatchingPolicy) {
		t.Errorf("reason = %v, want the ground the lifecycle gave", body["reason"])
	}
}

// TestTheOutstandingCapIsAnsweredAsADeny: R43's cap is refused inside the
// lifecycle, before evaluation, and reaches the caller as a deny carrying its
// own ground rather than as an error.
func TestTheOutstandingCapIsAnsweredAsADeny(t *testing.T) {
	f := newDecideFixture(t, decideOptions{})
	f.life.result = decision.Result{
		State: store.DecisionDenied, Outcome: engine.Deny,
		Reason: decision.ReasonOutstandingCap, Obligations: []decision.Obligation{},
	}
	rec := f.create(t, f.workload(t, "svc-payments"), decideBody(""))
	if rec.Code != http.StatusOK {
		t.Fatalf("a capped decide = %d, want a deny: %s", rec.Code, rec.Body.String())
	}
	var result decision.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if result.Reason != decision.ReasonOutstandingCap {
		t.Errorf("reason = %q, want %q so a PEP can tell a cap from a policy deny",
			result.Reason, decision.ReasonOutstandingCap)
	}
}

// ---------------------------------------------------------------------------
// R40: who may call, and who may read
// ---------------------------------------------------------------------------

// TestTheDecideSurfaceRefusesBeforeEvaluating is R40's first half: the
// credential check runs ahead of everything, and nothing reaches the lifecycle
// when it fails.
func TestTheDecideSurfaceRefusesBeforeEvaluating(t *testing.T) {
	f := newDecideFixture(t, decideOptions{})

	t.Run("an unauthenticated create is refused", func(t *testing.T) {
		rec := f.create(t, "", decideBody(""))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("an unauthenticated decide = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("an end-user token is refused on the PEP surface", func(t *testing.T) {
		// The mount table admits only a workload credential here, so a person's
		// token is refused by the kind check rather than by a handler.
		rec := f.create(t, f.idp.token(t, "alice", "console-1"), decideBody(""))
		if rec.Code != http.StatusForbidden {
			t.Errorf("an end-user decide = %d, want %d", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("an unauthenticated read is refused", func(t *testing.T) {
		rec := f.read(t, "", testDecideID)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("an unauthenticated read = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	if f.life.decided() != 0 {
		t.Errorf("%d refused requests reached the lifecycle, want 0", f.life.decided())
	}
	if len(f.life.reads) != 0 {
		t.Errorf("%d refused reads reached the lifecycle, want 0", len(f.life.reads))
	}
}

// TestTheCallerIsTheVerifiedToken: the decision is attributed to the credential
// and to nothing in the request.
func TestTheCallerIsTheVerifiedToken(t *testing.T) {
	f := newDecideFixture(t, decideOptions{})
	token := f.workload(t, "svc-payments")

	if rec := f.create(t, token, decideBody(`"caller_id": "svc-someone-else"`)); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	caller := f.lastCaller(t)
	if caller == nil || caller.ID != "svc-payments" || caller.Kind != identity.SubjectWorkload {
		t.Fatalf("caller = %+v, want the workload the token names", caller)
	}

	if rec := f.read(t, token, testDecideID); rec.Code != http.StatusOK {
		t.Fatalf("read = %d: %s", rec.Code, rec.Body.String())
	}
	read := f.life.lastRead(t)
	if read.id != testDecideID {
		t.Errorf("the read asked for %q, want the identifier in the path", read.id)
	}
	if !strings.HasSuffix(read.callerID, "#svc-payments") {
		t.Errorf("the read was attributed to %q, want the token's workload", read.callerID)
	}
}

func (f *decideFixture) lastCaller(t *testing.T) *identity.Subject {
	t.Helper()
	return f.life.lastRequest(t).Caller
}

// TestARefusedReadIsIndistinguishableFromAMissingOne is this unit's most
// important assertion.
//
// R40 limits a decision to its creator and its targeted approvers. If the
// refusal a stranger gets differed in any way from the answer for an identifier
// that names nothing, this endpoint would be an oracle for which decisions
// exist — and a workload holding any valid credential could ask it.
func TestARefusedReadIsIndistinguishableFromAMissingOne(t *testing.T) {
	stranger := "svc-stranger"

	responses := map[string]*httptest.ResponseRecorder{}
	for name, tc := range map[string]struct {
		err error
		id  string
	}{
		"a decision that is not the caller's": {err: decision.ErrNotAuthorized, id: testDecideID},
		"a decision that does not exist":      {err: store.ErrNotFound, id: otherDecideID},
		"an identifier that names nothing":    {err: nil, id: "not-a-decision-identifier"},
	} {
		f := newDecideFixture(t, decideOptions{})
		f.life.viewErr = tc.err
		responses[name] = f.read(t, f.workload(t, stranger), tc.id)
	}

	var want *httptest.ResponseRecorder
	var wantName string
	for name, rec := range responses {
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want %d", name, rec.Code, http.StatusNotFound)
		}
		if want == nil {
			want, wantName = rec, name
			continue
		}
		if rec.Body.String() != want.Body.String() {
			t.Errorf("%s answers %q but %s answers %q; the two must not be tellable apart",
				name, rec.Body.String(), wantName, want.Body.String())
		}
		if rec.Header().Get("Content-Type") != want.Header().Get("Content-Type") {
			t.Errorf("%s and %s answer with different content types", name, wantName)
		}
	}
}

// TestAMalformedIdentifierIsNotAFault: the decisions table keys on a uuid, so an
// identifier that is not one would be a query error. It must not reach the
// lifecycle at all, and it must not answer differently from a decision that is
// simply not there.
func TestAMalformedIdentifierIsNotAFault(t *testing.T) {
	f := newDecideFixture(t, decideOptions{})
	for _, id := range []string{"1", "not-a-uuid", strings.Repeat("z", 36), testDecideID + "x"} {
		rec := f.read(t, f.workload(t, "svc-payments"), id)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s/%s = %d, want %d", api.DecisionsPath, id, rec.Code, http.StatusNotFound)
		}
	}
	if len(f.life.reads) != 0 {
		t.Errorf("%d malformed identifiers reached the lifecycle, want 0", len(f.life.reads))
	}
}

// ---------------------------------------------------------------------------
// the body: the same mapping the check surface uses
// ---------------------------------------------------------------------------

// TestTheDecideBodyMapsLikeTheCheckBody: the two calls take one body and must
// reach one input from it. A decision issued against attributes a check of the
// same request would not have seen is the divergence that makes the pair
// untrustworthy.
func TestTheDecideBodyMapsLikeTheCheckBody(t *testing.T) {
	f := newDecideFixture(t, decideOptions{
		contextEntity: "request",
		aliases:       map[string]string{"acctNumber": "number"},
	})
	body := `{
		"subject":  {"type": "account", "id": "acct-src",
		             "properties": {"acctNumber": "1001", "nickname": "payroll", "id": "ignored"}},
		"resource": {"type": "account", "id": "acct-dst", "properties": {"amount": 5000}},
		"action":   {"name": "close"},
		"context":  {"channel": "mobile", "undeclared": true}
	}`
	if rec := f.create(t, f.workload(t, "svc-payments"), body); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}

	in := f.life.lastRequest(t).Input
	if in.Action != "close" {
		t.Errorf("action = %q, want %q", in.Action, "close")
	}
	// A declared property, reached through the operator's alias table.
	if in.Subject.Attributes["number"] != "1001" {
		t.Errorf("subject.number = %v, want the aliased property", in.Subject.Attributes["number"])
	}
	// An undeclared one is dropped rather than refused: a policy cannot read it.
	if _, present := in.Subject.Attributes["nickname"]; present {
		t.Errorf("an undeclared property reached the input: %v", in.Subject.Attributes)
	}
	// The envelope identifier wins over a property of the same name.
	if in.Subject.Attributes["id"] != "acct-src" {
		t.Errorf("subject.id = %v, want the envelope identifier", in.Subject.Attributes["id"])
	}
	// A declared int arrives as an int and not as a float.
	if amount, ok := in.Resource.Attributes["amount"].(int64); !ok || amount != 5000 {
		t.Errorf("resource.amount = %#v, want int64(5000)", in.Resource.Attributes["amount"])
	}
	// The context binds to the configured entity type, with the same rules.
	if in.Context.Type != "request" || in.Context.Attributes["channel"] != "mobile" {
		t.Errorf("context = %+v, want the configured entity carrying its declared attribute", in.Context)
	}
	if _, present := in.Context.Attributes["undeclared"]; present {
		t.Errorf("an undeclared context property reached the input: %v", in.Context.Attributes)
	}
}

// TestADeclaredPropertyOfTheWrongTypeIsRefused: a value the policy will read and
// cannot be converted is the caller's mistake, and answering it with a decision
// would turn that mistake into one.
func TestADeclaredPropertyOfTheWrongTypeIsRefused(t *testing.T) {
	f := newDecideFixture(t, decideOptions{})
	body := `{
		"subject":  {"type": "account", "id": "acct-src", "properties": {"number": "1001"}},
		"resource": {"type": "account", "id": "acct-dst", "properties": {"amount": "not a number"}},
		"action":   {"name": "close"}
	}`
	rec := f.create(t, f.workload(t, "svc-payments"), body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a mistyped declared property = %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if f.life.decided() != 0 {
		t.Errorf("a request that could not be mapped reached the lifecycle")
	}
}

// TestAMalformedDecideBodyIsRefused: the shape check is the check surface's,
// stated once, so the two endpoints cannot come to disagree about what a
// well-formed access request is.
func TestAMalformedDecideBodyIsRefused(t *testing.T) {
	f := newDecideFixture(t, decideOptions{})
	for name, body := range map[string]string{
		"no subject":  `{"resource": {"type": "account", "id": "a"}, "action": {"name": "close"}}`,
		"no action":   `{"subject": {"type": "account", "id": "a"}, "resource": {"type": "account", "id": "b"}}`,
		"no resource": `{"subject": {"type": "account", "id": "a"}, "action": {"name": "close"}}`,
		"not json":    `{`,
	} {
		rec := f.create(t, f.workload(t, "svc-payments"), body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want %d", name, rec.Code, http.StatusBadRequest)
		}
	}
	if f.life.decided() != 0 {
		t.Errorf("%d malformed requests reached the lifecycle, want 0", f.life.decided())
	}
}

// TestTheDecideBodyIsBounded: the cap is enforced while the body is read, so a
// caller cannot make this surface allocate by declaring a large one.
func TestTheDecideBodyIsBounded(t *testing.T) {
	f := newDecideFixture(t, decideOptions{maxBytes: 256})
	padded := decideBody(fmt.Sprintf("%q: %q", "note", strings.Repeat("x", 1024)))
	rec := f.create(t, f.workload(t, "svc-payments"), padded)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized body = %d, want %d: %s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
	if f.life.decided() != 0 {
		t.Errorf("an oversized body reached the lifecycle")
	}
}

// TestTheRequestedLifetimeIsBounded: `ttl` is the one member decide adds to the
// check body, and an unbounded one is a subject's outstanding slot (R43) that
// nobody gets back.
func TestTheRequestedLifetimeIsBounded(t *testing.T) {
	t.Run("a lifetime is carried to the lifecycle", func(t *testing.T) {
		f := newDecideFixture(t, decideOptions{})
		if rec := f.create(t, f.workload(t, "svc-a"), decideBody(`"ttl": "30m"`)); rec.Code != http.StatusCreated {
			t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
		}
		if got := f.life.lastRequest(t).TTL; got != 30*time.Minute {
			t.Errorf("ttl = %s, want 30m", got)
		}
	})

	t.Run("no lifetime leaves the deployment's default in place", func(t *testing.T) {
		f := newDecideFixture(t, decideOptions{})
		if rec := f.create(t, f.workload(t, "svc-a"), decideBody("")); rec.Code != http.StatusCreated {
			t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
		}
		if got := f.life.lastRequest(t).TTL; got != 0 {
			t.Errorf("ttl = %s, want zero so the service default stands", got)
		}
	})

	t.Run("an unusable lifetime is refused", func(t *testing.T) {
		f := newDecideFixture(t, decideOptions{maxTTL: time.Hour})
		for name, ttl := range map[string]string{
			"not a duration": `"soon"`,
			"negative":       `"-5m"`,
			"zero":           `"0s"`,
			"over the cap":   `"48h"`,
			"a bare number":  `300`,
		} {
			rec := f.create(t, f.workload(t, "svc-a"), decideBody(`"ttl": `+ttl))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s ttl = %d, want %d: %s", name, rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		}
		if f.life.decided() != 0 {
			t.Errorf("%d unusable lifetimes reached the lifecycle, want 0", f.life.decided())
		}
	})
}

// ---------------------------------------------------------------------------
// the states the surface has to answer for
// ---------------------------------------------------------------------------

// TestDecidingWithNoPolicySetIsAnExplicitRefusal: an instance that holds no
// policy set cannot judge. Unlike the check surface it has nothing honest to
// answer with — a decision object that was never created and never audited would
// be a record of something that did not happen — so it refuses with a status,
// and never with a 500.
func TestDecidingWithNoPolicySetIsAnExplicitRefusal(t *testing.T) {
	f := newDecideFixture(t, decideOptions{noSchema: true})
	rec := f.create(t, f.workload(t, "svc-payments"), decideBody(""))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a decide with no policy set = %d, want %d: %s",
			rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	var body api.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if body.Error != string(engine.ReasonPolicySetStale) {
		t.Errorf("error = %q, want the ground the check surface uses for the same state", body.Error)
	}
	if f.life.decided() != 0 {
		t.Errorf("a request reached the lifecycle with no policy set to judge it")
	}
}

// TestALifecycleFailureIsMappedNotNarrated: the table is the whole of what a PEP
// learns, and a database failure is not something it is the audience for.
func TestALifecycleFailureIsMappedNotNarrated(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"a challenge kind this build cannot issue": {err: challenge.ErrNoHandler, want: http.StatusNotImplemented},
		"an unusable challenge declaration":        {err: challenge.ErrUnsupportedSpec, want: http.StatusNotImplemented},
		"a caller the lifecycle will not accept":   {err: decision.ErrUnauthenticated, want: http.StatusUnauthorized},
		"anything else":                            {err: errors.New("connection refused"), want: http.StatusInternalServerError},
	} {
		f := newDecideFixture(t, decideOptions{})
		f.life.decideErr = fmt.Errorf("decision: open challenge 0 of %s: %w", testDecideID, tc.err)
		rec := f.create(t, f.workload(t, "svc-payments"), decideBody(""))
		if rec.Code != tc.want {
			t.Errorf("%s = %d, want %d: %s", name, rec.Code, tc.want, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "connection refused") {
			t.Errorf("%s narrated the underlying failure to the caller: %s", name, rec.Body.String())
		}
	}
}

// ---------------------------------------------------------------------------
// the mount
// ---------------------------------------------------------------------------

// TestTheDecideRoutesAreOnThePEPSurfaceAlone: the separation is three routers,
// so a decide endpoint is not reachable from a listener it was not mounted on.
func TestTheDecideRoutesAreOnThePEPSurfaceAlone(t *testing.T) {
	f := newDecideFixture(t, decideOptions{})
	token := f.workload(t, "svc-payments")
	for _, surface := range []api.Surface{api.SurfaceConsole, api.SurfaceCallback} {
		rec := f.do(surface, http.MethodPost, api.DecisionsPath, token, decideBody(""))
		if rec.Code != http.StatusNotFound {
			t.Errorf("POST %s on the %s surface = %d, want 404", api.DecisionsPath, surface, rec.Code)
		}
		rec = f.do(surface, http.MethodGet, api.DecisionsPath+"/"+testDecideID, token, "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("the read on the %s surface = %d, want 404", surface, rec.Code)
		}
	}
}

// TestTheDecideSurfaceRefusesToBeBuiltWithoutItsDependencies: a missing
// dependency is a wiring mistake, and a surface that started without one would
// answer 500s that look like an outage.
func TestTheDecideSurfaceRefusesToBeBuiltWithoutItsDependencies(t *testing.T) {
	life := &recordingDecider{}
	schemas := &countingSchema{schema: decideSchema()}
	audit := &recordingEvents{}
	for name, cfg := range map[string]api.DecisionsConfig{
		"no lifecycle": {Access: life, Schema: schemas, Audit: audit},
		"no read rule": {Decisions: life, Schema: schemas, Audit: audit},
		"no schema":    {Decisions: life, Access: life, Audit: audit},
		// R43 asks the refusal to be audited, so a surface with nowhere to record
		// one cannot serve: it would shed load and leave no sign that it had.
		"no audit recorder": {Decisions: life, Access: life, Schema: schemas},
		"nothing at all":    {},
	} {
		if _, err := api.NewDecisions(cfg); err == nil {
			t.Errorf("%s: the decide surface was built anyway", name)
		}
	}
}
