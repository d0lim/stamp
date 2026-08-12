package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/store"
)

// The audit console owns four things: it decides auditor standing from an
// operator-configured claim, it chains the refusal, it parses the four query
// axes into the store's query rather than trusting a client to have done it,
// and it falls back to R40's own-record rule for a reader without standing.
// What the query itself does with those axes is tested where the database is.

const auditDecisionID = "5c2d1e3a-0000-4000-8000-0000000000aa"

type fakeHistory struct {
	mu sync.Mutex

	queries []store.DecisionQuery

	page       store.DecisionPage
	decision   store.Decision
	progress   []store.ChallengeProgress
	approvals  []store.Approval
	policy     store.PolicyRecord
	decisionEr error
	policyEr   error
}

func (h *fakeHistory) ListDecisions(_ context.Context, q store.DecisionQuery) (store.DecisionPage, error) {
	h.mu.Lock()
	h.queries = append(h.queries, q)
	h.mu.Unlock()
	return h.page, nil
}

func (h *fakeHistory) Decision(context.Context, string) (store.Decision, error) {
	if h.decisionEr != nil {
		return store.Decision{}, h.decisionEr
	}
	return h.decision, nil
}

func (h *fakeHistory) ChallengeProgress(context.Context, string) ([]store.ChallengeProgress, error) {
	return h.progress, nil
}

func (h *fakeHistory) Approvals(context.Context, string) ([]store.Approval, error) {
	return h.approvals, nil
}

func (h *fakeHistory) PolicyVersion(context.Context, string, int64) (store.PolicyRecord, error) {
	if h.policyEr != nil {
		return store.PolicyRecord{}, h.policyEr
	}
	return h.policy, nil
}

func (h *fakeHistory) lastQuery(t *testing.T) store.DecisionQuery {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.queries) == 0 {
		t.Fatal("no query reached the history")
	}
	return h.queries[len(h.queries)-1]
}

type fakeAccess struct {
	mu       sync.Mutex
	asked    []string
	err      error
	response decision.Result
}

func (a *fakeAccess) Get(_ context.Context, _ *identity.Subject, id string) (decision.Result, error) {
	a.mu.Lock()
	a.asked = append(a.asked, id)
	a.mu.Unlock()
	return a.response, a.err
}

type fakeAppender struct {
	mu      sync.Mutex
	entries []store.AuditEntry
}

func (a *fakeAppender) Append(_ context.Context, entries ...store.AuditEntry) ([]store.AuditRecord, error) {
	a.mu.Lock()
	a.entries = append(a.entries, entries...)
	a.mu.Unlock()
	return nil, nil
}

func (a *fakeAppender) all() []store.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]store.AuditEntry(nil), a.entries...)
}

type auditFixture struct {
	server  *api.Server
	idp     *mockIdP
	history *fakeHistory
	access  *fakeAccess
	audit   *fakeAppender
}

func newAuditFixture(t *testing.T, rule api.AuditorRule) *auditFixture {
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
	history := &fakeHistory{
		decision: store.Decision{
			ID: auditDecisionID, CallerID: "svc-a", PolicyID: "wire", PolicyVersion: 3,
			SubjectID: "alice", ResourceID: "acct-1", Action: "transfer",
			Request:      json.RawMessage(`{"action":"transfer"}`),
			FactSnapshot: json.RawMessage(`{"note":"<script>alert(1)</script>"}`),
			Obligations:  json.RawMessage(`[]`),
			State:        store.DecisionAllowed,
			CreatedAt:    fixedNow, ExpiresAt: fixedNow.Add(time.Hour),
		},
		policy: store.PolicyRecord{ID: "wire", Version: 3, Origin: store.OriginForm, Document: "apiVersion: stamp/v1"},
	}
	access := &fakeAccess{err: decision.ErrNotAuthorized}
	appender := &fakeAppender{}
	console, err := api.NewAuditConsole(api.AuditConsoleConfig{
		History:  history,
		Access:   access,
		Auditors: rule,
		Audit:    appender,
		Now:      func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatalf("build audit console: %v", err)
	}
	if err := server.Mount(console); err != nil {
		t.Fatalf("mount audit console: %v", err)
	}
	return &auditFixture{server: server, idp: idp, history: history, access: access, audit: appender}
}

func (f *auditFixture) get(t *testing.T, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.server.Handler(api.SurfaceConsole).ServeHTTP(rec, req)
	return rec
}

func (f *auditFixture) auditorToken(t *testing.T, subject string) string {
	t.Helper()
	return f.idp.tokenWith(t, subject, "console", map[string]any{"roles": []string{"auditor"}})
}

func (f *auditFixture) plainToken(t *testing.T, subject string) string {
	t.Helper()
	return f.idp.tokenWith(t, subject, "console", map[string]any{"roles": []string{"approver"}})
}

// R22: standing is enforced on the server. A token without it does not read the
// history, and the refusal lands in the chain.
func TestAuditListRefusesWithoutAuditorStandingAndChainsTheRefusal(t *testing.T) {
	t.Parallel()
	f := newAuditFixture(t, api.AuditorRule{})

	rec := f.get(t, "/audit/decisions", f.plainToken(t, "bob"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the history answered %d for a token without standing, want 403: %s", rec.Code, rec.Body)
	}
	if len(f.history.queries) != 0 {
		t.Error("a refused read still reached the decision history")
	}

	entries := f.audit.all()
	if len(entries) != 1 {
		t.Fatalf("the refusal wrote %d audit entries, want 1", len(entries))
	}
	if entries[0].Kind != store.AuditKindAuditRefused {
		t.Errorf("the refusal was chained as %q, want %q", entries[0].Kind, store.AuditKindAuditRefused)
	}
	payload, ok := entries[0].Payload.(map[string]any)
	if !ok {
		t.Fatalf("the refusal payload is %T, want a map", entries[0].Payload)
	}
	if !strings.Contains(payload["caller_id"].(string), "bob") {
		t.Errorf("the refusal does not name the caller: %v", payload)
	}
	if payload["action"] != "list" {
		t.Errorf("the refusal records action %v, want \"list\"", payload["action"])
	}
}

func TestAuditListServesAReaderWithStanding(t *testing.T) {
	t.Parallel()
	f := newAuditFixture(t, api.AuditorRule{})
	f.history.page = store.DecisionPage{
		Decisions: []store.Decision{f.history.decision},
		Next:      store.DecisionCursor{CreatedAt: fixedNow, ID: auditDecisionID},
	}

	rec := f.get(t, "/audit/decisions", f.auditorToken(t, "ann"))
	if rec.Code != http.StatusOK {
		t.Fatalf("the history answered %d for an auditor, want 200: %s", rec.Code, rec.Body)
	}
	var body api.AuditDecisionListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Decisions) != 1 || body.Decisions[0].ID != auditDecisionID {
		t.Fatalf("the page is %+v", body.Decisions)
	}
	if body.NextCursor == "" {
		t.Error("a page with a next cursor served none")
	}
	if body.Query.Order != "created_at desc" {
		t.Errorf("the echoed order is %q", body.Query.Order)
	}
	// The list is a list. A frozen fact snapshot belongs on the detail read.
	if strings.Contains(rec.Body.String(), "fact_snapshot") {
		t.Error("the history list spilled a fact snapshot")
	}
}

// An operator whose auditors are an IdP group names the group claim and the
// group. The default spelling then grants nothing.
func TestAuditorStandingFollowsTheOperatorRule(t *testing.T) {
	t.Parallel()
	f := newAuditFixture(t, api.AuditorRule{Claim: "groups", Values: []string{"sec-audit"}})

	viaGroup := f.idp.tokenWith(t, "ann", "console", map[string]any{"groups": []string{"sre", "sec-audit"}})
	if rec := f.get(t, "/audit/decisions", viaGroup); rec.Code != http.StatusOK {
		t.Errorf("a member of the configured group got %d, want 200: %s", rec.Code, rec.Body)
	}
	viaDefault := f.idp.tokenWith(t, "bob", "console", map[string]any{"roles": []string{"auditor"}})
	if rec := f.get(t, "/audit/decisions", viaDefault); rec.Code != http.StatusForbidden {
		t.Errorf("the default spelling still granted standing under a configured rule: %d", rec.Code)
	}
}

// The four axes arrive as a store query. Every one of them is parsed here so
// that a malformed window is a 400 and never a silently wider read.
func TestAuditListParsesTheFourAxes(t *testing.T) {
	t.Parallel()
	f := newAuditFixture(t, api.AuditorRule{})
	token := f.auditorToken(t, "ann")

	rec := f.get(t, "/audit/decisions?from=2026-08-01T00:00:00Z&to=2026-09-01T00:00:00Z"+
		"&policy=wire&subject=alice&state=denied&limit=7", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", rec.Code, rec.Body)
	}
	q := f.history.lastQuery(t)
	if q.From != time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC) || q.To != time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC) {
		t.Errorf("the period arrived as [%s, %s)", q.From, q.To)
	}
	if q.PolicyID != "wire" || q.SubjectID != "alice" || q.State != store.DecisionDenied || q.Limit != 7 {
		t.Errorf("the axes arrived as %+v", q)
	}

	for _, bad := range []string{
		"?from=2026-08-01", // no timezone
		"?state=approved",  // not a decision state
		"?limit=0",         // not a page
		"?limit=-3",        //
		"?from=2026-09-01T00:00:00Z&to=2026-08-01T00:00:00Z", // empty window
		"?cursor=not-a-cursor",
	} {
		if rec := f.get(t, "/audit/decisions"+bad, token); rec.Code != http.StatusBadRequest {
			t.Errorf("%q answered %d, want 400", bad, rec.Code)
		}
	}
}

func TestAuditListClampsThePageSize(t *testing.T) {
	t.Parallel()
	f := newAuditFixture(t, api.AuditorRule{})
	rec := f.get(t, "/audit/decisions?limit=100000", f.auditorToken(t, "ann"))
	if rec.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", rec.Code, rec.Body)
	}
	if got := f.history.lastQuery(t).Limit; got != store.MaxDecisionPageSize {
		t.Errorf("an unbounded page was passed through as %d, want %d", got, store.MaxDecisionPageSize)
	}
}

// R22's second half: without standing a reader still sees their own record, and
// the rule that decides "their own" is R40's, asked of the component that owns
// it rather than reimplemented here.
func TestAuditDetailFallsBackToTheOwnRecordRule(t *testing.T) {
	t.Parallel()
	f := newAuditFixture(t, api.AuditorRule{})

	rec := f.get(t, "/audit/decisions/"+auditDecisionID, f.plainToken(t, "bob"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("a reader the access rule refused got %d, want 404: %s", rec.Code, rec.Body)
	}
	if len(f.access.asked) != 1 {
		t.Fatalf("the access rule was consulted %d times, want 1", len(f.access.asked))
	}

	f.access.err = nil
	rec = f.get(t, "/audit/decisions/"+auditDecisionID, f.plainToken(t, "bob"))
	if rec.Code != http.StatusOK {
		t.Fatalf("a reader the access rule admitted got %d, want 200: %s", rec.Code, rec.Body)
	}
	var detail api.AuditDecisionDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if detail.ViaAuditorStanding {
		t.Error("a read admitted by the own-record rule claims auditor standing")
	}
}

// An auditor's detail read does not consult the own-record rule at all: their
// standing is the authorisation, and asking would write a refusal for a read
// that was allowed.
func TestAuditorDetailReadSkipsTheOwnRecordRule(t *testing.T) {
	t.Parallel()
	f := newAuditFixture(t, api.AuditorRule{})

	rec := f.get(t, "/audit/decisions/"+auditDecisionID, f.auditorToken(t, "ann"))
	if rec.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", rec.Code, rec.Body)
	}
	if len(f.access.asked) != 0 {
		t.Errorf("an auditor's read consulted the own-record rule %d times", len(f.access.asked))
	}
	var detail api.AuditDecisionDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !detail.ViaAuditorStanding {
		t.Error("an auditor's read does not report auditor standing")
	}
	// R22: the policy version the decision froze, not the effective one.
	if detail.PolicyVersion != 3 || detail.PolicyDocument == "" {
		t.Errorf("the frozen policy version is %d with document %q", detail.PolicyVersion, detail.PolicyDocument)
	}
	// The fact snapshot is passed through as JSON: the value survives, byte for
	// byte, once decoded. encoding/json writes `<` as < on the way out,
	// which is an encoding and not a sanitisation — the console still receives
	// the script tag and still has to render it as text (R22).
	var facts struct {
		Note string `json:"note"`
	}
	if err := json.Unmarshal(detail.FactSnapshot, &facts); err != nil {
		t.Fatalf("decode fact snapshot: %v", err)
	}
	if facts.Note != "<script>alert(1)</script>" {
		t.Errorf("the fact snapshot was rewritten in transit: %q", facts.Note)
	}
}

// A decision whose frozen policy version is no longer readable still renders.
// The decision is the record; the document is context.
func TestAuditDetailSurvivesAMissingPolicyVersion(t *testing.T) {
	t.Parallel()
	f := newAuditFixture(t, api.AuditorRule{})
	f.history.policyEr = store.ErrNotFound

	rec := f.get(t, "/audit/decisions/"+auditDecisionID, f.auditorToken(t, "ann"))
	if rec.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", rec.Code, rec.Body)
	}
}

// TestAnUnreadableDecisionIsByteIdenticalToAMissingOne is #38 on the audit
// console's detail read.
//
// This is the same claim as on the approval surface and it has to hold here too,
// because R40's rule is one rule and this endpoint is the *other* door to it: a
// targeted approver reads their decision here, since a workload credential and a
// user token cannot be served by one route. A reader refused here who could have
// asked the same question on the PEP surface and been answered "not found" would
// simply ask twice, and the difference between the two answers is the existence
// of the decision.
//
// The refusal of the *history list* is deliberately not folded in: `not_an_auditor`
// is about standing to read a collection, answers no question about any
// particular decision, and is the refusal R22 asks to be chained.
func TestAnUnreadableDecisionIsByteIdenticalToAMissingOne(t *testing.T) {
	t.Parallel()

	// Both readers lack auditor standing, so both fall through to R40's rule —
	// which is where the two answers used to part company.
	read := func(t *testing.T, err error) *httptest.ResponseRecorder {
		t.Helper()
		f := newAuditFixture(t, api.AuditorRule{})
		f.access.err = err
		return f.get(t, "/audit/decisions/"+auditDecisionID, f.plainToken(t, "bob"))
	}

	base := read(t, store.ErrNotFound)
	if base.Code != http.StatusNotFound {
		t.Fatalf("a decision that does not exist = %d, want 404: %s", base.Code, base.Body)
	}
	refused := read(t, decision.ErrNotAuthorized)
	if refused.Code != base.Code {
		t.Errorf("an unreadable decision = %d, a missing one = %d", refused.Code, base.Code)
	}
	if !bytes.Equal(refused.Body.Bytes(), base.Body.Bytes()) {
		t.Errorf("body\n got %q\nwant %q", refused.Body.String(), base.Body.String())
	}
}

func TestAuditRoutesAreConsoleOnlyAndUserAuthenticated(t *testing.T) {
	t.Parallel()
	console, err := api.NewAuditConsole(api.AuditConsoleConfig{
		History: &fakeHistory{}, Access: &fakeAccess{}, Audit: &fakeAppender{},
	})
	if err != nil {
		t.Fatalf("build audit console: %v", err)
	}
	routes := console.Routes()
	if len(routes) != 2 {
		t.Fatalf("the audit console offers %d routes, want 2", len(routes))
	}
	for _, route := range routes {
		if route.Surface != api.SurfaceConsole || route.Auth != api.AuthUser {
			t.Errorf("route %q is %s/%s, want console/user", route.Name, route.Surface, route.Auth)
		}
	}
}
