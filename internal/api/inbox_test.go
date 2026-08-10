package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/identity"
)

// The inbox surface owns two things: it takes the approver from the verified
// token and never from the request, and it hands the list through untouched.
// Which challenges are in it is the quorum handler's answer and is tested where
// the database is.

type recordingInbox struct {
	mu       sync.Mutex
	requests []challenge.InboxRequest
	items    []challenge.InboxItem
	err      error
}

func (r *recordingInbox) Inbox(_ context.Context, req challenge.InboxRequest) ([]challenge.InboxItem, error) {
	r.mu.Lock()
	r.requests = append(r.requests, req)
	r.mu.Unlock()
	return r.items, r.err
}

func (r *recordingInbox) last(t *testing.T) challenge.InboxRequest {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.requests) == 0 {
		t.Fatal("nothing reached the lister")
	}
	return r.requests[len(r.requests)-1]
}

type inboxFixture struct {
	server *api.Server
	idp    *mockIdP
	lister *recordingInbox
}

func newInboxFixture(t *testing.T) *inboxFixture {
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
	lister := &recordingInbox{}
	inbox, err := api.NewInbox(api.InboxConfig{Quorums: lister, Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("build inbox: %v", err)
	}
	if err := server.Mount(inbox); err != nil {
		t.Fatalf("mount inbox: %v", err)
	}
	return &inboxFixture{server: server, idp: idp, lister: lister}
}

func (f *inboxFixture) get(t *testing.T, surface api.Surface, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.server.Handler(surface).ServeHTTP(rec, req)
	return rec
}

// The approver is the token's subject. Nothing in the request says otherwise —
// there is no query parameter to say it with, which is the point.
func TestInboxAsksForTheTokenSubject(t *testing.T) {
	t.Parallel()
	f := newInboxFixture(t)

	rec := f.get(t, api.SurfaceConsole, "/decisions/inbox?approver=carol", f.idp.token(t, "bob", "console"))
	if rec.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", rec.Code, rec.Body)
	}
	req := f.lister.last(t)
	if req.Subject == nil || req.Subject.ID != "bob" {
		t.Fatalf("the lister was asked for %v, want the token subject bob", req.Subject)
	}
}

func TestUnauthenticatedInboxIsRefusedBeforeTheLister(t *testing.T) {
	t.Parallel()
	f := newInboxFixture(t)
	rec := f.get(t, api.SurfaceConsole, "/decisions/inbox", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an anonymous inbox read answered %d, want 401", rec.Code)
	}
	if len(f.lister.requests) != 0 {
		t.Fatal("an anonymous request reached the lister")
	}
}

func TestInboxIsNotReachableOnThePEPSurface(t *testing.T) {
	t.Parallel()
	f := newInboxFixture(t)
	rec := f.get(t, api.SurfacePEP, "/decisions/inbox", f.idp.token(t, "bob", "console"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("the PEP surface answered %d for a console path, want 404", rec.Code)
	}
}

// An empty inbox is an empty list and not a null, because a console that has to
// branch on null before it can render "nothing is waiting on you" will forget.
func TestEmptyInboxSerializesAsAList(t *testing.T) {
	t.Parallel()
	f := newInboxFixture(t)
	rec := f.get(t, api.SurfaceConsole, "/decisions/inbox", f.idp.token(t, "bob", "console"))
	if !strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Errorf("an empty inbox serialized as %s", rec.Body)
	}
}

// The list carries the server's clock. Time remaining computed from a skewed
// browser is not the deadline the server will enforce.
func TestInboxCarriesTheServerClock(t *testing.T) {
	t.Parallel()
	f := newInboxFixture(t)
	f.lister.items = []challenge.InboxItem{{
		DecisionID: testDecisionID, Ordinal: 0, PolicyID: "wire",
		Have: 1, Need: 2, ExpiresAt: fixedNow.Add(time.Hour),
	}}
	rec := f.get(t, api.SurfaceConsole, "/decisions/inbox", f.idp.token(t, "bob", "console"))
	var body api.InboxResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.ServerTime.Equal(fixedNow) {
		t.Errorf("the list reports server time %s, want %s", body.ServerTime, fixedNow)
	}
	if len(body.Items) != 1 || body.Items[0].Need != 2 {
		t.Errorf("the list is %+v", body.Items)
	}
}

func TestInboxRefusesANonPositiveLimit(t *testing.T) {
	t.Parallel()
	f := newInboxFixture(t)
	for _, bad := range []string{"0", "-1", "many"} {
		rec := f.get(t, api.SurfaceConsole, "/decisions/inbox?limit="+bad, f.idp.token(t, "bob", "console"))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("limit=%s answered %d, want 400", bad, rec.Code)
		}
	}
}
