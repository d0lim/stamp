package idpgroup

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
)

// testIssuer is the issuer every fixture directory is bound to. It matches the
// deployment's trusted issuer set, because a directory bound to anything else
// is refused at load.
const testIssuer = "https://idp.example.test"

// --- fixtures ----------------------------------------------------------------

// fakeResolver answers hostname lookups from a table. Every test installs one so
// that no test reaches a real resolver, and the rebinding test can change the
// answer between the load-time lookup and the call-time one.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{answers: map[string][]netip.Addr{}}
}

func (r *fakeResolver) set(host string, addrs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	parsed := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			panic("fakeResolver: " + a + ": " + err.Error())
		}
		parsed = append(parsed, addr)
	}
	r.answers[host] = parsed
}

func (r *fakeResolver) resolve(_ context.Context, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	addrs, ok := r.answers[host]
	if !ok {
		return nil, errors.New("no such host: " + host)
	}
	out := make([]netip.Addr, len(addrs))
	copy(out, addrs)
	return out, nil
}

// fakeClock drives the membership cache. Expiry is a property of declared time,
// not of how long the test took to run.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// recordingAuditor captures the failure records the sources emit.
type recordingAuditor struct {
	mu      sync.Mutex
	records []*fact.Failure
}

func (a *recordingAuditor) RecordFactFailure(_ context.Context, f *fact.Failure) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, f)
}

func (a *recordingAuditor) all() []*fact.Failure {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*fact.Failure, len(a.records))
	copy(out, a.records)
	return out
}

// directory is a stub group directory. It counts calls, so a test can prove the
// TTL kept one from happening, and captures the last request, so a test can
// prove what did and did not travel on it.
type directory struct {
	server   *httptest.Server
	calls    atomic.Int64
	lastReq  atomic.Pointer[http.Request]
	body     atomic.Pointer[string]
	status   atomic.Int64
	redirect atomic.Pointer[string]
}

func newDirectory(t *testing.T) *directory {
	t.Helper()
	d := &directory{}
	d.answer(`{"members": [{"value": "alice"}, {"value": "bob"}]}`)
	d.status.Store(http.StatusOK)
	d.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		d.calls.Add(1)
		d.lastReq.Store(req.Clone(context.Background()))
		if loc := d.redirect.Load(); loc != nil {
			w.Header().Set("Location", *loc)
			w.WriteHeader(http.StatusFound)
			return
		}
		status := int(d.status.Load())
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte(*d.body.Load()))
	}))
	t.Cleanup(d.server.Close)
	return d
}

func (d *directory) redirectTo(loc string) { d.redirect.Store(&loc) }

func (d *directory) answer(body string) { d.body.Store(&body) }

func (d *directory) url() string { return d.server.URL + "/scim/v2/Groups" }

func originOfURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

// hostSwap rewrites a test server URL to be reached by hostname instead of by
// its loopback literal, so the resolver — and therefore the pinning path — is
// actually exercised.
func hostSwap(t *testing.T, serverURL, host string) string {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("parse %q: %v", serverURL, err)
	}
	u.Host = host + ":" + u.Port()
	return u.String()
}

func groupDecl(target string) Declaration {
	return Declaration{
		Name:    "release_approvers",
		Issuer:  testIssuer,
		URL:     target,
		TTL:     time.Minute,
		Timeout: 2 * time.Second,
		Params:  []policy.Param{{Name: "group", Type: policy.TypeString}},
		Returns: policy.ListOf(policy.TypeString),
	}
}

func newGate(t *testing.T, cfg fact.EgressConfig) *fact.Gate {
	t.Helper()
	g, err := fact.NewGate(cfg)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	return g
}

// sourcesFor builds a loaded Sources against a stub directory, with the clock
// and the auditor the tests inspect.
func sourcesFor(t *testing.T, d *directory, mutate ...func(*Declaration)) (*Sources, *fakeClock, *recordingAuditor) {
	t.Helper()
	decl := groupDecl(d.url())
	for _, m := range mutate {
		m(&decl)
	}
	clock := newFakeClock()
	auditor := &recordingAuditor{}
	s, err := NewSources([]Declaration{decl}, SourcesConfig{
		Gate: newGate(t, fact.EgressConfig{
			Allow:         []string{originOfURL(t, d.url())},
			AllowLoopback: true,
			Resolve:       newFakeResolver().resolve,
		}),
		Issuers: []identity.IssuerConfig{{Issuer: testIssuer, JWKSURL: testIssuer + "/jwks"}},
		Now:     clock.now,
		Audit:   auditor,
	})
	if err != nil {
		t.Fatalf("NewSources: %v", err)
	}
	t.Cleanup(s.Close)
	return s, clock, auditor
}

func members(t *testing.T, v fact.Value) []string {
	t.Helper()
	if err := v.CheckType(policy.ListOf(policy.TypeString)); err != nil {
		t.Fatalf("returned value: %v", err)
	}
	items, _ := v.Data.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, _ := item.(string)
		out = append(out, s)
	}
	return out
}

func mustFailure(t *testing.T, err error) *fact.Failure {
	t.Helper()
	if err == nil {
		t.Fatal("expected a failure, got none")
	}
	var f *fact.Failure
	if !errors.As(err, &f) {
		t.Fatalf("error %v is not a *fact.Failure", err)
	}
	return f
}

func mustErr(_ fact.Value, err error) error { return err }

// --- the happy path ----------------------------------------------------------

func TestLookupReturnsGroupMembers(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "scim member objects",
			body: `{"members": [{"value": "alice"}, {"value": "bob"}]}`,
			want: []string{"alice", "bob"},
		},
		{
			name: "bare identifiers",
			body: `{"members": ["bob", "alice"]}`,
			want: []string{"alice", "bob"},
		},
		{
			name: "duplicates collapse to one member",
			body: `{"members": ["bob", "alice", "bob"]}`,
			want: []string{"alice", "bob"},
		},
		{
			name: "an empty group is an answer, not a failure",
			body: `{"members": []}`,
			want: []string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := newDirectory(t)
			d.answer(tc.body)
			s, _, _ := sourcesFor(t, d)

			v, err := s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall"))
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			got := members(t, v)
			if len(got) != len(tc.want) {
				t.Fatalf("members = %#v, want %#v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("members = %#v, want %#v", got, tc.want)
				}
			}
		})
	}
}

// The group identifier travels under the declared parameter name, and any query
// string the operator put on the endpoint survives beside it.
func TestGroupTravelsUnderTheDeclaredParameterName(t *testing.T) {
	d := newDirectory(t)
	s, _, _ := sourcesFor(t, d, func(decl *Declaration) {
		decl.URL = d.url() + "?excludedAttributes=meta"
	})

	if _, err := s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall")); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	q := d.lastReq.Load().URL.Query()
	if q.Get("group") != "sre-oncall" {
		t.Fatalf("group = %q, want %q", q.Get("group"), "sre-oncall")
	}
	if q.Get("excludedAttributes") != "meta" {
		t.Fatalf("the operator's own query string was dropped: %q", d.lastReq.Load().URL.RawQuery)
	}
}

// A configured answer field other than the SCIM default is honoured, because a
// directory's shape is operator configuration and not something a policy states.
func TestConfiguredAnswerShapeIsHonoured(t *testing.T) {
	d := newDirectory(t)
	d.answer(`{"Resources": [{"id": "carol"}]}`)
	s, _, _ := sourcesFor(t, d, func(decl *Declaration) {
		decl.MembersField = "Resources"
		decl.MemberIDField = "id"
	})

	v, err := s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got := members(t, v); len(got) != 1 || got[0] != "carol" {
		t.Fatalf("members = %#v", got)
	}
}

// --- the TTL -----------------------------------------------------------------

// U13's third scenario: a repeat resolution inside the TTL does not call the
// IdP again.
func TestRepeatedLookupInsideTheTTLDoesNotRecallTheDirectory(t *testing.T) {
	d := newDirectory(t)
	s, clock, _ := sourcesFor(t, d)

	for i := 0; i < 3; i++ {
		if _, err := s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall")); err != nil {
			t.Fatalf("Lookup %d: %v", i, err)
		}
		clock.advance(15 * time.Second)
	}
	if got := d.calls.Load(); got != 1 {
		t.Fatalf("directory calls = %d, want 1", got)
	}

	// A different group is a different question and is asked separately.
	if _, err := s.Lookup(context.Background(), "release_approvers", fact.String("payments-oncall")); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got := d.calls.Load(); got != 2 {
		t.Fatalf("directory calls = %d, want 2", got)
	}
}

// Membership staleness is a security property: past the TTL the answer is gone,
// and a directory that has since broken produces a failure rather than the
// membership as it stood before somebody was removed from it.
func TestExpiredMembershipIsNeverServedAsAFallback(t *testing.T) {
	d := newDirectory(t)
	s, clock, _ := sourcesFor(t, d)

	if _, err := s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall")); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	clock.advance(time.Minute + time.Second)
	d.status.Store(http.StatusInternalServerError)

	f := mustFailure(t, mustErr(s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall"))))
	if f.Reason != fact.ReasonStatus {
		t.Fatalf("reason = %q, want %q", f.Reason, fact.ReasonStatus)
	}
	if !f.FailsClosed() {
		t.Fatal("a directory failure must fail closed by default")
	}
}

// A failed lookup is not cached. Caching it would pin the outage for the length
// of a TTL in one direction, and pin a fail-open answer for the same length in
// the other.
func TestAFailedLookupIsNotCached(t *testing.T) {
	d := newDirectory(t)
	d.status.Store(http.StatusInternalServerError)
	s, _, _ := sourcesFor(t, d)

	_ = mustFailure(t, mustErr(s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall"))))
	d.status.Store(http.StatusOK)
	if _, err := s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall")); err != nil {
		t.Fatalf("second Lookup: %v", err)
	}
	if got := d.calls.Load(); got != 2 {
		t.Fatalf("directory calls = %d, want 2 — the failure was cached", got)
	}
}

// The cache is bounded because the group identifier reaches it from the request.
func TestTheMembershipCacheIsBounded(t *testing.T) {
	d := newDirectory(t)
	decl := groupDecl(d.url())
	clock := newFakeClock()
	s, err := NewSources([]Declaration{decl}, SourcesConfig{
		Gate: newGate(t, fact.EgressConfig{
			Allow:         []string{originOfURL(t, d.url())},
			AllowLoopback: true,
			Resolve:       newFakeResolver().resolve,
		}),
		Issuers:         []identity.IssuerConfig{{Issuer: testIssuer}},
		MaxCacheEntries: 4,
		Now:             clock.now,
	})
	if err != nil {
		t.Fatalf("NewSources: %v", err)
	}
	t.Cleanup(s.Close)

	for i := 0; i < 32; i++ {
		group := "group-" + strings.Repeat("x", i)
		if _, err := s.Lookup(context.Background(), "release_approvers", fact.String(group)); err != nil {
			t.Fatalf("Lookup %d: %v", i, err)
		}
	}
	if got := s.cache.len(); got > 4 {
		t.Fatalf("cache holds %d entries, want at most 4", got)
	}
}

// --- the egress gate ---------------------------------------------------------

// R35: a directory the operator allowlisted at an address nobody is permitted to
// mean is still refused, and it is refused at load rather than at the first
// call. Link-local is the metadata service; a private address is refused unless
// the deployment opted in.
func TestAGroupDirectoryAtAForbiddenAddressIsRefusedAtLoad(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		private bool
	}{
		{"link-local, which no configuration opens", "http://169.254.169.254/scim/v2/Groups", true},
		{"the metadata service written as IPv4-mapped IPv6", "http://[::ffff:169.254.169.254]/scim/v2/Groups", true},
		{"a private address this deployment did not permit", "http://10.0.0.7:8080/scim/v2/Groups", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSources([]Declaration{groupDecl(tc.target)}, SourcesConfig{
				Gate: newGate(t, fact.EgressConfig{
					Allow:         []string{originOfURL(t, tc.target)},
					AllowLoopback: true,
					AllowPrivate:  tc.private,
					Resolve:       newFakeResolver().resolve,
				}),
				Issuers: []identity.IssuerConfig{{Issuer: testIssuer}},
			})
			if err == nil {
				t.Fatal("a directory at a forbidden address loaded")
			}
			if !errors.Is(err, fact.ErrLoad) || !errors.Is(err, fact.ErrBlocked) {
				t.Fatalf("error = %v, want a load rejection wrapping the egress refusal", err)
			}
		})
	}
}

// A destination that is not on the allowlist at all is refused, whatever it
// resolves to. The policy author names a declared source; the operator names
// where that source is.
func TestADirectoryOffTheAllowlistIsRefusedAtLoad(t *testing.T) {
	d := newDirectory(t)
	_, err := NewSources([]Declaration{groupDecl(d.url())}, SourcesConfig{
		Gate: newGate(t, fact.EgressConfig{
			Allow:         []string{"https://directory.example.test:443"},
			AllowLoopback: true,
			Resolve:       newFakeResolver().resolve,
		}),
		Issuers: []identity.IssuerConfig{{Issuer: testIssuer}},
	})
	if !errors.Is(err, fact.ErrBlocked) {
		t.Fatalf("error = %v, want an egress refusal", err)
	}
	if d.calls.Load() != 0 {
		t.Fatal("the directory was called during a load that should have refused it")
	}
}

// R35: the resolved address is pinned in the dialler. Here the name passes the
// load-time preflight against a permitted address and then, between load and
// call, starts answering with a link-local one — which is what a rebinding
// attack looks like from inside the process. The dial has to be refused on the
// address it is about to use, which is the proof that this source's calls go
// through the gate's client rather than one of its own.
func TestDNSRebindingOnTheDirectoryIsRefusedAtDial(t *testing.T) {
	d := newDirectory(t)
	target := hostSwap(t, d.url(), "directory.test")
	res := newFakeResolver()
	res.set("directory.test", "127.0.0.1") // benign at load

	auditor := &recordingAuditor{}
	s, err := NewSources([]Declaration{groupDecl(target)}, SourcesConfig{
		Gate: newGate(t, fact.EgressConfig{
			Allow:         []string{originOfURL(t, target)},
			AllowLoopback: true,
			Resolve:       res.resolve,
		}),
		Issuers: []identity.IssuerConfig{{Issuer: testIssuer}},
		Audit:   auditor,
	})
	if err != nil {
		t.Fatalf("NewSources: %v", err)
	}
	t.Cleanup(s.Close)

	res.set("directory.test", "169.254.169.254") // hostile at call

	f := mustFailure(t, mustErr(s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall"))))
	if f.Reason != fact.ReasonEgressBlocked {
		t.Fatalf("reason = %q, want %q (error: %v)", f.Reason, fact.ReasonEgressBlocked, f)
	}
	if !f.FailsClosed() {
		t.Fatal("a blocked dial must fail closed")
	}
	if d.calls.Load() != 0 {
		t.Fatal("the call reached a server the gate should never have dialled")
	}
	if len(auditor.all()) != 1 {
		t.Fatalf("expected the refusal to be audited, got %d records", len(auditor.all()))
	}
}

// A redirect is a destination the operator did not allow, chosen by whoever
// answered the call.
func TestARedirectingDirectoryIsNotFollowed(t *testing.T) {
	var elsewhere atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere.Add(1)
		_, _ = w.Write([]byte(`{"members": ["mallory"]}`))
	}))
	t.Cleanup(other.Close)

	d := newDirectory(t)
	d.redirectTo(other.URL + "/groups")
	s, _, _ := sourcesFor(t, d)

	f := mustFailure(t, mustErr(s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall"))))
	if f.Reason != fact.ReasonRedirect {
		t.Fatalf("reason = %q, want %q", f.Reason, fact.ReasonRedirect)
	}
	if elsewhere.Load() != 0 {
		t.Fatal("the redirect was followed to a destination nobody allowed")
	}
}

// --- credentials -------------------------------------------------------------

// U6's rule: a fact call carries no ambient authority. With no credential
// configured, nothing that could authenticate this deployment goes out.
func TestNoCredentialTravelsWhenTheOperatorConfiguredNone(t *testing.T) {
	d := newDirectory(t)
	s, _, _ := sourcesFor(t, d)

	if _, err := s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall")); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	req := d.lastReq.Load()
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want none", got)
	}
	if len(req.Cookies()) != 0 {
		t.Fatalf("cookies travelled: %v", req.Cookies())
	}
}

// The operator's credential is presented to the operator's own endpoint, and it
// is not part of anything a policy can see: the schema half of the declaration
// carries no trace of it.
func TestTheOperatorCredentialTravelsAndStaysOutOfTheSchemaHalf(t *testing.T) {
	const authValue = "directory-issued-opaque-string"
	d := newDirectory(t)
	s, _, _ := sourcesFor(t, d, func(decl *Declaration) { decl.Credential = authValue })

	if _, err := s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall")); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got := d.lastReq.Load().Header.Get("Authorization"); got != "Bearer "+authValue {
		t.Fatalf("Authorization = %q", got)
	}

	decl, ok := s.Declaration("release_approvers")
	if !ok {
		t.Fatal("the declaration is not configured")
	}
	sd := decl.SourceDecl()
	if sd.Kind != policy.SourceIdPGroup {
		t.Fatalf("kind = %q, want %q", sd.Kind, policy.SourceIdPGroup)
	}
	if strings.Contains(strings.ToLower(sd.Name), "bearer") {
		t.Fatal("unreachable, but keeps the assertion honest about what is compared")
	}
}

// --- what the directory may answer -------------------------------------------

func TestBadDirectoryAnswersAreRefused(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		reason fact.Reason
	}{
		{"an unknown group", http.StatusNotFound, "", ReasonUnknownGroup},
		{"our credential refused", http.StatusUnauthorized, "", ReasonDirectoryDenied},
		{"our credential forbidden", http.StatusForbidden, "", ReasonDirectoryDenied},
		{"any other bad status", http.StatusBadGateway, "", fact.ReasonStatus},
		{"not JSON at all", http.StatusOK, `<html>login</html>`, fact.ReasonDecode},
		{"no member field", http.StatusOK, `{"schemas": []}`, fact.ReasonDecode},
		{"a member that is a number", http.StatusOK, `{"members": [7]}`, fact.ReasonDecode},
		{"a member object with no identifier", http.StatusOK, `{"members": [{"display": "alice"}]}`, fact.ReasonDecode},
		{"a blank identifier", http.StatusOK, `{"members": ["  "]}`, fact.ReasonDecode},
		{"a paginated answer", http.StatusOK, `{"totalResults": 9, "members": ["alice"]}`, ReasonDirectoryPaged},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := newDirectory(t)
			d.status.Store(int64(tc.status))
			if tc.body != "" {
				d.answer(tc.body)
			}
			s, _, auditor := sourcesFor(t, d)

			f := mustFailure(t, mustErr(s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall"))))
			if f.Reason != tc.reason {
				t.Fatalf("reason = %q, want %q (error: %v)", f.Reason, tc.reason, f)
			}
			if !f.FailsClosed() {
				t.Fatal("the default failure behaviour must be deny")
			}
			if got := auditor.all(); len(got) != 1 || got[0].AuditReason() != string(tc.reason) {
				t.Fatalf("audit records = %#v", got)
			}
		})
	}
}

// A page reported as complete is not a page. totalResults matching what came
// back is the ordinary case and must not be mistaken for truncation.
func TestACompleteAnswerReportingItsTotalIsAccepted(t *testing.T) {
	d := newDirectory(t)
	d.answer(`{"totalResults": 2, "members": ["alice", "bob"]}`)
	s, _, _ := sourcesFor(t, d)

	v, err := s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got := members(t, v); len(got) != 2 {
		t.Fatalf("members = %#v", got)
	}
}

func TestAnOversizedAnswerIsRefused(t *testing.T) {
	d := newDirectory(t)
	d.answer(`{"members": ["` + strings.Repeat("a", 4096) + `"]}`)
	decl := groupDecl(d.url())
	s, err := NewSources([]Declaration{decl}, SourcesConfig{
		Gate: newGate(t, fact.EgressConfig{
			Allow:         []string{originOfURL(t, d.url())},
			AllowLoopback: true,
			Resolve:       newFakeResolver().resolve,
		}),
		Issuers:          []identity.IssuerConfig{{Issuer: testIssuer}},
		MaxResponseBytes: 256,
	})
	if err != nil {
		t.Fatalf("NewSources: %v", err)
	}
	t.Cleanup(s.Close)

	f := mustFailure(t, mustErr(s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall"))))
	if f.Reason != fact.ReasonTooLarge {
		t.Fatalf("reason = %q, want %q", f.Reason, fact.ReasonTooLarge)
	}
}

func TestTooManyMembersIsRefused(t *testing.T) {
	d := newDirectory(t)
	d.answer(`{"members": ["alice", "bob", "carol"]}`)
	s, err := NewSources([]Declaration{groupDecl(d.url())}, SourcesConfig{
		Gate: newGate(t, fact.EgressConfig{
			Allow:         []string{originOfURL(t, d.url())},
			AllowLoopback: true,
			Resolve:       newFakeResolver().resolve,
		}),
		Issuers:    []identity.IssuerConfig{{Issuer: testIssuer}},
		MaxMembers: 2,
	})
	if err != nil {
		t.Fatalf("NewSources: %v", err)
	}
	t.Cleanup(s.Close)

	f := mustFailure(t, mustErr(s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall"))))
	if f.Reason != fact.ReasonDecode {
		t.Fatalf("reason = %q, want %q", f.Reason, fact.ReasonDecode)
	}
}

// The timeout is the declaration's, and a call that runs past it is reported as
// that timeout rather than as a generic transport error.
func TestTheDeclaredTimeoutBoundsOneCall(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = w.Write([]byte(`{"members": ["alice"]}`))
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})

	decl := groupDecl(server.URL + "/groups")
	decl.Timeout = 30 * time.Millisecond
	s, err := NewSources([]Declaration{decl}, SourcesConfig{
		Gate: newGate(t, fact.EgressConfig{
			Allow:         []string{originOfURL(t, server.URL)},
			AllowLoopback: true,
			Resolve:       newFakeResolver().resolve,
		}),
		Issuers: []identity.IssuerConfig{{Issuer: testIssuer}},
	})
	if err != nil {
		t.Fatalf("NewSources: %v", err)
	}
	t.Cleanup(s.Close)

	f := mustFailure(t, mustErr(s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall"))))
	if f.Reason != fact.ReasonTimeout {
		t.Fatalf("reason = %q, want %q (error: %v)", f.Reason, fact.ReasonTimeout, f)
	}
}

// --- the load gate -----------------------------------------------------------

func TestTheLoadGateRefusesWhatTheOperatorDidNotGrant(t *testing.T) {
	d := newDirectory(t)
	tests := []struct {
		name   string
		mutate func(*Declaration)
		want   string
	}{
		{"no ttl", func(dc *Declaration) { dc.TTL = 0 }, "ttl must be positive"},
		{"a ttl past the revocation budget", func(dc *Declaration) { dc.TTL = time.Hour }, "exceeds the maximum"},
		{"no timeout", func(dc *Declaration) { dc.Timeout = 0 }, "timeout must be positive"},
		{"no url", func(dc *Declaration) { dc.URL = "" }, "url is required"},
		{"no issuer", func(dc *Declaration) { dc.Issuer = "" }, "no issuer is configured"},
		{"an untrusted issuer", func(dc *Declaration) { dc.Issuer = "https://other.example" }, "is not trusted"},
		{"the wrong return type", func(dc *Declaration) { dc.Returns = policy.TypeString }, "a group source returns"},
		{"no parameter", func(dc *Declaration) { dc.Params = nil }, "exactly one string parameter"},
		{"two parameters", func(dc *Declaration) {
			dc.Params = append(dc.Params, policy.Param{Name: "tenant", Type: policy.TypeString})
		}, "exactly one string parameter"},
		{"a non-string parameter", func(dc *Declaration) {
			dc.Params = []policy.Param{{Name: "group", Type: policy.TypeInt}}
		}, "exactly one string parameter"},
		{"a name that is not an identifier", func(dc *Declaration) { dc.Name = "release approvers" }, "not a valid identifier"},
		{"fail-open without the operator flag", func(dc *Declaration) { dc.OnError = policy.OnErrorAllow }, "operator fail-open flag"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decl := groupDecl(d.url())
			tc.mutate(&decl)
			_, err := NewSources([]Declaration{decl}, SourcesConfig{
				Gate: newGate(t, fact.EgressConfig{
					Allow:         []string{originOfURL(t, d.url())},
					AllowLoopback: true,
					Resolve:       newFakeResolver().resolve,
				}),
				Issuers: []identity.IssuerConfig{{Issuer: testIssuer}},
			})
			if err == nil {
				t.Fatal("the declaration loaded")
			}
			if !errors.Is(err, fact.ErrLoad) {
				t.Fatalf("error = %v, want a load rejection", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// The operator flag admits fail-open, exactly as it does in the synchronous
// plane. What it admits is a condition answer, not an approver set — the
// approver path is checked separately.
func TestFailOpenLoadsOnlyWithTheOperatorFlag(t *testing.T) {
	d := newDirectory(t)
	decl := groupDecl(d.url())
	decl.OnError = policy.OnErrorAllow
	s, err := NewSources([]Declaration{decl}, SourcesConfig{
		Gate: newGate(t, fact.EgressConfig{
			Allow:         []string{originOfURL(t, d.url())},
			AllowLoopback: true,
			Resolve:       newFakeResolver().resolve,
		}),
		Issuers:       []identity.IssuerConfig{{Issuer: testIssuer}},
		AllowFailOpen: true,
	})
	if err != nil {
		t.Fatalf("NewSources: %v", err)
	}
	t.Cleanup(s.Close)

	d.status.Store(http.StatusInternalServerError)
	f := mustFailure(t, mustErr(s.Lookup(context.Background(), "release_approvers", fact.String("sre-oncall"))))
	if f.FailsClosed() {
		t.Fatal("a declaration the operator admitted as fail-open reports FailsClosed")
	}
}

func TestDuplicateDeclarationsAreRefused(t *testing.T) {
	d := newDirectory(t)
	_, err := NewSources([]Declaration{groupDecl(d.url()), groupDecl(d.url())}, SourcesConfig{
		Gate: newGate(t, fact.EgressConfig{
			Allow:         []string{originOfURL(t, d.url())},
			AllowLoopback: true,
			Resolve:       newFakeResolver().resolve,
		}),
		Issuers: []identity.IssuerConfig{{Issuer: testIssuer}},
	})
	if err == nil || !strings.Contains(err.Error(), "declared more than once") {
		t.Fatalf("error = %v", err)
	}
}

func TestSourcesNeedAGateAndAnIssuerSet(t *testing.T) {
	d := newDirectory(t)
	if _, err := NewSources(nil, SourcesConfig{
		Issuers: []identity.IssuerConfig{{Issuer: testIssuer}},
	}); !errors.Is(err, fact.ErrLoad) {
		t.Fatalf("error = %v, want a load rejection for the missing gate", err)
	}
	if _, err := NewSources(nil, SourcesConfig{
		Gate: newGate(t, fact.EgressConfig{Allow: []string{originOfURL(t, d.url())}, AllowLoopback: true}),
	}); !errors.Is(err, fact.ErrLoad) {
		t.Fatalf("error = %v, want a load rejection for the missing issuer set", err)
	}
}

// --- the schema gate ---------------------------------------------------------

func TestVerifySchemaChecksTheGroupSourcesAndOnlyThose(t *testing.T) {
	d := newDirectory(t)
	s, _, _ := sourcesFor(t, d)
	configured := mustDecl(t, s, "release_approvers").SourceDecl()

	t.Run("a matching schema passes", func(t *testing.T) {
		if err := s.VerifySchema(&policy.Schema{Sources: []policy.SourceDecl{configured}}); err != nil {
			t.Fatalf("VerifySchema: %v", err)
		}
	})
	t.Run("a group source this deployment does not configure is refused", func(t *testing.T) {
		other := configured
		other.Name = "finance_approvers"
		err := s.VerifySchema(&policy.Schema{Sources: []policy.SourceDecl{other}})
		if !errors.Is(err, fact.ErrLoad) || !strings.Contains(err.Error(), "not configured on this deployment") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("a signature that disagrees is refused", func(t *testing.T) {
		other := configured
		other.Params = []policy.Param{{Name: "team", Type: policy.TypeString}}
		err := s.VerifySchema(&policy.Schema{Sources: []policy.SourceDecl{other}})
		if !errors.Is(err, fact.ErrLoad) || !strings.Contains(err.Error(), "parameter 0") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("sources of other kinds belong to other planes", func(t *testing.T) {
		http := policy.SourceDecl{
			Name: "whitelist", Kind: policy.SourceHTTP,
			Returns: policy.ListOf(policy.TypeString), OnError: policy.OnErrorDeny,
		}
		if err := s.VerifySchema(&policy.Schema{Sources: []policy.SourceDecl{http}}); err != nil {
			t.Fatalf("VerifySchema: %v", err)
		}
	})
	t.Run("a nil schema is nothing to check", func(t *testing.T) {
		if err := s.VerifySchema(nil); err != nil {
			t.Fatalf("VerifySchema: %v", err)
		}
	})
}

func mustDecl(t *testing.T, s *Sources, name string) Declaration {
	t.Helper()
	decl, ok := s.Declaration(name)
	if !ok {
		t.Fatalf("source %q is not configured", name)
	}
	return decl
}

func TestNamesReportsTheConfiguredSources(t *testing.T) {
	d := newDirectory(t)
	s, _, _ := sourcesFor(t, d)
	got := s.Names()
	if len(got) != 1 || got[0] != "release_approvers" {
		t.Fatalf("Names = %#v", got)
	}
}

// --- the condition path ------------------------------------------------------

// R16 also puts this source in ordinary conditions, so a batch that mixes it
// with the synchronous plane's sources has to come back whole.
func TestResolveSourcesAnswersItsOwnAndDelegatesTheRest(t *testing.T) {
	d := newDirectory(t)
	decl := groupDecl(d.url())
	fallback := resolverFunc(func(_ context.Context, calls []engine.SourceCall) (*engine.Facts, error) {
		facts := engine.NewFacts()
		for _, c := range calls {
			facts.Set(c, true)
		}
		return facts, nil
	})
	s, err := NewSources([]Declaration{decl}, SourcesConfig{
		Gate: newGate(t, fact.EgressConfig{
			Allow:         []string{originOfURL(t, d.url())},
			AllowLoopback: true,
			Resolve:       newFakeResolver().resolve,
		}),
		Issuers:  []identity.IssuerConfig{{Issuer: testIssuer}},
		Fallback: fallback,
	})
	if err != nil {
		t.Fatalf("NewSources: %v", err)
	}
	t.Cleanup(s.Close)

	mine := engine.SourceCall{Name: "release_approvers", Args: []any{"sre-oncall"}}
	theirs := engine.SourceCall{Name: "whitelist", Args: []any{"acct-1"}}
	facts, err := s.ResolveSources(context.Background(), []engine.SourceCall{mine, theirs})
	if err != nil {
		t.Fatalf("ResolveSources: %v", err)
	}
	got, ok := facts.Value(mine)
	if !ok {
		t.Fatal("the group source was not answered")
	}
	items, _ := got.([]any)
	if len(items) != 2 || items[0] != "alice" {
		t.Fatalf("members = %#v", got)
	}
	if v, ok := facts.Value(theirs); !ok || v != true {
		t.Fatalf("the delegated call came back as %#v (ok=%v)", v, ok)
	}
}

func TestResolveSourcesWithoutAFallbackRefusesAnUnknownName(t *testing.T) {
	d := newDirectory(t)
	s, _, _ := sourcesFor(t, d)
	_, err := s.ResolveSources(context.Background(), []engine.SourceCall{{Name: "whitelist", Args: []any{"x"}}})
	if err == nil || !strings.Contains(err.Error(), "not configured on this deployment") {
		t.Fatalf("error = %v", err)
	}
}

func TestLookupRefusesAnUnknownSourceAndABadArgument(t *testing.T) {
	d := newDirectory(t)
	s, _, _ := sourcesFor(t, d)

	f := mustFailure(t, mustErr(s.Lookup(context.Background(), "nope", fact.String("g"))))
	if f.Reason != fact.ReasonUnknownSource {
		t.Fatalf("reason = %q", f.Reason)
	}
	for _, args := range [][]fact.Value{
		{},
		{fact.String("a"), fact.String("b")},
		{fact.Int(7)},
		{fact.String("   ")},
	} {
		f := mustFailure(t, mustErr(s.Lookup(context.Background(), "release_approvers", args...)))
		if f.Reason != fact.ReasonBadArgument {
			t.Fatalf("args %#v: reason = %q, want %q", args, f.Reason, fact.ReasonBadArgument)
		}
	}
}

// trustedIssuers is the deployment's pinned issuer set as the identity layer
// states it. A group source bound to anything outside it is refused at load.
func trustedIssuers() []identity.IssuerConfig {
	return []identity.IssuerConfig{{Issuer: testIssuer, JWKSURL: testIssuer + "/jwks"}}
}
