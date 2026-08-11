package fact

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/policy"
)

// httpDecl is a well-formed http declaration pointed at url.
func httpDecl(url string) Declaration {
	return Declaration{
		Name:    "risk",
		Kind:    policy.SourceHTTP,
		Returns: policy.TypeInt,
		TTL:     time.Minute,
		Timeout: 2 * time.Second,
		URL:     url,
	}
}

// --- the address ranges a fact call may never reach --------------------------

// R35, AE12: a link-local destination is refused at load. Being on the operator
// allowlist does not buy an exemption — the allowlist says which destinations
// the operator meant to permit, and the range rules say which destinations
// nobody is permitted to mean. 169.254.169.254 is the cloud metadata endpoint,
// which is the whole reason this rule exists.
func TestLinkLocalDestinationIsRejectedAtLoad(t *testing.T) {
	targets := []string{
		"http://169.254.169.254:80/latest/meta-data/iam/security-credentials/",
		"http://[fe80::1]:80/fact",
		// The IPv4-mapped spelling of the metadata address. A range check that
		// forgets to unmap admits this one.
		"http://[::ffff:169.254.169.254]:80/latest/meta-data/",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			cfg := Config{Egress: EgressConfig{
				Allow:         []string{originOfURL(t, target)},
				AllowLoopback: true,
				AllowPrivate:  true, // even the loosest operator posture keeps link-local out
				Resolve:       newFakeResolver().resolve,
			}}
			if _, err := NewRegistry([]Declaration{httpDecl(target)}, cfg); err == nil {
				t.Fatal("expected a link-local destination to be rejected at load")
			} else if !errors.Is(err, ErrBlocked) {
				t.Fatalf("expected an egress refusal, got %v", err)
			}
		})
	}
}

func TestPrivateDestinationIsRejectedAtLoadByDefault(t *testing.T) {
	targets := []string{
		"http://10.0.0.5:80/fact",
		"http://172.16.9.9:80/fact",
		"http://192.168.1.1:80/fact",
		"http://[fd00::1]:80/fact",
		"http://127.0.0.1:80/fact",
		"http://0.0.0.0:80/fact",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			cfg := Config{Egress: EgressConfig{
				Allow:   []string{originOfURL(t, target)},
				Resolve: newFakeResolver().resolve,
			}}
			if _, err := NewRegistry([]Declaration{httpDecl(target)}, cfg); err == nil {
				t.Fatal("expected a private destination to be rejected at load")
			} else if !errors.Is(err, ErrBlocked) {
				t.Fatalf("expected an egress refusal, got %v", err)
			}
		})
	}
}

// A hostname is not a hiding place. The load-time preflight resolves the
// declared target so that "points at the metadata service" is caught by the
// same rule whether it was spelled as an address or as a name.
func TestHostnameResolvingToLinkLocalIsRejectedAtLoad(t *testing.T) {
	res := newFakeResolver()
	res.set("facts.example.com", "169.254.169.254")

	cfg := Config{Egress: EgressConfig{
		Allow:   []string{"https://facts.example.com:443"},
		Resolve: res.resolve,
	}}
	if _, err := NewRegistry([]Declaration{httpDecl("https://facts.example.com/fact")}, cfg); err == nil {
		t.Fatal("expected a hostname resolving to link-local to be rejected at load")
	} else if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected an egress refusal, got %v", err)
	}
}

// Resolution failing is not the same as resolution finding something forbidden.
// DNS is allowed to be down at process start; a deployment that refused to load
// because of it would turn a transient outage into a restart loop.
func TestUnresolvableHostnameIsNotALoadFailure(t *testing.T) {
	res := newFakeResolver()
	res.fail(errors.New("dns is having a day"))

	cfg := Config{Egress: EgressConfig{
		Allow:   []string{"https://facts.example.com:443"},
		Resolve: res.resolve,
	}}
	if _, err := NewRegistry([]Declaration{httpDecl("https://facts.example.com/fact")}, cfg); err != nil {
		t.Fatalf("expected load to survive a resolver outage: %v", err)
	}
}

// --- the allowlist -----------------------------------------------------------

func TestOriginNotOnTheAllowlistIsRejectedAtLoad(t *testing.T) {
	res := newFakeResolver()
	res.set("elsewhere.example.com", "203.0.113.7")

	cfg := Config{Egress: EgressConfig{
		Allow:   []string{"https://facts.example.com:443"},
		Resolve: res.resolve,
	}}
	if _, err := NewRegistry([]Declaration{httpDecl("https://elsewhere.example.com/fact")}, cfg); err == nil {
		t.Fatal("expected an unlisted origin to be rejected")
	} else if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected an egress refusal, got %v", err)
	}
}

func TestAllowlistMatchesExactly(t *testing.T) {
	gate, err := NewGate(EgressConfig{Allow: []string{"https://facts.example.com"}})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	allowed := []string{
		"https://facts.example.com/fact",
		"https://facts.example.com:443/fact?account=1",
		"https://FACTS.EXAMPLE.COM/fact", // host comparison is case-insensitive
	}
	for _, raw := range allowed {
		if err := gate.CheckURL(raw); err != nil {
			t.Errorf("CheckURL(%q) = %v, want nil", raw, err)
		}
	}
	refused := []string{
		"http://facts.example.com/fact",       // scheme differs
		"https://facts.example.com:8443/fact", // port differs
		"https://sub.facts.example.com/fact",  // no implicit subdomains
		"https://facts.example.com.evil.test/fact",
		"file:///etc/passwd",
		"gopher://facts.example.com/fact",
		"https://user:pw@facts.example.com/fact", // credentials in the URL
		"://not a url",
	}
	for _, raw := range refused {
		if err := gate.CheckURL(raw); err == nil {
			t.Errorf("CheckURL(%q) = nil, want a refusal", raw)
		} else if !errors.Is(err, ErrBlocked) {
			t.Errorf("CheckURL(%q) = %v, want an egress refusal", raw, err)
		}
	}
}

func TestMalformedAllowlistEntryIsRejectedAtLoad(t *testing.T) {
	entries := []string{
		"https://facts.example.com/some/path",
		"https://user:pw@facts.example.com",
		"ftp://facts.example.com",
		"facts.example.com",
	}
	for _, entry := range entries {
		t.Run(entry, func(t *testing.T) {
			if _, err := NewGate(EgressConfig{Allow: []string{entry}}); err == nil {
				t.Fatal("expected the allowlist entry to be rejected")
			}
			if _, err := NewRegistry(nil, Config{Egress: EgressConfig{Allow: []string{entry}}}); err == nil {
				t.Fatal("expected the registry to refuse to load")
			}
		})
	}
}

// --- DNS rebinding -----------------------------------------------------------

// R35: the resolved address is pinned before the dial. Here the name passes the
// load-time preflight against a permitted address and then, between load and
// call, starts answering with a private one — which is exactly what a rebinding
// attack looks like from inside the process. The dial has to be refused on the
// address it is about to use, not on the address it saw earlier.
func TestDNSRebindingIsRefusedAtDial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the fact call reached a server it should never have dialled")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	target := hostSwap(t, server.URL, "rebind.test")
	res := newFakeResolver()
	res.set("rebind.test", "127.0.0.1") // benign at load

	auditor := &recordingAuditor{}
	r, err := NewRegistry([]Declaration{httpDecl(target + "/fact")}, Config{
		Audit: auditor,
		Egress: EgressConfig{
			Allow:         []string{originOfURL(t, target)},
			AllowLoopback: true,
			Resolve:       res.resolve,
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	res.set("rebind.test", "10.0.0.7") // hostile at call

	f := mustFailure(t, mustErr(r.Lookup(context.Background(), "risk")))
	if f.Reason != ReasonEgressBlocked {
		t.Fatalf("reason = %q, want %q (error: %v)", f.Reason, ReasonEgressBlocked, f)
	}
	if !f.FailsClosed() {
		t.Fatal("a blocked dial must fail closed")
	}
	if len(auditor.all()) != 1 {
		t.Fatalf("expected the refusal to be audited, got %d records", len(auditor.all()))
	}
}

// A name that answers with a permitted address and a forbidden one at the same
// time is refused outright. Picking the permitted one would leave the outcome
// up to which record the attacker got the resolver to order first.
func TestOneForbiddenAddressPoisonsTheWholeAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the fact call reached a server it should never have dialled")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	target := hostSwap(t, server.URL, "split.test")
	res := newFakeResolver()
	res.set("split.test", "127.0.0.1")

	r, err := NewRegistry([]Declaration{httpDecl(target + "/fact")}, Config{Egress: EgressConfig{
		Allow:         []string{originOfURL(t, target)},
		AllowLoopback: true,
		Resolve:       res.resolve,
	}})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	res.set("split.test", "127.0.0.1", "169.254.169.254")

	f := mustFailure(t, mustErr(r.Lookup(context.Background(), "risk")))
	if f.Reason != ReasonEgressBlocked {
		t.Fatalf("reason = %q, want %q (error: %v)", f.Reason, ReasonEgressBlocked, f)
	}
}

// The dial goes to the address the gate resolved and approved, not to whatever
// the system resolver would say a moment later. The proof is that a hostname
// with no real DNS record reaches the loopback listener the fake resolver named.
func TestDialUsesTheResolvedAddress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value": 7}`))
	}))
	t.Cleanup(server.Close)

	target := hostSwap(t, server.URL, "pinned.invalid")
	res := newFakeResolver()
	res.set("pinned.invalid", "127.0.0.1")

	r, err := NewRegistry([]Declaration{httpDecl(target + "/fact")}, Config{Egress: EgressConfig{
		Allow:         []string{originOfURL(t, target)},
		AllowLoopback: true,
		Resolve:       res.resolve,
	}})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	v, err := r.Lookup(context.Background(), "risk")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if v.Data != int64(7) {
		t.Fatalf("value = %#v, want 7", v.Data)
	}
	if res.lookups() < 2 {
		t.Fatalf("expected the gate to resolve at load and again at dial, got %d lookups", res.lookups())
	}
}

// --- CheckAddr in isolation ---------------------------------------------------

func TestCheckAddrRanges(t *testing.T) {
	tests := []struct {
		addr      string
		loopback  bool
		private   bool
		permitted bool
	}{
		{addr: "203.0.113.7", permitted: true},
		{addr: "2001:db8::1", permitted: true},
		{addr: "169.254.169.254", loopback: true, private: true, permitted: false},
		{addr: "fe80::1", loopback: true, private: true, permitted: false},
		{addr: "::ffff:169.254.169.254", private: true, permitted: false},
		{addr: "127.0.0.1", permitted: false},
		{addr: "127.0.0.1", loopback: true, permitted: true},
		{addr: "::1", loopback: true, permitted: true},
		{addr: "10.1.2.3", permitted: false},
		{addr: "10.1.2.3", private: true, permitted: true},
		{addr: "::ffff:10.1.2.3", permitted: false},
		{addr: "172.31.255.1", permitted: false},
		{addr: "192.168.0.1", permitted: false},
		{addr: "fd00::abcd", permitted: false},
		{addr: "0.0.0.0", loopback: true, private: true, permitted: false},
		{addr: "::", loopback: true, private: true, permitted: false},
		{addr: "255.255.255.255", private: true, permitted: false},
		{addr: "224.0.0.1", private: true, permitted: false},
		{addr: "ff02::1", private: true, permitted: false},
		{addr: "100.64.0.1", private: true, permitted: false},
		{addr: "192.0.0.1", private: true, permitted: false},
		{addr: "240.0.0.1", private: true, permitted: false},
	}
	for _, tc := range tests {
		name := tc.addr
		if tc.loopback {
			name += "+loopback"
		}
		if tc.private {
			name += "+private"
		}
		t.Run(name, func(t *testing.T) {
			gate, err := NewGate(EgressConfig{AllowLoopback: tc.loopback, AllowPrivate: tc.private})
			if err != nil {
				t.Fatalf("NewGate: %v", err)
			}
			addr, err := netip.ParseAddr(tc.addr)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = gate.CheckAddr(addr)
			if tc.permitted && err != nil {
				t.Fatalf("CheckAddr(%s) = %v, want nil", tc.addr, err)
			}
			if !tc.permitted && err == nil {
				t.Fatalf("CheckAddr(%s) = nil, want a refusal", tc.addr)
			}
		})
	}
}

// A name that fails to resolve at call time is a transport failure, not an
// egress refusal. Filing it as a refusal would bury genuine SSRF attempts in
// the audit trail under everybody's DNS outages.
func TestResolverOutageAtCallTimeIsATransportFailure(t *testing.T) {
	res := newFakeResolver()
	res.set("facts.test", "203.0.113.9")

	r, err := NewRegistry([]Declaration{httpDecl("https://facts.test/fact")}, Config{Egress: EgressConfig{
		Allow:   []string{"https://facts.test:443"},
		Resolve: res.resolve,
	}})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	res.fail(errors.New("dns is having a day"))

	f := mustFailure(t, mustErr(r.Lookup(context.Background(), "risk")))
	if f.Reason != ReasonTransport {
		t.Fatalf("reason = %q, want %q (error: %v)", f.Reason, ReasonTransport, f)
	}
}

// The call-time allowlist check is a second gate, not a restatement of the
// first. It is exercised directly because a registry built through the normal
// path can only hold sources the load-time check already admitted — which is
// exactly why the call-time check must be verified on its own rather than
// assumed to be unreachable.
func TestCallTimeAllowlistCheckStandsOnItsOwn(t *testing.T) {
	gate, err := NewGate(EgressConfig{Allow: []string{"https://allowed.test:443"}})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	source := newHTTPSource(httpDecl("https://revoked.test/fact"), gate, newEgressClient(gate), DefaultMaxResponseBytes)

	f := mustFailure(t, mustErr(source.Fetch(context.Background(), nil)))
	if f.Reason != ReasonEgressBlocked {
		t.Fatalf("reason = %q, want %q (error: %v)", f.Reason, ReasonEgressBlocked, f)
	}
}

// --- connection reuse and the address pin -------------------------------------
//
// These tests exist to settle one question before any performance knob is
// touched: does a pooled connection let a request skip the gate? They are read
// together, and the answer they add up to is written out in the comment above
// newEgressClient.

// countingListener is a test server that reports how many TCP connections it
// has accepted.
//
// Reuse is not observable from the client's return values — a reused connection
// and a fresh one produce the same response. The only honest measure of whether
// a request went through the dialler is how many times the far end was dialled.
type countingListener struct {
	*httptest.Server
	mu       sync.Mutex
	accepted int
}

func newCountingListener(t *testing.T, handler http.Handler) *countingListener {
	t.Helper()
	l := &countingListener{}
	srv := httptest.NewUnstartedServer(handler)
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state != http.StateNew {
			return
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		l.accepted++
	}
	srv.Start()
	t.Cleanup(srv.Close)
	l.Server = srv
	return l
}

func (l *countingListener) dials() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.accepted
}

// factHandler answers every request with the same well-formed envelope.
func factHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value": 7}`))
	})
}

// idleWatch reports when the transport hands a connection back to its pool.
//
// The tests below need to act after a connection has been pooled, and "the
// Fetch returned" is not that moment: the transport returns the connection from
// its read loop, on another goroutine. Waiting on the trace hook makes the
// sequencing a fact rather than a hope.
type idleWatch struct {
	returned chan error
}

func newIdleWatch(n int) *idleWatch {
	return &idleWatch{returned: make(chan error, n)}
}

func (w *idleWatch) context(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		PutIdleConn: func(err error) { w.returned <- err },
	})
}

// wait blocks until n connections have been offered back to the pool and
// reports how many of them the pool actually kept. A connection the pool
// refuses is one the next request has to dial again.
func (w *idleWatch) wait(t *testing.T, n int) int {
	t.Helper()
	kept := 0
	for i := 0; i < n; i++ {
		select {
		case err := <-w.returned:
			if err == nil {
				kept++
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d connections were offered back to the pool", i, n)
		}
	}
	return kept
}

// reuseGate builds a gate and the shared client the registry would build, for
// tests that need to drive sources by hand.
func reuseGate(t *testing.T, res *fakeResolver, origins ...string) (*Gate, *http.Client) {
	t.Helper()
	gate, err := NewGate(EgressConfig{
		Allow:         origins,
		AllowLoopback: true,
		Resolve:       res.resolve,
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	client := newEgressClient(gate)
	t.Cleanup(client.CloseIdleConnections)
	return gate, client
}

// The finding this unit was opened to establish: the address pin is a property
// of the socket, not of the request. A reused connection does not pass through
// Gate.DialContext a second time, so the resolve-and-check step does not re-run.
//
// The demonstration is deliberately hostile. Between the first call and the
// second, the name is rebound to a private address — the exact move
// TestDNSRebindingIsRefusedAtDial refuses — and the second call succeeds
// anyway, because it never dials. Emptying the pool puts the third call back
// through the dialler, and there the refusal lands.
//
// What the second call reached is worth being precise about, because it is the
// whole basis of the judgement recorded above newEgressClient: it reached the
// address the gate had already approved. A socket's peer cannot be changed by a
// DNS record. Reuse delays the effect of a rebinding; it does not carry a
// request anywhere the gate said no to.
func TestReusedConnectionDoesNotReRunTheAddressPin(t *testing.T) {
	server := newCountingListener(t, factHandler())
	target := hostSwap(t, server.URL, "reuse.test")

	res := newFakeResolver()
	res.set("reuse.test", "127.0.0.1")

	gate, client := reuseGate(t, res, originOfURL(t, target))
	source := newHTTPSource(httpDecl(target+"/fact"), gate, client, DefaultMaxResponseBytes)

	watch := newIdleWatch(1)
	if _, err := source.Fetch(watch.context(context.Background()), nil); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if kept := watch.wait(t, 1); kept != 1 {
		t.Fatal("the first connection was not pooled, so the rest of this test proves nothing")
	}
	if got := res.lookups(); got != 1 {
		t.Fatalf("resolver lookups after the first call = %d, want 1", got)
	}

	// Rebind. A fresh dial would now be refused.
	res.set("reuse.test", "10.0.0.7")

	if _, err := source.Fetch(context.Background(), nil); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if got := res.lookups(); got != 1 {
		t.Fatalf("the second call resolved again (%d lookups); it was expected to ride the pooled connection", got)
	}
	if got := server.dials(); got != 1 {
		t.Fatalf("the far end was dialled %d times, want 1 — the second call did not reuse", got)
	}

	// The moment the pool no longer holds the connection, the pin runs again and
	// the rebound name is refused. The gate is not bypassed; it is deferred to
	// the next dial.
	client.CloseIdleConnections()
	f := mustFailure(t, mustErr(source.Fetch(context.Background(), nil)))
	if f.Reason != ReasonEgressBlocked {
		t.Fatalf("reason = %q, want %q (error: %v)", f.Reason, ReasonEgressBlocked, f)
	}
	if got := server.dials(); got != 1 {
		t.Fatalf("the refused call still reached the listener (%d dials)", got)
	}
}

// The premise the whole judgement rests on. Go pools connections under a key
// that includes the requested host, so one host's request cannot inherit
// another host's connection — but a premise with no test is an assumption, and
// if this one were false, reuse would be pin bypass rather than pin deferral.
//
// Both names point at the same listener, on the same address and the same port,
// which is the case most likely to collapse into a shared pool entry if the key
// were the dialled address.
func TestDifferentHostsDoNotShareAConnection(t *testing.T) {
	server := newCountingListener(t, factHandler())
	first := hostSwap(t, server.URL, "first.test")
	second := hostSwap(t, server.URL, "second.test")

	res := newFakeResolver()
	res.set("first.test", "127.0.0.1")
	res.set("second.test", "127.0.0.1")

	gate, client := reuseGate(t, res, originOfURL(t, first), originOfURL(t, second))
	a := newHTTPSource(httpDecl(first+"/fact"), gate, client, DefaultMaxResponseBytes)
	b := newHTTPSource(httpDecl(second+"/fact"), gate, client, DefaultMaxResponseBytes)

	watch := newIdleWatch(2)
	if _, err := a.Fetch(watch.context(context.Background()), nil); err != nil {
		t.Fatalf("first.test: %v", err)
	}
	watch.wait(t, 1)

	if _, err := b.Fetch(watch.context(context.Background()), nil); err != nil {
		t.Fatalf("second.test: %v", err)
	}
	watch.wait(t, 1)

	if got := server.dials(); got != 2 {
		t.Fatalf("the listener was dialled %d times, want 2 — second.test rode first.test's connection", got)
	}
	if got := res.lookups(); got != 2 {
		t.Fatalf("resolver lookups = %d, want 2 — the gate did not run for the second host", got)
	}

	// And a repeat of each host reuses its own connection rather than opening a
	// third.
	if _, err := a.Fetch(context.Background(), nil); err != nil {
		t.Fatalf("first.test again: %v", err)
	}
	if got := server.dials(); got != 2 {
		t.Fatalf("the listener was dialled %d times, want 2 — the repeat did not reuse", got)
	}
}

// The same premise stated as a refusal, which is the form that matters. A
// pooled, approved connection to a listener is sitting in the pool. A second
// host names that identical listener — same address, same port — and resolves
// into a private range. The gate has to refuse it, and the pooled connection
// must not become a way around that.
func TestABlockedHostCannotInheritAnApprovedConnection(t *testing.T) {
	server := newCountingListener(t, factHandler())
	approved := hostSwap(t, server.URL, "approved.test")
	blocked := hostSwap(t, server.URL, "blocked.test")

	res := newFakeResolver()
	res.set("approved.test", "127.0.0.1")
	res.set("blocked.test", "10.0.0.7")

	gate, client := reuseGate(t, res, originOfURL(t, approved), originOfURL(t, blocked))
	good := newHTTPSource(httpDecl(approved+"/fact"), gate, client, DefaultMaxResponseBytes)
	bad := newHTTPSource(httpDecl(blocked+"/fact"), gate, client, DefaultMaxResponseBytes)

	watch := newIdleWatch(1)
	if _, err := good.Fetch(watch.context(context.Background()), nil); err != nil {
		t.Fatalf("approved.test: %v", err)
	}
	if kept := watch.wait(t, 1); kept != 1 {
		t.Fatal("the approved connection was not pooled, so this test proves nothing")
	}

	f := mustFailure(t, mustErr(bad.Fetch(context.Background(), nil)))
	if f.Reason != ReasonEgressBlocked {
		t.Fatalf("reason = %q, want %q (error: %v)", f.Reason, ReasonEgressBlocked, f)
	}
	if !f.FailsClosed() {
		t.Fatal("a blocked dial must fail closed")
	}
	if got := server.dials(); got != 1 {
		t.Fatalf("the listener was dialled %d times, want 1 — the blocked host reached it", got)
	}
}

// The performance corollary, and the assertion that fails without
// MaxIdleConnsPerHost set: a burst wider than Go's default of two must leave
// every one of its connections in the pool, so that the next burst reuses them
// instead of opening a fresh socket per request.
//
// The first wave is held at a barrier so all of it is genuinely in flight at
// once — that is what makes the connections concurrent rather than sequential
// reuse of one. The count the test reads is how many of them the pool kept,
// which at the Go default would be two.
func TestABurstWiderThanTheDefaultKeepsItsConnections(t *testing.T) {
	const wave = 8

	var arrivals atomic.Int32
	allArrived := make(chan struct{})
	release := make(chan struct{})
	server := newCountingListener(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n := arrivals.Add(1); n <= wave {
			if n == wave {
				close(allArrived)
			}
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value": 7}`))
	}))
	target := hostSwap(t, server.URL, "burst.test")

	res := newFakeResolver()
	res.set("burst.test", "127.0.0.1")

	gate, client := reuseGate(t, res, originOfURL(t, target))
	source := newHTTPSource(httpDecl(target+"/fact"), gate, client, DefaultMaxResponseBytes)

	watch := newIdleWatch(2 * wave)
	fire := func(held bool) {
		t.Helper()
		var wg sync.WaitGroup
		errs := make(chan error, wave)
		for i := 0; i < wave; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := source.Fetch(watch.context(context.Background()), nil); err != nil {
					errs <- err
				}
			}()
		}
		if held {
			<-allArrived
			close(release)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("fetch: %v", err)
		}
	}

	fire(true)
	if kept := watch.wait(t, wave); kept != wave {
		t.Fatalf("the pool kept %d of %d connections; a burst wider than MaxIdleConnsPerHost throws the excess away", kept, wave)
	}
	if got := server.dials(); got != wave {
		t.Fatalf("the first wave opened %d connections, want %d", got, wave)
	}

	fire(false)
	watch.wait(t, wave)
	if got := server.dials(); got != wave {
		t.Fatalf("the second wave opened %d connections in total, want %d — it did not reuse", got, wave)
	}
}

// The transport's settings are the egress boundary as much as the gate is, and
// a field quietly dropped in an edit is not visible in any behavioural test that
// happens to pass anyway. This pins the ones whose absence would be a hole.
func TestEgressTransportIsConfiguredAsDocumented(t *testing.T) {
	gate, err := NewGate(EgressConfig{Allow: []string{"https://facts.test"}})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	client := newEgressClient(gate)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", client.Transport)
	}

	// An environment proxy would take the destination out of the dialler's
	// hands: the socket would go to the proxy and the hostname would be resolved
	// at the far end.
	if transport.Proxy != nil {
		t.Error("Proxy must be nil; an environment proxy undoes the address pin")
	}
	// The dialler is the gate's, which is what makes the pin apply to every
	// connection this transport opens. Asked for a link-local destination, it
	// has to refuse rather than dial.
	if _, err := transport.DialContext(context.Background(), "tcp", "169.254.169.254:80"); !errors.Is(err, ErrBlocked) {
		t.Errorf("the transport's dialler is not the gate's: dialling link-local gave %v", err)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig must be set")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must never be set; no configuration in this package turns verification off")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2", transport.TLSClientConfig.MinVersion)
	}
	// Left empty so the transport fills it in from the request URL — the
	// certificate is checked against the name the policy declared.
	if transport.TLSClientConfig.ServerName != "" {
		t.Errorf("ServerName = %q, want it left to the request URL", transport.TLSClientConfig.ServerName)
	}
	if transport.MaxIdleConns != egressMaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d", transport.MaxIdleConns, egressMaxIdleConns)
	}
	// Unset, this is Go's default of 2, which is the whole of issue #30.
	if transport.MaxIdleConnsPerHost != egressMaxIdleConns {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d", transport.MaxIdleConnsPerHost, egressMaxIdleConns)
	}
	// Bounds how long a pooled connection outlives the DNS answer that produced
	// it, for a deployment whose traffic is bursty enough to let it go idle.
	if transport.IdleConnTimeout != 30*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 30s", transport.IdleConnTimeout)
	}
	// HTTP/2 is not force-attempted. Its pool coalesces differently from
	// HTTP/1's, and TestDifferentHostsDoNotShareAConnection is a statement about
	// the pool this transport actually uses.
	if transport.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 must stay off; see the note above newEgressClient")
	}

	if client.Jar != nil {
		t.Error("Jar must be nil; a fact call carries no ambient authority")
	}
	if transport.MaxConnsPerHost != 0 {
		t.Errorf("MaxConnsPerHost = %d, want 0; a cap on open connections would make a busy host wait rather than dial", transport.MaxConnsPerHost)
	}
	if client.CheckRedirect == nil {
		t.Fatal("CheckRedirect must be set")
	}
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("CheckRedirect = %v, want http.ErrUseLastResponse", err)
	}
}

// The unset ForceAttemptHTTP2 field is checked above; this is the same fact
// observed on the wire, because "the field is false" and "these connections are
// HTTP/1.1" are only the same statement if you already know that supplying a
// DialContext and a TLSClientConfig suppresses the automatic upgrade.
//
// It matters because the pooling claims in this file are claims about the
// HTTP/1.1 pool. The server here offers HTTP/2 and would speak it if the client
// asked.
func TestEgressConnectionsAreHTTP11(t *testing.T) {
	var proto atomic.Value
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		proto.Store(req.Proto)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value": 7}`))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	target := hostSwap(t, server.URL, "example.com") // the name httptest's certificate carries
	res := newFakeResolver()
	res.set("example.com", "127.0.0.1")

	gate, err := NewGate(EgressConfig{
		Allow:         []string{originOfURL(t, target)},
		AllowLoopback: true,
		Resolve:       res.resolve,
		RootCAs:       certPool(t, server),
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	client := newEgressClient(gate)
	t.Cleanup(client.CloseIdleConnections)

	source := newHTTPSource(httpDecl(target+"/fact"), gate, client, DefaultMaxResponseBytes)
	if _, err := source.Fetch(context.Background(), nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := proto.Load(); got != "HTTP/1.1" {
		t.Fatalf("the fact call negotiated %v; the pooling reasoning in this file is about HTTP/1.1", got)
	}
}
