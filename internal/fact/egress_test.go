package fact

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
