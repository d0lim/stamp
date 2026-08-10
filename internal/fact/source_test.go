package fact

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/policy"
)

// --- shared test helpers -----------------------------------------------------

// fakeResolver stands in for DNS. Every test that needs a hostname uses it, so
// no test reaches a real resolver, and the rebinding tests can change the answer
// between the load-time lookup and the call-time one.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	err     error
	calls   int
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

func (r *fakeResolver) fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

func (r *fakeResolver) resolve(_ context.Context, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	addrs, ok := r.answers[host]
	if !ok {
		return nil, errors.New("no such host: " + host)
	}
	out := make([]netip.Addr, len(addrs))
	copy(out, addrs)
	return out, nil
}

func (r *fakeResolver) lookups() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// fakeClock drives the TTL cache. Cache expiry is a property of declared time,
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

// recordingAuditor captures the failure records the registry emits.
type recordingAuditor struct {
	mu      sync.Mutex
	records []*Failure
}

func (a *recordingAuditor) RecordFactFailure(_ context.Context, f *Failure) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, f)
}

func (a *recordingAuditor) all() []*Failure {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*Failure, len(a.records))
	copy(out, a.records)
	return out
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

func originOfURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	origin, err := originOf(u)
	if err != nil {
		t.Fatalf("origin of %q: %v", raw, err)
	}
	return origin
}

func certPool(t *testing.T, server *httptest.Server) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return pool
}

// whitelistDecl is the running example from the requirements: an account
// whitelist a policy checks membership against.
func staticWhitelist(values ...any) Declaration {
	return Declaration{
		Name:    "account_whitelist",
		Kind:    policy.SourceStatic,
		Returns: policy.ListOf(policy.TypeString),
		Values:  values,
	}
}

func mustFailure(t *testing.T, err error) *Failure {
	t.Helper()
	if err == nil {
		t.Fatal("expected a failure, got nil")
	}
	var f *Failure
	if !errors.As(err, &f) {
		t.Fatalf("expected a *Failure, got %T: %v", err, err)
	}
	return f
}

// --- load-time gate: fail-open ----------------------------------------------

// R36: the declaration alone never grants fail-open. Without the operator flag
// the policy is refused at load, not at call time, because a refusal that
// arrives at call time arrives during the outage the declaration was for.
func TestFailOpenIsRejectedAtLoadWithoutOperatorFlag(t *testing.T) {
	decl := staticWhitelist("acct-1")
	decl.OnError = policy.OnErrorAllow

	_, err := NewRegistry([]Declaration{decl}, Config{})
	if err == nil {
		t.Fatal("expected the registry to reject a fail-open declaration at load")
	}
	if !errors.Is(err, ErrLoad) {
		t.Fatalf("expected a load error, got %v", err)
	}
}

func TestFailOpenIsAdmittedWithOperatorFlag(t *testing.T) {
	decl := staticWhitelist("acct-1")
	decl.OnError = policy.OnErrorAllow

	r, err := NewRegistry([]Declaration{decl}, Config{AllowFailOpen: true})
	if err != nil {
		t.Fatalf("expected the operator flag to admit the declaration: %v", err)
	}
	t.Cleanup(r.Close)

	got, ok := r.Declaration("account_whitelist")
	if !ok {
		t.Fatal("source is not registered")
	}
	if got.OnError != policy.OnErrorAllow {
		t.Fatalf("on_error = %q, want %q", got.OnError, policy.OnErrorAllow)
	}
}

// The failure behaviour a caller reads is the one the declaration fixed, and it
// travels with the failure so no call site has to re-derive it.
func TestFailureCarriesTheDeclaredBehaviour(t *testing.T) {
	t.Run("default is deny", func(t *testing.T) {
		r, err := NewRegistry(nil, Config{})
		if err != nil {
			t.Fatalf("NewRegistry: %v", err)
		}
		t.Cleanup(r.Close)
		f := mustFailure(t, mustErr(r.Lookup(context.Background(), "nope")))
		if !f.FailsClosed() {
			t.Fatal("an unknown source must fail closed")
		}
		if f.Reason != ReasonUnknownSource {
			t.Fatalf("reason = %q", f.Reason)
		}
	})

	t.Run("allow only with the flag", func(t *testing.T) {
		decl := Declaration{
			Name:    "flaky",
			Kind:    policy.SourceHTTP,
			Returns: policy.TypeBool,
			OnError: policy.OnErrorAllow,
			TTL:     time.Minute,
			Timeout: 50 * time.Millisecond,
			URL:     "http://dead.test:1/fact",
		}
		res := newFakeResolver()
		res.set("dead.test", "127.0.0.1")
		r, err := NewRegistry([]Declaration{decl}, Config{
			AllowFailOpen: true,
			Egress: EgressConfig{
				Allow:         []string{"http://dead.test:1"},
				AllowLoopback: true,
				Resolve:       res.resolve,
			},
		})
		if err != nil {
			t.Fatalf("NewRegistry: %v", err)
		}
		t.Cleanup(r.Close)
		f := mustFailure(t, mustErr(r.Lookup(context.Background(), "flaky")))
		if f.FailsClosed() {
			t.Fatalf("declaration asked to fail open and the operator allowed it; got %+v", f)
		}
	})
}

func mustErr(_ Value, err error) error { return err }

// --- load-time gate: schema verification ------------------------------------

func TestVerifySchemaRejectsFailOpenForEveryKind(t *testing.T) {
	r, err := NewRegistry(nil, Config{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	// An idp_group source is served by another unit, but the fail-open flag is
	// a property of the deployment, not of the implementation.
	schema := &policy.Schema{Sources: []policy.SourceDecl{{
		Name:    "admins",
		Kind:    policy.SourceIdPGroup,
		Returns: policy.ListOf(policy.TypeString),
		OnError: policy.OnErrorAllow,
	}}}
	if err := r.VerifySchema(schema); err == nil {
		t.Fatal("expected the schema to be rejected at load")
	} else if !errors.Is(err, ErrLoad) {
		t.Fatalf("expected a load error, got %v", err)
	}
}

func TestVerifySchemaRequiresAConfiguredSynchronousSource(t *testing.T) {
	r, err := NewRegistry(nil, Config{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	schema := &policy.Schema{Sources: []policy.SourceDecl{{
		Name:    "account_whitelist",
		Kind:    policy.SourceStatic,
		Returns: policy.ListOf(policy.TypeString),
		OnError: policy.OnErrorDeny,
	}}}
	if err := r.VerifySchema(schema); err == nil {
		t.Fatal("expected a schema naming an unconfigured source to be rejected")
	}
}

func TestVerifySchemaRejectsSignatureDrift(t *testing.T) {
	r, err := NewRegistry([]Declaration{staticWhitelist("a")}, Config{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	schema := &policy.Schema{Sources: []policy.SourceDecl{{
		Name:    "account_whitelist",
		Kind:    policy.SourceStatic,
		Returns: policy.ListOf(policy.TypeInt), // drifted from list<string>
		OnError: policy.OnErrorDeny,
	}}}
	if err := r.VerifySchema(schema); err == nil {
		t.Fatal("expected a return type mismatch to be rejected")
	}
}

func TestVerifySchemaAcceptsAMatchingDeployment(t *testing.T) {
	r, err := NewRegistry([]Declaration{staticWhitelist("a", "b")}, Config{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	schema := &policy.Schema{Sources: []policy.SourceDecl{{
		Name:    "account_whitelist",
		Kind:    policy.SourceStatic,
		Returns: policy.ListOf(policy.TypeString),
		OnError: policy.OnErrorDeny,
	}}}
	if err := r.VerifySchema(schema); err != nil {
		t.Fatalf("expected the schema to verify: %v", err)
	}
}

// --- load-time gate: declaration shape --------------------------------------

func TestLoadRejectsMalformedDeclarations(t *testing.T) {
	res := newFakeResolver()
	res.set("facts.test", "127.0.0.1")
	cfg := Config{Egress: EgressConfig{
		Allow:         []string{"http://facts.test:8080"},
		AllowLoopback: true,
		Resolve:       res.resolve,
	}}

	httpBase := Declaration{
		Name:    "risk",
		Kind:    policy.SourceHTTP,
		Returns: policy.TypeInt,
		TTL:     time.Minute,
		Timeout: time.Second,
		URL:     "http://facts.test:8080/risk",
	}

	tests := []struct {
		name string
		decl func() Declaration
	}{
		{"http without a ttl", func() Declaration { d := httpBase; d.TTL = 0; return d }},
		{"http without a timeout", func() Declaration { d := httpBase; d.Timeout = 0; return d }},
		{"http without a url", func() Declaration { d := httpBase; d.URL = ""; return d }},
		{"http carrying static values", func() Declaration { d := httpBase; d.Values = []any{"x"}; return d }},
		{"static with a ttl", func() Declaration { d := staticWhitelist("a"); d.TTL = time.Minute; return d }},
		{"static with a timeout", func() Declaration { d := staticWhitelist("a"); d.Timeout = time.Second; return d }},
		{"static with parameters", func() Declaration {
			d := staticWhitelist("a")
			d.Params = []policy.Param{{Name: "who", Type: policy.TypeString}}
			return d
		}},
		{"static returning a scalar", func() Declaration {
			d := staticWhitelist()
			d.Returns = policy.TypeString
			return d
		}},
		{"static with a mistyped value", func() Declaration { return staticWhitelist(int64(3)) }},
		{"event kind", func() Declaration { d := staticWhitelist("a"); d.Kind = policy.SourceEvent; return d }},
		{"idp group kind", func() Declaration { d := staticWhitelist("a"); d.Kind = policy.SourceIdPGroup; return d }},
		{"unknown kind", func() Declaration { d := staticWhitelist("a"); d.Kind = "carrier_pigeon"; return d }},
		{"invalid name", func() Declaration { d := staticWhitelist("a"); d.Name = "Account-Whitelist"; return d }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRegistry([]Declaration{tc.decl()}, cfg); err == nil {
				t.Fatal("expected the declaration to be rejected at load")
			} else if !errors.Is(err, ErrLoad) {
				t.Fatalf("expected a load error, got %v", err)
			}
		})
	}
}

func TestLoadRejectsDuplicateNames(t *testing.T) {
	if _, err := NewRegistry([]Declaration{staticWhitelist("a"), staticWhitelist("b")}, Config{}); err == nil {
		t.Fatal("expected a duplicate declaration to be rejected")
	}
}

func TestLoadCollectsEveryRejection(t *testing.T) {
	bad1 := staticWhitelist("a")
	bad1.Name = "One"
	bad2 := staticWhitelist("b")
	bad2.Name = "two"
	bad2.Returns = policy.TypeString

	_, err := NewRegistry([]Declaration{bad1, bad2}, Config{})
	if err == nil {
		t.Fatal("expected rejections")
	}
	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) || len(joined.Unwrap()) != 2 {
		t.Fatalf("expected both rejections to be reported in one pass, got %v", err)
	}
}

// --- argument handling -------------------------------------------------------

func TestArgumentMismatchFailsClosed(t *testing.T) {
	r, err := NewRegistry([]Declaration{staticWhitelist("a")}, Config{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	f := mustFailure(t, mustErr(r.Lookup(context.Background(), "account_whitelist", String("x"))))
	if f.Reason != ReasonBadArgument {
		t.Fatalf("reason = %q, want %q", f.Reason, ReasonBadArgument)
	}
	if !f.FailsClosed() {
		t.Fatal("a bad argument must fail closed")
	}
}

func TestNamesAndDeclarationExposeTheResolvedSurface(t *testing.T) {
	r, err := NewRegistry([]Declaration{staticWhitelist("a")}, Config{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	if names := r.Names(); len(names) != 1 || names[0] != "account_whitelist" {
		t.Fatalf("Names() = %v", names)
	}
	decl, ok := r.Declaration("account_whitelist")
	if !ok {
		t.Fatal("Declaration() missed a registered source")
	}
	if decl.SourceDecl().OnError != policy.DefaultOnError {
		t.Fatalf("an unspecified on_error must resolve to %q", policy.DefaultOnError)
	}
	if _, ok := r.Declaration("absent"); ok {
		t.Fatal("Declaration() invented a source")
	}
}

func TestFromSourceDeclCarriesTheSignature(t *testing.T) {
	sd := policy.SourceDecl{
		Name:    "risk",
		Kind:    policy.SourceHTTP,
		Params:  []policy.Param{{Name: "account", Type: policy.TypeString}},
		Returns: policy.TypeInt,
		OnError: policy.OnErrorDeny,
	}
	decl := FromSourceDecl(sd)
	if err := sameSignature(decl.SourceDecl(), sd); err != nil {
		t.Fatalf("round trip lost the signature: %v", err)
	}
	// The transport half stays empty: it is not the policy author's to write.
	if decl.URL != "" || decl.TTL != 0 || decl.Timeout != 0 || decl.Values != nil {
		t.Fatalf("FromSourceDecl filled in transport configuration: %+v", decl)
	}
}
