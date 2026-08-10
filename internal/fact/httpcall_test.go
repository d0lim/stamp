package fact

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/policy"
)

// --- the happy path ----------------------------------------------------------

func TestHTTPSourceReturnsTheDeclaredType(t *testing.T) {
	tests := []struct {
		name    string
		returns policy.Type
		body    string
		want    any
	}{
		{"bool", policy.TypeBool, `{"value": true}`, true},
		{"int", policy.TypeInt, `{"value": 42}`, int64(42)},
		{"double", policy.TypeDouble, `{"value": 1.5}`, 1.5},
		{"string", policy.TypeString, `{"value": "ok"}`, "ok"},
		{"duration", policy.TypeDuration, `{"value": "90s"}`, 90 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := registryFor(t, tc.returns, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			})
			v, err := r.Lookup(context.Background(), "risk")
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if v.Data != tc.want {
				t.Fatalf("value = %#v, want %#v", v.Data, tc.want)
			}
		})
	}
}

func TestHTTPSourceReturnsAList(t *testing.T) {
	r := registryFor(t, policy.ListOf(policy.TypeString), func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value": ["acct-1", "acct-2"]}`))
	})
	v, err := r.Lookup(context.Background(), "risk")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	items, ok := v.Data.([]any)
	if !ok || len(items) != 2 || items[0] != "acct-1" {
		t.Fatalf("value = %#v", v.Data)
	}
}

// Arguments travel as named query parameters, and a list argument travels as
// repeated parameters rather than a delimited string, so an element that
// contains the delimiter cannot be read back as two elements.
func TestArgumentsTravelUnderTheirDeclaredNames(t *testing.T) {
	var got atomic.Pointer[http.Request]
	decl := httpDeclWithParams(policy.TypeBool,
		policy.Param{Name: "account", Type: policy.TypeString},
		policy.Param{Name: "tags", Type: policy.ListOf(policy.TypeString)},
	)
	r := registryForDecl(t, decl, func(w http.ResponseWriter, req *http.Request) {
		got.Store(req)
		_, _ = w.Write([]byte(`{"value": true}`))
	})

	if _, err := r.Lookup(context.Background(), "risk",
		String("acct,1"), List(policy.TypeString, "a,b", "c")); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	q := got.Load().URL.Query()
	if q.Get("account") != "acct,1" {
		t.Fatalf("account = %q", q.Get("account"))
	}
	if tags := q["tags"]; len(tags) != 2 || tags[0] != "a,b" || tags[1] != "c" {
		t.Fatalf("tags = %#v, want two elements preserved verbatim", tags)
	}
}

// --- timeout -----------------------------------------------------------------

// AE5, R13: the timeout is the declaration's, the outcome is the declaration's
// default of deny, and the reason reaches the audit trail. An operator reading
// the log has to be able to tell "the whitelist was down" from "the account was
// not on the whitelist", and the audit reason is the only place that distinction
// survives.
func TestTimeoutDeniesAndRecordsTheAuditReason(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	auditor := &recordingAuditor{}
	decl := httpDeclWithParams(policy.ListOf(policy.TypeString))
	decl.Name = "account_whitelist"
	decl.Timeout = 40 * time.Millisecond

	r := registryForDeclWithConfig(t, decl, func(w http.ResponseWriter, req *http.Request) {
		select {
		case <-release:
		case <-req.Context().Done():
		case <-time.After(5 * time.Second):
		}
		_, _ = w.Write([]byte(`{"value": []}`))
	}, func(cfg *Config) { cfg.Audit = auditor })

	start := time.Now()
	_, err := r.Lookup(context.Background(), "account_whitelist")
	elapsed := time.Since(start)

	f := mustFailure(t, err)
	if f.Reason != ReasonTimeout {
		t.Fatalf("reason = %q, want %q (error: %v)", f.Reason, ReasonTimeout, f)
	}
	if !f.FailsClosed() {
		t.Fatal("a timed-out fact source must deny by default")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("the declared timeout did not bound the call: %v", elapsed)
	}

	records := auditor.all()
	if len(records) != 1 {
		t.Fatalf("expected one audit record, got %d", len(records))
	}
	if records[0].AuditReason() != string(ReasonTimeout) {
		t.Fatalf("audit reason = %q, want %q", records[0].AuditReason(), ReasonTimeout)
	}
	if records[0].Source != "account_whitelist" {
		t.Fatalf("audit record names source %q", records[0].Source)
	}
	if records[0].At.IsZero() {
		t.Fatal("audit record has no timestamp")
	}
}

// --- redirects ---------------------------------------------------------------

// AE12: a redirect is an answer, not a step. The second server is on the
// allowlist and would have been perfectly legal to declare directly, which is
// the point — the refusal is about not following, not about where it led.
func TestRedirectIsNotFollowed(t *testing.T) {
	var reached atomic.Bool
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		_, _ = w.Write([]byte(`{"value": 1}`))
	}))
	t.Cleanup(second.Close)

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, second.URL+"/fact", http.StatusFound)
	}))
	t.Cleanup(first.Close)

	res := newFakeResolver()
	res.set("first.test", "127.0.0.1")
	res.set("second.test", "127.0.0.1")
	firstURL := hostSwap(t, first.URL, "first.test")
	secondURL := hostSwap(t, second.URL, "second.test")

	r, err := NewRegistry([]Declaration{httpDecl(firstURL + "/fact")}, Config{Egress: EgressConfig{
		Allow:         []string{originOfURL(t, firstURL), originOfURL(t, secondURL), originOfURL(t, second.URL)},
		AllowLoopback: true,
		Resolve:       res.resolve,
	}})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	f := mustFailure(t, mustErr(r.Lookup(context.Background(), "risk")))
	if f.Reason != ReasonRedirect {
		t.Fatalf("reason = %q, want %q (error: %v)", f.Reason, ReasonRedirect, f)
	}
	if reached.Load() {
		t.Fatal("the redirect was followed")
	}
	if !f.FailsClosed() {
		t.Fatal("a redirected fact source must deny by default")
	}
}

// AE12 again, this time with the destination the requirement actually names.
// The same URL is refused twice by the same gate: once as a declared target at
// load, and once as a redirect destination at call time. Two arrival routes,
// one rule.
func TestRedirectToAnInternalHostIsRejectedAtLoadAndAtCall(t *testing.T) {
	const internal = "http://169.254.169.254/latest/meta-data/"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, internal, http.StatusFound)
	}))
	t.Cleanup(server.Close)

	res := newFakeResolver()
	res.set("facts.test", "127.0.0.1")
	target := hostSwap(t, server.URL, "facts.test")
	egress := EgressConfig{
		// The metadata origin is on the allowlist on purpose: the refusal must
		// not depend on an operator having remembered to leave it off.
		Allow:         []string{originOfURL(t, target), "http://169.254.169.254:80"},
		AllowLoopback: true,
		AllowPrivate:  true,
		Resolve:       res.resolve,
	}

	// At load.
	if _, err := NewRegistry([]Declaration{httpDecl(internal)}, Config{Egress: egress}); err == nil {
		t.Fatal("expected the internal host to be rejected as a declared target")
	} else if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected an egress refusal at load, got %v", err)
	}

	// At call.
	r, err := NewRegistry([]Declaration{httpDecl(target + "/fact")}, Config{Egress: egress})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	f := mustFailure(t, mustErr(r.Lookup(context.Background(), "risk")))
	if f.Reason != ReasonRedirect {
		t.Fatalf("reason = %q, want %q (error: %v)", f.Reason, ReasonRedirect, f)
	}
	if !strings.Contains(f.Detail, "not on the egress allowlist") {
		t.Fatalf("the refusal should say the destination would not have been permitted either: %q", f.Detail)
	}
}

// --- TLS ---------------------------------------------------------------------

// R35: the address is pinned before the dial, and the certificate is still
// checked against the hostname the policy named. The two are not in tension
// because the pin lives in the dialler — the transport layers TLS on top of the
// connection it is handed, using the URL's host as the server name. Rewriting
// the URL to the address would pin just as well and quietly verify against the
// wrong name, which is what the second half of this test is here to catch.
func TestTLSIsVerifiedAgainstTheOriginalHostname(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value": 9}`))
	}))
	t.Cleanup(server.Close)

	// httptest's certificate is issued for example.com and for 127.0.0.1.
	t.Run("the name on the certificate is accepted", func(t *testing.T) {
		res := newFakeResolver()
		res.set("example.com", "127.0.0.1")
		target := hostSwap(t, server.URL, "example.com")

		r, err := NewRegistry([]Declaration{httpDecl(target + "/fact")}, Config{Egress: EgressConfig{
			Allow:         []string{originOfURL(t, target)},
			AllowLoopback: true,
			Resolve:       res.resolve,
			RootCAs:       certPool(t, server),
		}})
		if err != nil {
			t.Fatalf("NewRegistry: %v", err)
		}
		t.Cleanup(r.Close)

		v, err := r.Lookup(context.Background(), "risk")
		if err != nil {
			t.Fatalf("Lookup over TLS to a pinned address: %v", err)
		}
		if v.Data != int64(9) {
			t.Fatalf("value = %#v", v.Data)
		}
	})

	// The same listener, the same pinned address, a hostname the certificate
	// does not cover. If verification followed the pinned address instead of
	// the hostname it would succeed here, because the certificate does cover
	// 127.0.0.1.
	t.Run("a name not on the certificate is refused", func(t *testing.T) {
		res := newFakeResolver()
		res.set("notthecert.example", "127.0.0.1")
		target := hostSwap(t, server.URL, "notthecert.example")

		r, err := NewRegistry([]Declaration{httpDecl(target + "/fact")}, Config{Egress: EgressConfig{
			Allow:         []string{originOfURL(t, target)},
			AllowLoopback: true,
			Resolve:       res.resolve,
			RootCAs:       certPool(t, server),
		}})
		if err != nil {
			t.Fatalf("NewRegistry: %v", err)
		}
		t.Cleanup(r.Close)

		f := mustFailure(t, mustErr(r.Lookup(context.Background(), "risk")))
		var hostErr x509.HostnameError
		if !errors.As(f, &hostErr) {
			t.Fatalf("expected a certificate hostname error, got %v", f)
		}
		if hostErr.Host != "notthecert.example" {
			t.Fatalf("verified against %q, want the hostname the policy named", hostErr.Host)
		}
	})

	// An untrusted issuer is still an untrusted issuer. There is no
	// configuration that turns verification off.
	t.Run("an untrusted issuer is refused", func(t *testing.T) {
		res := newFakeResolver()
		res.set("example.com", "127.0.0.1")
		target := hostSwap(t, server.URL, "example.com")

		r, err := NewRegistry([]Declaration{httpDecl(target + "/fact")}, Config{Egress: EgressConfig{
			Allow:         []string{originOfURL(t, target)},
			AllowLoopback: true,
			Resolve:       res.resolve,
			RootCAs:       x509.NewCertPool(),
		}})
		if err != nil {
			t.Fatalf("NewRegistry: %v", err)
		}
		t.Cleanup(r.Close)

		if _, err := r.Lookup(context.Background(), "risk"); err == nil {
			t.Fatal("expected an untrusted certificate to be refused")
		}
	})
}

// --- no ambient credentials ---------------------------------------------------

// R35: a fact call carries nothing the deployment would not hand a stranger.
// The proxy variables are set to a listener that fails the test if it is ever
// used, because an egress proxy would also defeat the address pin.
func TestFactCallCarriesNoAmbientCredentials(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the fact call went through the environment's proxy")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(proxy.Close)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)

	var headers atomic.Pointer[http.Header]
	r := registryFor(t, policy.TypeBool, func(w http.ResponseWriter, req *http.Request) {
		h := req.Header.Clone()
		headers.Store(&h)
		_, _ = w.Write([]byte(`{"value": true}`))
	})
	if _, err := r.Lookup(context.Background(), "risk"); err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	h := *headers.Load()
	for _, name := range []string{"Authorization", "Cookie", "Proxy-Authorization", "X-Api-Key"} {
		if v := h.Get(name); v != "" {
			t.Errorf("fact call carried %s: %q", name, v)
		}
	}
	if h.Get("Accept") != "application/json" {
		t.Errorf("Accept = %q", h.Get("Accept"))
	}
}

// --- responses that are not answers -------------------------------------------

func TestNonOKStatusFailsClosed(t *testing.T) {
	r := registryFor(t, policy.TypeBool, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	f := mustFailure(t, mustErr(r.Lookup(context.Background(), "risk")))
	if f.Reason != ReasonStatus {
		t.Fatalf("reason = %q, want %q", f.Reason, ReasonStatus)
	}
	if !f.FailsClosed() {
		t.Fatal("must fail closed")
	}
}

func TestOversizedResponseIsRefused(t *testing.T) {
	decl := httpDeclWithParams(policy.TypeString)
	r := registryForDeclWithConfig(t, decl, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value": "` + strings.Repeat("a", 4096) + `"}`))
	}, func(cfg *Config) { cfg.Egress.MaxResponseBytes = 512 })

	f := mustFailure(t, mustErr(r.Lookup(context.Background(), "risk")))
	if f.Reason != ReasonTooLarge {
		t.Fatalf("reason = %q, want %q", f.Reason, ReasonTooLarge)
	}
}

func TestUndecodableResponsesFailClosed(t *testing.T) {
	tests := []struct {
		name    string
		returns policy.Type
		body    string
	}{
		{"not json", policy.TypeInt, `<html>nope</html>`},
		{"no envelope", policy.TypeInt, `42`},
		{"no value field", policy.TypeInt, `{"result": 42}`},
		{"unknown envelope field", policy.TypeInt, `{"value": 42, "extra": 1}`},
		// A quoted number is not a number. Decoding straight into a json.Number
		// would accept this, which would hand the evaluator an int the endpoint
		// never sent as one.
		{"int quoted as a string", policy.TypeInt, `{"value": "42"}`},
		{"double quoted as a string", policy.TypeDouble, `{"value": "1.5"}`},
		{"string sent as a number", policy.TypeString, `{"value": 42}`},
		{"bool sent as a string", policy.TypeBool, `{"value": "true"}`},
		{"null", policy.TypeInt, `{"value": null}`},
		{"object where a scalar was declared", policy.TypeInt, `{"value": {"n": 1}}`},
		{"scalar where a list was declared", policy.ListOf(policy.TypeString), `{"value": "a"}`},
		{"fractional int", policy.TypeInt, `{"value": 1.5}`},
		{"heterogeneous list", policy.ListOf(policy.TypeString), `{"value": ["a", 2]}`},
		{"bad timestamp", policy.TypeTimestamp, `{"value": "yesterday"}`},
		{"bad duration", policy.TypeDuration, `{"value": "a fortnight"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := registryFor(t, tc.returns, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			})
			f := mustFailure(t, mustErr(r.Lookup(context.Background(), "risk")))
			if f.Reason != ReasonDecode {
				t.Fatalf("reason = %q, want %q (error: %v)", f.Reason, ReasonDecode, f)
			}
			if !f.FailsClosed() {
				t.Fatal("must fail closed")
			}
		})
	}
}

func TestTimestampsComeBackInUTC(t *testing.T) {
	r := registryFor(t, policy.TypeTimestamp, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value": "2026-08-10T21:00:00+09:00"}`))
	})
	v, err := r.Lookup(context.Background(), "risk")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	got, ok := v.Data.(time.Time)
	if !ok {
		t.Fatalf("value = %#v", v.Data)
	}
	if got.Location() != time.UTC || !got.Equal(time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("value = %v, want the same instant in UTC", got)
	}
}

// --- helpers -----------------------------------------------------------------

func httpDeclWithParams(returns policy.Type, params ...policy.Param) Declaration {
	return Declaration{
		Name:    "risk",
		Kind:    policy.SourceHTTP,
		Params:  params,
		Returns: returns,
		TTL:     time.Minute,
		Timeout: 2 * time.Second,
	}
}

// registryFor stands up a loopback fact endpoint reached by hostname, so the
// resolver and the pinning dialler are on the path in every HTTP test.
func registryFor(t *testing.T, returns policy.Type, handler http.HandlerFunc) *Registry {
	t.Helper()
	return registryForDecl(t, httpDeclWithParams(returns), handler)
}

func registryForDecl(t *testing.T, decl Declaration, handler http.HandlerFunc) *Registry {
	t.Helper()
	return registryForDeclWithConfig(t, decl, handler, nil)
}

func registryForDeclWithConfig(t *testing.T, decl Declaration, handler http.HandlerFunc, tweak func(*Config)) *Registry {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	res := newFakeResolver()
	res.set("facts.test", "127.0.0.1")
	target := hostSwap(t, server.URL, "facts.test")
	decl.URL = target + "/fact"

	cfg := Config{Egress: EgressConfig{
		Allow:         []string{originOfURL(t, target)},
		AllowLoopback: true,
		Resolve:       res.resolve,
	}}
	if tweak != nil {
		tweak(&cfg)
	}
	r, err := NewRegistry([]Declaration{decl}, cfg)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)
	return r
}
