package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/d0lim/stamp/internal/api"
)

func testBundle() fstest.MapFS {
	return fstest.MapFS{
		"index.html":             {Data: []byte("<!doctype html><title>stamp</title>")},
		"assets/index-abc123.js": {Data: []byte("export const a = 1;\n")},
		"favicon.svg":            {Data: []byte("<svg/>")},
	}
}

func newTestConsole(t *testing.T, cfg api.ConsoleConfig) *api.Console {
	t.Helper()
	if cfg.Assets == nil {
		cfg.Assets = testBundle()
	}
	c, err := api.NewConsole(cfg)
	if err != nil {
		t.Fatalf("NewConsole: %v", err)
	}
	return c
}

// serveConsole routes a request through the console's own handlers, without the
// server, so these tests are about the console rather than about mounting.
func serveConsole(t *testing.T, c *api.Console, method, target string,
	headers map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	for _, r := range c.Routes() {
		mux.Handle(r.Pattern, r.Handler)
	}
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestConsoleConfigIsTheOnlySourceOfTheAPIBase is R50 from the server's side:
// the base address is in a document the server writes, and there is no request
// input that changes it.
func TestConsoleConfigIsTheOnlySourceOfTheAPIBase(t *testing.T) {
	t.Parallel()
	c := newTestConsole(t, api.ConsoleConfig{APIBaseURL: "https://api.example.com"})

	// Every one of these is a channel whoever can hand an approver a link
	// controls. None of them is read. The fragment is not in the list because a
	// fragment never reaches a server at all — which is exactly why it has to
	// be refused in the browser, and the console's own tests do that.
	targets := []string{
		api.ConsoleConfigPath,
		api.ConsoleConfigPath + "?apiBaseUrl=https://attacker.example",
		api.ConsoleConfigPath + "?apiBaseUrl=https%3A%2F%2Fattacker.example",
	}
	for _, target := range targets {
		rec := serveConsole(t, c, http.MethodGet, target, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", target, rec.Code)
		}
		var doc struct {
			APIBaseURL string `json:"apiBaseUrl"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("decode config from %s: %v", target, err)
		}
		if doc.APIBaseURL != "https://api.example.com" {
			t.Errorf("GET %s served apiBaseUrl %q, want the configured one", target, doc.APIBaseURL)
		}
	}
}

func TestConsoleConfigIsNotCached(t *testing.T) {
	t.Parallel()
	c := newTestConsole(t, api.ConsoleConfig{APIBaseURL: "https://api.example.com"})
	rec := serveConsole(t, c, http.MethodGet, api.ConsoleConfigPath, nil)
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control on the configuration document = %q, want no-store", got)
	}
}

// TestConsoleCSPPinsConnectSrc is the other half of R50. The engine's origin
// allowlist is a request-side control and cannot stop the bundle from posting a
// token outbound; connect-src can.
func TestConsoleCSPPinsConnectSrc(t *testing.T) {
	t.Parallel()
	c := newTestConsole(t, api.ConsoleConfig{
		APIBaseURL: "https://api.example.com",
		OIDC: api.ConsoleOIDC{
			Issuer:                "https://idp.example.com",
			AuthorizationEndpoint: "https://idp.example.com/authorize",
			TokenEndpoint:         "https://idp.example.com/token",
			ClientID:              "stamp-console",
		},
	})
	csp := c.ContentSecurityPolicy()

	connect := ""
	for _, directive := range strings.Split(csp, ";") {
		if after, ok := strings.CutPrefix(strings.TrimSpace(directive), "connect-src "); ok {
			connect = after
		}
	}
	if connect == "" {
		t.Fatalf("the policy has no connect-src directive: %s", csp)
	}
	for _, want := range []string{"'self'", "https://api.example.com", "https://idp.example.com"} {
		if !strings.Contains(connect, want) {
			t.Errorf("connect-src %q is missing %q", connect, want)
		}
	}
	if strings.Contains(connect, "*") {
		t.Errorf("connect-src %q contains a wildcard", connect)
	}

	// An inline script is what an injection into the bundle would reach for,
	// and the absence of 'unsafe-inline' is what stops it.
	for _, forbidden := range []string{"'unsafe-inline'", "'unsafe-eval'"} {
		if strings.Contains(csp, forbidden) {
			t.Errorf("the policy contains %s: %s", forbidden, csp)
		}
	}
	for _, want := range []string{
		"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'",
		"base-uri 'none'", "object-src 'none'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("the policy is missing %q: %s", want, csp)
		}
	}
}

func TestConsoleSendsItsHeadersOnEveryResponse(t *testing.T) {
	t.Parallel()
	c := newTestConsole(t, api.ConsoleConfig{})
	for _, target := range []string{
		api.ConsoleBasePath, api.ConsoleConfigPath, api.ConsoleBasePath + "policies",
	} {
		rec := serveConsole(t, c, http.MethodGet, target, map[string]string{"Accept": "text/html"})
		h := rec.Header()
		if h.Get("Content-Security-Policy") == "" {
			t.Errorf("GET %s carries no Content-Security-Policy", target)
		}
		if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("GET %s X-Content-Type-Options = %q, want nosniff", target, got)
		}
		if got := h.Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("GET %s Referrer-Policy = %q, want no-referrer", target, got)
		}
		if got := h.Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("GET %s X-Frame-Options = %q, want DENY", target, got)
		}
	}
}

// TestConsoleDeepLinksResolveToTheShell is what makes client-side routing
// survive a refresh: /console/inbox is the router's, not the filesystem's.
func TestConsoleDeepLinksResolveToTheShell(t *testing.T) {
	t.Parallel()
	c := newTestConsole(t, api.ConsoleConfig{})
	rec := serveConsole(t, c, http.MethodGet, api.ConsoleBasePath+"inbox/decision-1",
		map[string]string{"Accept": "text/html"})
	if rec.Code != http.StatusOK {
		t.Fatalf("a deep link returned %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<!doctype html>") {
		t.Errorf("a deep link did not return the shell: %q", rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("the shell's Cache-Control = %q, want no-store", got)
	}
}

// TestConsoleDoesNotFallBackForAssetsOrAPIPaths keeps a 404 looking like a 404.
func TestConsoleDoesNotFallBackForAssetsOrAPIPaths(t *testing.T) {
	t.Parallel()
	c := newTestConsole(t, api.ConsoleConfig{})
	for _, target := range []string{
		api.ConsoleBasePath + "assets/gone-deadbee.js",
		// /console/v1 is the console surface's own API namespace; DryRunPath
		// lives there. A typo has to read as a wrong endpoint, not as HTML.
		api.ConsoleBasePath + "v1/policies/dry-runn",
	} {
		rec := serveConsole(t, c, http.MethodGet, target, map[string]string{"Accept": "text/html"})
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", target, rec.Code)
		}
	}
}

func TestConsoleServesHashedAssetsImmutably(t *testing.T) {
	t.Parallel()
	c := newTestConsole(t, api.ConsoleConfig{})
	rec := serveConsole(t, c, http.MethodGet, api.ConsoleBasePath+"assets/index-abc123.js", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET a hashed asset = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Errorf("a hashed asset's Cache-Control = %q, want an immutable one", got)
	}
}

// TestConsoleWithoutABundleSaysWhichCommandIsMissing is the development-mode
// scenario: a Go-only build starts, mounts the role, and explains itself.
func TestConsoleWithoutABundleSaysWhichCommandIsMissing(t *testing.T) {
	t.Parallel()
	c, err := api.NewConsole(api.ConsoleConfig{Assets: fstest.MapFS{}})
	if err != nil {
		t.Fatalf("NewConsole with no bundle: %v", err)
	}
	if c.Available() {
		t.Fatal("an empty filesystem reported an available bundle")
	}
	rec := serveConsole(t, c, http.MethodGet, api.ConsoleBasePath, map[string]string{"Accept": "text/html"})
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("an unbuilt console returned %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "npm run build") {
		t.Errorf("the guidance does not name the build command: %q", rec.Body.String())
	}

	// The configuration document is still served: it is generated, not built.
	if rec := serveConsole(t, c, http.MethodGet, api.ConsoleConfigPath, nil); rec.Code != http.StatusOK {
		t.Errorf("the configuration document under an unbuilt console = %d, want 200", rec.Code)
	}
}

func TestConsoleRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  api.ConsoleConfig
	}{
		{"a relative api base", api.ConsoleConfig{APIBaseURL: "/api"}},
		{"a plaintext api base", api.ConsoleConfig{APIBaseURL: "http://api.example.com"}},
		{"an api base with a query", api.ConsoleConfig{APIBaseURL: "https://api.example.com?x=1"}},
		{"a non-http scheme", api.ConsoleConfig{APIBaseURL: "javascript:alert(1)"}},
		{"a plaintext token endpoint", api.ConsoleConfig{
			OIDC: api.ConsoleOIDC{TokenEndpoint: "http://idp.example.com/token"}}},
		{"a relative authorization endpoint", api.ConsoleConfig{
			OIDC: api.ConsoleOIDC{AuthorizationEndpoint: "/authorize"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.cfg.Assets = testBundle()
			if _, err := api.NewConsole(tc.cfg); err == nil {
				t.Fatal("the configuration was accepted, want a refusal")
			}
		})
	}
}

func TestConsoleAllowsPlaintextOnlyWhenAsked(t *testing.T) {
	t.Parallel()
	if _, err := api.NewConsole(api.ConsoleConfig{
		Assets:                 testBundle(),
		APIBaseURL:             "http://127.0.0.1:8081",
		AllowInsecureTransport: true,
	}); err != nil {
		t.Fatalf("loopback development configuration was refused: %v", err)
	}
}

// TestConsoleRoutesAreStaticOnTheConsoleSurface is the mount-table half: the
// bundle is reachable without a credential, and that is a named auth kind
// rather than a hole in the console surface's rule.
func TestConsoleRoutesAreStaticOnTheConsoleSurface(t *testing.T) {
	t.Parallel()
	c := newTestConsole(t, api.ConsoleConfig{})
	if len(c.Routes()) == 0 {
		t.Fatal("the console offered no routes")
	}
	for _, r := range c.Routes() {
		if r.Surface != api.SurfaceConsole {
			t.Errorf("route %q is on the %s surface, want console", r.Name, r.Surface)
		}
		if r.Auth != api.AuthStatic {
			t.Errorf("route %q asks for %q, want %q", r.Name, r.Auth, api.AuthStatic)
		}
	}
}

// TestPublicAuthStaysOffTheConsoleSurface is the property AuthStatic exists to
// protect: widening the console surface to AuthPublic instead would have let a
// console API route mount with no credential at all.
func TestPublicAuthStaysOffTheConsoleSurface(t *testing.T) {
	t.Parallel()
	srv, err := api.New(api.Config{})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	err = srv.Mount(staticProvider{{
		Name:    "would-be-bff",
		Surface: api.SurfaceConsole,
		Pattern: "GET /secret",
		Auth:    api.AuthPublic,
		Handler: http.NotFoundHandler(),
	}})
	if err == nil {
		t.Fatal("a public route mounted on the console surface, want a refusal")
	}
	if !strings.Contains(err.Error(), "console") {
		t.Errorf("the refusal does not name the surface: %v", err)
	}
}

// TestStaticAuthStaysOffTheOtherSurfaces is the same rule in the other
// direction: the bundle's auth kind is not a way to mount an uncredentialed
// PEP endpoint.
func TestStaticAuthStaysOffTheOtherSurfaces(t *testing.T) {
	t.Parallel()
	for _, surface := range []api.Surface{api.SurfacePEP, api.SurfaceCallback} {
		srv, err := api.New(api.Config{})
		if err != nil {
			t.Fatalf("new server: %v", err)
		}
		if err := srv.Mount(staticProvider{{
			Name:    "static-elsewhere",
			Surface: surface,
			Pattern: "GET /assets/",
			Auth:    api.AuthStatic,
			Handler: http.NotFoundHandler(),
		}}); err == nil {
			t.Errorf("a static route mounted on the %s surface, want a refusal", surface)
		}
	}
}
