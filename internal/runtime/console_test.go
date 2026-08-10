package runtime

// console_test.go asserts the two halves of D19's separability promise at the
// composition root, where both are actually observable.
//
// The first half is that the declared public contract and the console surface
// the process really mounts are the same set. The declaration is what the
// console's own boundary check reads, so a declaration that drifted from the
// route table would let the check pass while the console called something that
// was not public — or refuse a call to something that was.
//
// The second half is R51: console serving and the API surface are separate
// roles, and neither leaks into the other.

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/d0lim/stamp/console"
	"github.com/d0lim/stamp/internal/api"
)

func firstLine(body []byte) string {
	text := string(body)
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		return text[:i]
	}
	return text
}

// responseHeaders issues one request and returns the response headers, which
// [harness.do] discards.
func (h *harness) responseHeaders(t *testing.T, surface api.Surface, path string) http.Header {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://"+h.app.Addr(surface)+path, nil)
	if err != nil {
		t.Fatalf("build request %s: %v", path, err)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.Header
}

// TestConsoleContractMatchesTheMountedConsoleSurface is the drift guard.
func TestConsoleContractMatchesTheMountedConsoleSurface(t *testing.T) {
	h := newHarness(t, harnessOptions{roles: RoleAll})
	mounted := h.app.server.Mounted(api.SurfaceConsole)

	var mountedAPI []string
	var mountedStatic []string
	for _, r := range mounted {
		switch r.Auth {
		case api.AuthUser:
			mountedAPI = append(mountedAPI, r.Pattern)
		case api.AuthStatic:
			mountedStatic = append(mountedStatic, r.Name)
		default:
			t.Errorf("route %q is mounted on the console surface with %q auth", r.Name, r.Auth)
		}
	}
	slices.Sort(mountedAPI)
	slices.Sort(mountedStatic)

	declared := api.ContractPatterns(api.GroupAPI)
	if !slices.Equal(mountedAPI, declared) {
		t.Errorf("the console surface and the declared contract differ.\n"+
			" mounted:  %s\n declared: %s\n\n"+
			"an endpoint the console may call belongs in internal/api/contract.go; "+
			"one it may not belongs on another surface.",
			strings.Join(mountedAPI, "\n           "), strings.Join(declared, "\n           "))
	}

	// The uncredentialed routes on the console surface are the bundle and its
	// two documents, and nothing else. This is the assertion that would catch a
	// BFF arriving as "just one static-looking helper".
	wantStatic := []string{"console-config", "console-root-redirect", "console-shell"}
	if !slices.Equal(mountedStatic, wantStatic) {
		t.Errorf("the uncredentialed console routes are %v, want %v", mountedStatic, wantStatic)
	}
}

// TestConsoleRoleServesAssetsAndNoAPI is R51 in the console direction.
func TestConsoleRoleServesAssetsAndNoAPI(t *testing.T) {
	h := newHarness(t, harnessOptions{roles: "console", writerID: "console-only"})

	code, body := h.do(http.MethodGet, api.SurfaceConsole, api.ConsoleConfigPath, "", "", nil)
	if code != http.StatusOK {
		t.Fatalf("the configuration document under --roles=console = %d, want 200", code)
	}
	if !strings.Contains(string(body), `"apiBaseUrl"`) {
		t.Errorf("the configuration document carries no apiBaseUrl: %s", body)
	}

	// The bundle itself is only assertable when this tree has been built. In a
	// Go-only checkout the route answers the guidance instead, which is its own
	// test in internal/api — what matters here either way is that it is not a
	// 404, because 404 is what the role being off looks like.
	shellCode, shell := h.do(http.MethodGet, api.SurfaceConsole, api.ConsoleBasePath, "", "", nil)
	switch {
	case console.Built():
		if shellCode != http.StatusOK {
			t.Errorf("the embedded shell returned %d, want 200", shellCode)
		}
		if !strings.Contains(strings.ToLower(string(shell)), "<!doctype html>") {
			t.Errorf("the embedded shell is not the built index.html: %q", firstLine(shell))
		}
	default:
		if shellCode != http.StatusServiceUnavailable {
			t.Errorf("an unbuilt console returned %d, want 503", shellCode)
		}
		t.Log("console/dist holds no bundle; run `cd console && npm ci && npm run build` for the full assertion")
	}

	// Every declared API endpoint is absent, because the API role is not
	// running. A console tier that quietly served one would be the single image
	// collapsing back into one role.
	for _, e := range api.ConsoleContract() {
		if e.Group != api.GroupAPI {
			continue
		}
		path := strings.NewReplacer("{id}", "d-1", "{ordinal}", "0").Replace(e.Path)
		code, _ := h.do(e.Method, api.SurfaceConsole, path, "", "", nil)
		if code != http.StatusNotFound {
			t.Errorf("%s %s under --roles=console = %d, want 404", e.Method, path, code)
		}
	}
}

// TestAPIRoleServesNoConsoleAssets is R51 in the other direction.
func TestAPIRoleServesNoConsoleAssets(t *testing.T) {
	h := newHarness(t, harnessOptions{roles: "api", writerID: "api-only"})
	for _, path := range []string{
		api.ConsoleBasePath,
		api.ConsoleConfigPath,
		api.ConsoleBasePath + "assets/index-abc123.js",
		api.ConsoleBasePath + "inbox",
		strings.TrimSuffix(api.ConsoleBasePath, "/"),
	} {
		code, _ := h.do(http.MethodGet, api.SurfaceConsole, path, "", "", nil)
		if code != http.StatusNotFound {
			t.Errorf("GET %s under --roles=api = %d, want 404", path, code)
		}
	}

	// The API tier still answers its own API, so the 404s above are about the
	// console role rather than about a broken process.
	if code, _ := h.do(http.MethodGet, api.SurfaceConsole, "/policies", "", "", nil); code != http.StatusUnauthorized {
		t.Errorf("GET /policies under --roles=api = %d, want 401", code)
	}
}

// TestConsoleResponsesCarryTheirSecurityHeaders checks the headers on the real
// listener rather than on a handler, because a middleware that was attached in
// the wrong place would still pass a handler level test.
func TestConsoleResponsesCarryTheirSecurityHeaders(t *testing.T) {
	h := newHarness(t, harnessOptions{roles: "console", writerID: "console-headers"})
	resp := h.responseHeaders(t, api.SurfaceConsole, api.ConsoleConfigPath)
	csp := resp.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("the console response carries no Content-Security-Policy")
	}
	for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "connect-src 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("the policy is missing %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("the policy allows inline script or style: %s", csp)
	}
	if got := resp.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := resp.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
}
