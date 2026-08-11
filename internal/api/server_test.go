package api_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
)

type staticProvider []api.Route

func (p staticProvider) Routes() []api.Route { return p }

func okHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	})
}

// The separation R39 asks for is that a PEP listener cannot reach the console
// or callback endpoints. This is asserted over real listeners rather than over
// handlers, because the claim is about what a caller on one port can do.
func TestPEPListenerCannotReachConsoleOrCallbackPaths(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})
	if err := f.server.Mount(staticProvider{{
		Name:    "external-callback",
		Surface: api.SurfaceCallback,
		Pattern: "POST /callback/v1/challenges/{id}",
		Auth:    api.AuthPublic,
		Handler: okHandler("callback"),
	}}); err != nil {
		t.Fatalf("mount callback: %v", err)
	}

	listeners, err := f.server.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- listeners.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})

	client := &http.Client{Timeout: 5 * time.Second}
	pep := "http://" + listeners.Addr(api.SurfacePEP)
	console := "http://" + listeners.Addr(api.SurfaceConsole)

	// Every cross-surface path is a 404 on the wrong listener: the router there
	// has never heard of it, so there is no authorization rule to get wrong.
	for _, tc := range []struct{ name, url, method string }{
		{"dry run on the PEP listener", pep + api.DryRunPath, http.MethodPost},
		{"callback on the PEP listener", pep + "/callback/v1/challenges/c1", http.MethodPost},
		{"evaluation on the console listener", console + api.EvaluationPath, http.MethodPost},
	} {
		req, err := http.NewRequestWithContext(t.Context(), tc.method, tc.url, strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("%s: build request: %v", tc.name, err)
		}
		// A valid workload credential, so the 404 is about routing rather than
		// about the credential.
		req.Header.Set("Authorization", "Bearer "+f.idp.token(t, "svc-a", testClientID))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: want 404, got %d", tc.name, resp.StatusCode)
		}
	}

	// The surfaces that are configured do answer their own health probe.
	for _, surface := range listeners.Surfaces() {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+listeners.Addr(surface)+"/healthz", nil)
		if err != nil {
			t.Fatalf("%s: build request: %v", surface, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s health: %v", surface, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s health: %d", surface, resp.StatusCode)
		}
		if got := resp.Header.Get("X-Stamp-Surface"); got != string(surface) {
			t.Fatalf("%s health reports surface %q", surface, got)
		}
	}
}

// Readiness and liveness are two endpoints because they have two remedies, and
// that split is the whole reason a lagging schema is a wait rather than an
// outage or a restart loop. Both halves are asserted: /readyz refuses while the
// gate refuses, and /healthz keeps answering 200 through it — because the chart
// still points the livenessProbe at /healthz, and a /healthz that followed the
// gate would restart every pod in the fleet instead of holding them back.
func TestReadyzRefusesWhileHealthzKeepsAnsweringAndBothNameTheirSurface(t *testing.T) {
	t.Parallel()

	var refuse atomic.Bool
	refuse.Store(true)
	server, err := api.New(api.Config{
		Addresses: map[api.Surface]string{api.SurfacePEP: "127.0.0.1:0"},
		Ready: func(context.Context) error {
			if refuse.Load() {
				return errors.New("database schema is at version 7 and this build needs 9")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	handler := server.Handler(api.SurfacePEP)

	probe := func(path string) (int, string, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String(), rec.Header().Get("X-Stamp-Surface")
	}

	code, body, surface := probe("/readyz")
	if code != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz while the gate refuses = %d, want 503", code)
	}
	// The reason travels in the body because that is where `kubectl describe`
	// and a curl both show it. A 503 with no reason is a rollout nobody can
	// diagnose without reading the pod's logs.
	if !strings.Contains(body, "version 7") || !strings.Contains(body, "needs 9") {
		t.Errorf("GET /readyz body does not carry the gate's reason: %q", body)
	}
	if surface != string(api.SurfacePEP) {
		t.Errorf("GET /readyz reports surface %q", surface)
	}

	// Same moment, same process: liveness says the process is fine, because it
	// is. Nothing about a schema that has not landed is fixed by a restart.
	if code, _, surface := probe("/healthz"); code != http.StatusOK || surface != string(api.SurfacePEP) {
		t.Errorf("GET /healthz while readiness refuses = %d on surface %q, want 200 on %q",
			code, surface, api.SurfacePEP)
	}

	refuse.Store(false)
	if code, body, _ := probe("/readyz"); code != http.StatusOK || !strings.Contains(body, "ready") {
		t.Errorf("GET /readyz once the gate opens = %d %q, want 200 ready", code, body)
	}
}

// A server given no readiness question answers 200. An embedding that only
// wants a router must not have to prove something to serve.
func TestReadyzWithoutAGateIsAlwaysReady(t *testing.T) {
	t.Parallel()
	server, err := api.New(api.Config{Addresses: map[api.Surface]string{api.SurfacePEP: "127.0.0.1:0"}})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	rec := httptest.NewRecorder()
	server.Handler(api.SurfacePEP).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /readyz with a nil Ready = %d, want 200", rec.Code)
	}
}

// /readyz is mounted by the server on every surface, like /healthz, so a route
// that claims either pattern is a collision rather than an override. Without
// this, a later provider could take the pattern the chart's probe depends on and
// nothing would say so until a rollout hung.
func TestReadyzCannotBeShadowedByAMountedRoute(t *testing.T) {
	t.Parallel()
	server, err := api.New(api.Config{Addresses: map[api.Surface]string{api.SurfaceCallback: "127.0.0.1:0"}})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	// AuthPublic on the callback surface, so the only thing that can refuse this
	// mount is the pattern collision this test is about — a route needing a
	// credential would be refused for want of identity middleware instead, and
	// the test would pass without ever reaching the question.
	err = server.Mount(staticProvider{{
		Name:    "impostor",
		Surface: api.SurfaceCallback,
		Pattern: "GET /readyz",
		Auth:    api.AuthPublic,
		Handler: okHandler("no"),
	}})
	if err == nil {
		t.Fatal("mounting GET /readyz was accepted: the probe the chart depends on can be replaced")
	}
	if !strings.Contains(err.Error(), "readyz") {
		t.Errorf("the refusal does not name readyz: %v", err)
	}
}

func TestListenBindsOnlyConfiguredSurfaces(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})
	listeners, err := f.server.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listeners.Close() })

	if addr := listeners.Addr(api.SurfaceCallback); addr != "" {
		t.Fatalf("the callback surface has no address configured but bound %q", addr)
	}
	if len(listeners.Surfaces()) != 2 {
		t.Fatalf("bound surfaces: %v", listeners.Surfaces())
	}
}

// The surface-to-credential table is the whole of R40's "authenticated callers
// only" for the PEP surface, so a route that would break it must not be
// mountable at all.
func TestMountRejectsCredentialsTheSurfaceDoesNotAdmit(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	for _, tc := range []struct {
		name  string
		route api.Route
	}{
		{"public route on the PEP surface", api.Route{
			Name: "leak", Surface: api.SurfacePEP, Pattern: "GET /open", Auth: api.AuthPublic, Handler: okHandler("x"),
		}},
		{"user token on the PEP surface", api.Route{
			Name: "human-pep", Surface: api.SurfacePEP, Pattern: "GET /human", Auth: api.AuthUser, Handler: okHandler("x"),
		}},
		{"workload token on the console surface", api.Route{
			Name: "robot-console", Surface: api.SurfaceConsole, Pattern: "GET /robot", Auth: api.AuthWorkload, Handler: okHandler("x"),
		}},
		{"unknown surface", api.Route{
			Name: "nowhere", Surface: "admin", Pattern: "GET /nowhere", Auth: api.AuthUser, Handler: okHandler("x"),
		}},
		{"no handler", api.Route{
			Name: "empty", Surface: api.SurfaceConsole, Pattern: "GET /empty", Auth: api.AuthUser,
		}},
		{"no name", api.Route{
			Surface: api.SurfaceConsole, Pattern: "GET /unnamed", Auth: api.AuthUser, Handler: okHandler("x"),
		}},
	} {
		if err := f.server.Mount(staticProvider{tc.route}); err == nil {
			t.Fatalf("%s: mounted without error", tc.name)
		}
	}
}

func TestMountRejectsCollidingPatterns(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})
	route := api.Route{
		Name:    "second-evaluation",
		Surface: api.SurfacePEP,
		Pattern: "POST " + api.EvaluationPath,
		Auth:    api.AuthWorkload,
		Handler: okHandler("x"),
	}
	if err := f.server.Mount(staticProvider{route}); err == nil {
		t.Fatal("a second handler was mounted on an occupied pattern")
	}
}

func TestServerWithoutIdentityRefusesAuthenticatedRoutes(t *testing.T) {
	t.Parallel()
	server, err := api.New(api.Config{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	err = server.Mount(staticProvider{{
		Name: "check", Surface: api.SurfacePEP, Pattern: "POST /x", Auth: api.AuthWorkload, Handler: okHandler("x"),
	}})
	if err == nil {
		t.Fatal("a workload route was mounted with no identity middleware configured")
	}
	// A public callback route is still mountable: it is the one kind that does
	// not need the middleware.
	if err := server.Mount(staticProvider{{
		Name: "callback", Surface: api.SurfaceCallback, Pattern: "POST /cb", Auth: api.AuthPublic, Handler: okHandler("cb"),
	}}); err != nil {
		t.Fatalf("mount public callback: %v", err)
	}
}

func TestMountedReportsRoutesPerSurface(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})
	pep := f.server.Mounted(api.SurfacePEP)
	if len(pep) != 1 || pep[0].Name != "authzen-access-evaluation" {
		t.Fatalf("pep routes: %+v", pep)
	}
	console := f.server.Mounted(api.SurfaceConsole)
	if len(console) != 1 || console[0].Name != "policy-dry-run" {
		t.Fatalf("console routes: %+v", console)
	}
	if got := f.server.Mounted(api.SurfaceCallback); len(got) != 0 {
		t.Fatalf("callback routes: %+v", got)
	}
}
