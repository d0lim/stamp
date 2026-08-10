package api_test

import (
	"context"
	"io"
	"net/http"
	"strings"
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
