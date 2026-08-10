package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/identity"
)

// These tests are about the registry mechanism and nothing else: which
// components a role spec activates, and what that does to the router. The real
// wiring's route table is asserted in wiring_test.go, against a real database,
// because it is only real once every unit is in it.
//
// The assertion throughout is registered versus absent. A mounted route behind
// a credential answers 401 to an unauthenticated request; a route that was
// never mounted answers 404. That difference is the whole point of role
// selection: an inactive subsystem's endpoints do not exist on this process,
// they are not merely refused by it.

// testMiddleware builds an identity layer over an issuer that is never
// contacted. Every request in this file is unauthenticated, and an
// unauthenticated request is refused before any key set is fetched.
func testMiddleware(t *testing.T) *identity.Middleware {
	t.Helper()
	verifier, err := identity.New(t.Context(), identity.Config{
		Issuers:    []identity.IssuerConfig{{Issuer: "https://idp.invalid", JWKSURL: "https://idp.invalid/jwks"}},
		Audience:   "stamp",
		Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}
	mw, err := identity.NewMiddleware(identity.MiddlewareConfig{
		Verifier: verifier,
		Audit:    identity.AuditSinkFunc(func(context.Context, identity.AuthRecord) {}),
	})
	if err != nil {
		t.Fatalf("build middleware: %v", err)
	}
	return mw
}

func testServer(t *testing.T) *api.Server {
	t.Helper()
	srv, err := api.New(api.Config{
		Identity: testMiddleware(t),
		Addresses: map[api.Surface]string{
			api.SurfacePEP:     "127.0.0.1:0",
			api.SurfaceConsole: "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	return srv
}

func stubRoute(name string, surface api.Surface, pattern string, auth api.Auth) api.Route {
	return api.Route{
		Name:    name,
		Surface: surface,
		Pattern: pattern,
		Auth:    auth,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	}
}

// stubRegistry mirrors the shape of the real wiring: a PEP component under
// check, a console component under decide, and a runner under consumer.
func stubRegistry(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	r.MustAdd(Component{
		Name:   "stub-check",
		Roles:  []Role{RoleCheck},
		Routes: []api.Route{stubRoute("stub-check", api.SurfacePEP, "POST /stub/check", api.AuthWorkload)},
	})
	r.MustAdd(Component{
		Name:   "stub-decide",
		Roles:  []Role{RoleDecide},
		Routes: []api.Route{stubRoute("stub-decide", api.SurfaceConsole, "POST /stub/decide", api.AuthUser)},
	})
	r.MustAdd(Component{
		Name:  "stub-consumer",
		Roles: []Role{RoleConsumer},
		Run:   blockUntilDone,
	})
	return r
}

// status mounts the stub registry for spec and issues one unauthenticated
// request against a surface.
func status(t *testing.T, spec string, surface api.Surface, method, path string) int {
	t.Helper()
	set, err := ParseRoles(spec)
	if err != nil {
		t.Fatalf("ParseRoles(%q) returned error: %v", spec, err)
	}
	srv := testServer(t)
	if err := stubRegistry(t).Mount(set, srv); err != nil {
		t.Fatalf("mount for --roles=%s: %v", spec, err)
	}
	rec := httptest.NewRecorder()
	srv.Handler(surface).ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Code
}

func TestAllRolesActivateEveryComponent(t *testing.T) {
	set, err := ParseRoles("all")
	if err != nil {
		t.Fatalf("ParseRoles returned error: %v", err)
	}
	reg := stubRegistry(t)
	if got, want := len(reg.Active(set)), len(reg.components); got != want {
		t.Errorf("--roles=all activated %d components, want all %d", got, want)
	}
	for _, name := range []string{"stub-check", "stub-decide", "stub-consumer"} {
		if !contains(reg.ActiveNames(set), name) {
			t.Errorf("component %q not active under --roles=all", name)
		}
	}
}

func TestHealthEndpointRespondsOnEverySurfaceForEveryRoleSpec(t *testing.T) {
	// Including console-only and consumer-only, which mount no API surface at
	// all: a process that is running must be able to say so.
	for _, spec := range []string{"all", "check", "decide", "api", "console", "consumer"} {
		for _, surface := range api.Surfaces() {
			if got := status(t, spec, surface, http.MethodGet, "/healthz"); got != http.StatusOK {
				t.Errorf("GET /healthz on %s under --roles=%s = %d, want %d",
					surface, spec, got, http.StatusOK)
			}
		}
	}
}

func TestInactiveRoleRoutesAreAbsentRatherThanRefused(t *testing.T) {
	if got := status(t, "check", api.SurfacePEP, http.MethodPost, "/stub/check"); got != http.StatusUnauthorized {
		t.Errorf("the check route under --roles=check = %d, want it registered and refusing (%d)",
			got, http.StatusUnauthorized)
	}
	if got := status(t, "check", api.SurfaceConsole, http.MethodPost, "/stub/decide"); got != http.StatusNotFound {
		t.Errorf("the decide route under --roles=check = %d, want it unregistered (%d)",
			got, http.StatusNotFound)
	}
	if got := status(t, "decide", api.SurfacePEP, http.MethodPost, "/stub/check"); got != http.StatusNotFound {
		t.Errorf("the check route under --roles=decide = %d, want it unregistered (%d)",
			got, http.StatusNotFound)
	}
}

func TestSurfacesAreSeparateRoutersRatherThanPathPrefixes(t *testing.T) {
	// A route mounted on the PEP surface is not reachable through the console
	// listener even when both are active. That is the separation the three
	// listeners exist for, and it does not depend on a proxy rule elsewhere.
	if got := status(t, "all", api.SurfaceConsole, http.MethodPost, "/stub/check"); got != http.StatusNotFound {
		t.Errorf("the PEP route on the console surface = %d, want %d", got, http.StatusNotFound)
	}
	if got := status(t, "all", api.SurfacePEP, http.MethodPost, "/stub/decide"); got != http.StatusNotFound {
		t.Errorf("the console route on the PEP surface = %d, want %d", got, http.StatusNotFound)
	}
}

func TestMountRejectsARouteTheSurfaceDoesNotAdmit(t *testing.T) {
	set, err := ParseRoles("all")
	if err != nil {
		t.Fatalf("ParseRoles returned error: %v", err)
	}
	reg := NewRegistry()
	// R40: the PEP surface admits only a workload credential. A component that
	// asked for an unauthenticated route there is unmountable, so the mistake
	// is a startup failure rather than an endpoint review has to catch.
	reg.MustAdd(Component{
		Name:   "public-pep",
		Roles:  []Role{RoleCheck},
		Routes: []api.Route{stubRoute("public-pep", api.SurfacePEP, "POST /stub/open", api.AuthPublic)},
	})
	if err := reg.Mount(set, testServer(t)); err == nil {
		t.Error("mounting an unauthenticated PEP route succeeded, want an error")
	}
}

func TestRunnersFollowRoleSelection(t *testing.T) {
	consumer, err := ParseRoles("consumer")
	if err != nil {
		t.Fatalf("ParseRoles returned error: %v", err)
	}
	reg := stubRegistry(t)
	if got, want := len(reg.Runners(consumer)), 1; got != want {
		t.Errorf("--roles=consumer started %d runners, want %d", got, want)
	}

	console, err := ParseRoles("console")
	if err != nil {
		t.Fatalf("ParseRoles returned error: %v", err)
	}
	if got := len(reg.Runners(console)); got != 0 {
		t.Errorf("--roles=console started %d runners, want 0", got)
	}
}

func TestRunnersStopOnContextCancel(t *testing.T) {
	set, err := ParseRoles("all")
	if err != nil {
		t.Fatalf("ParseRoles returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	runners := stubRegistry(t).Runners(set)
	if len(runners) == 0 {
		t.Fatal("expected at least one runner under --roles=all")
	}
	go func() { done <- runners[0].Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runner returned %v after cancel, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not return within 2s of context cancellation")
	}
}

func TestRegistryRejectsInvalidComponents(t *testing.T) {
	cases := map[string]Component{
		"no name":      {Roles: []Role{RoleAPI}, Run: blockUntilDone},
		"no roles":     {Name: "x", Run: blockUntilDone},
		"unknown role": {Name: "x", Roles: []Role{Role("nope")}, Run: blockUntilDone},
		"inert":        {Name: "x", Roles: []Role{RoleAPI}},
	}
	for name, c := range cases {
		if err := NewRegistry().Add(c); err == nil {
			t.Errorf("Add(%s) succeeded, want an error", name)
		}
	}

	reg := NewRegistry()
	c := Component{Name: "dup", Roles: []Role{RoleAPI}, Run: blockUntilDone}
	if err := reg.Add(c); err != nil {
		t.Fatalf("first Add returned error: %v", err)
	}
	if err := reg.Add(c); err == nil {
		t.Error("duplicate Add succeeded, want an error")
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
