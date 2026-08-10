package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// status issues req against the handler built for spec and returns the code.
//
// A registered route answers 501 (the placeholder); an unregistered one falls
// through to the mux's 404. That difference is the whole assertion: role
// selection must decide whether a route exists at all, not merely whether it
// works.
func status(t *testing.T, spec, method, path string) int {
	t.Helper()
	set, err := ParseRoles(spec)
	if err != nil {
		t.Fatalf("ParseRoles(%q) returned error: %v", spec, err)
	}
	rec := httptest.NewRecorder()
	Default().Handler(set).ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Code
}

func TestAllRolesRegisterEverySubsystem(t *testing.T) {
	set, err := ParseRoles("all")
	if err != nil {
		t.Fatalf("ParseRoles returned error: %v", err)
	}
	reg := Default()
	if got, want := len(reg.Active(set)), len(reg.components); got != want {
		t.Errorf("--roles=all activated %d components, want all %d", got, want)
	}
	for _, name := range []string{
		"check-api", "decide-api", "expiry-sweeper",
		"policy-api", "console", "event-consumer",
	} {
		if !contains(reg.ActiveNames(set), name) {
			t.Errorf("component %q not active under --roles=all", name)
		}
	}
}

func TestHealthEndpointRespondsForEveryRoleSpec(t *testing.T) {
	// Including console-only, which mounts no API surface at all.
	for _, spec := range []string{"all", "check", "decide", "api", "console", "consumer"} {
		if got := status(t, spec, http.MethodGet, "/healthz"); got != http.StatusOK {
			t.Errorf("GET /healthz under --roles=%s = %d, want %d", spec, got, http.StatusOK)
		}
	}
}

func TestCheckRoleDoesNotRegisterDecideAPI(t *testing.T) {
	if got := status(t, "check", http.MethodPost, "/access/v1/evaluation"); got != http.StatusNotImplemented {
		t.Errorf("check endpoint under --roles=check = %d, want it registered (%d)", got, http.StatusNotImplemented)
	}
	if got := status(t, "check", http.MethodPost, "/decisions"); got != http.StatusNotFound {
		t.Errorf("POST /decisions under --roles=check = %d, want it unregistered (%d)", got, http.StatusNotFound)
	}
}

func TestAPIRoleDoesNotServeConsoleAssets(t *testing.T) {
	if got := status(t, "api", http.MethodGet, "/policies"); got != http.StatusNotImplemented {
		t.Errorf("GET /policies under --roles=api = %d, want it registered (%d)", got, http.StatusNotImplemented)
	}
	if got := status(t, "api", http.MethodGet, "/console/"); got != http.StatusNotFound {
		t.Errorf("console asset under --roles=api = %d, want it unserved (%d)", got, http.StatusNotFound)
	}
}

func TestConsoleRoleDoesNotRegisterAPIEndpoints(t *testing.T) {
	if got := status(t, "console", http.MethodGet, "/console/"); got != http.StatusNotImplemented {
		t.Errorf("console asset under --roles=console = %d, want it served (%d)", got, http.StatusNotImplemented)
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/policies"},
		{http.MethodPost, "/access/v1/evaluation"},
		{http.MethodPost, "/decisions"},
	} {
		if got := status(t, "console", tc.method, tc.path); got != http.StatusNotFound {
			t.Errorf("%s %s under --roles=console = %d, want it unregistered (%d)",
				tc.method, tc.path, got, http.StatusNotFound)
		}
	}
}

func TestRunnersFollowRoleSelection(t *testing.T) {
	decide, err := ParseRoles("decide")
	if err != nil {
		t.Fatalf("ParseRoles returned error: %v", err)
	}
	reg := Default()
	if got, want := len(reg.Runners(decide)), 1; got != want {
		t.Errorf("--roles=decide started %d runners, want %d (the sweeper)", got, want)
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
	runners := Default().Runners(set)
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
