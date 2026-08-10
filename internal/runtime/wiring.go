package runtime

import (
	"context"
	"net/http"
)

// Default builds the registry with every M1 subsystem slot present.
//
// The handlers here are placeholders that answer 501. They exist so the role
// wiring is exercised end to end from the first unit: a later unit replaces a
// placeholder with its real implementation without touching the role plumbing
// or the tests that assert which routes a given --roles value exposes.
func Default() *Registry {
	r := NewRegistry()

	r.MustAdd(Component{
		Name:  "check-api",
		Roles: []Role{RoleCheck},
		Mount: func(mux *http.ServeMux) {
			mux.Handle("POST /access/v1/evaluation", notImplemented("check-api"))
		},
	})

	r.MustAdd(Component{
		Name:  "decide-api",
		Roles: []Role{RoleDecide},
		Mount: func(mux *http.ServeMux) {
			mux.Handle("POST /decisions", notImplemented("decide-api"))
			mux.Handle("GET /decisions/{id}", notImplemented("decide-api"))
			mux.Handle("POST /decisions/{id}/approvals", notImplemented("decide-api"))
		},
	})

	r.MustAdd(Component{
		Name:  "expiry-sweeper",
		Roles: []Role{RoleDecide},
		Run:   blockUntilDone,
	})

	r.MustAdd(Component{
		Name:  "policy-api",
		Roles: []Role{RoleAPI},
		Mount: func(mux *http.ServeMux) {
			mux.Handle("GET /policies", notImplemented("policy-api"))
			mux.Handle("POST /policies/revisions", notImplemented("policy-api"))
		},
	})

	r.MustAdd(Component{
		Name:  "console",
		Roles: []Role{RoleConsole},
		Mount: func(mux *http.ServeMux) {
			mux.Handle("GET /console/", notImplemented("console"))
		},
	})

	r.MustAdd(Component{
		Name:  "event-consumer",
		Roles: []Role{RoleConsumer},
		Run:   blockUntilDone,
	})

	return r
}

func notImplemented(component string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Stamp-Component", component)
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte("not implemented\n"))
	})
}

func blockUntilDone(ctx context.Context) error {
	<-ctx.Done()
	return nil
}
