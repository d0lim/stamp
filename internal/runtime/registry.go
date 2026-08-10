package runtime

import (
	"context"
	"fmt"
	"net/http"
	"sort"
)

// Component is one registerable subsystem. Later units register their real
// implementations here; the registry itself never learns what they do.
//
// Mount and Run are both optional. A component with neither is a
// registration error — it would be silently inert, which is exactly the
// failure mode the role flag is supposed to make visible.
type Component struct {
	// Name identifies the component in logs and health output.
	Name string

	// Roles lists the roles that activate this component. A component is
	// active when any one of them is in the active set.
	Roles []Role

	// Mount attaches HTTP routes. Called only when the component is active.
	Mount func(mux *http.ServeMux)

	// Run executes a background loop (sweeper, consumer). Called only when
	// the component is active. It must return when ctx is cancelled.
	Run func(ctx context.Context) error
}

// Registry collects components before the active set is known.
type Registry struct {
	components []Component
	names      map[string]struct{}
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{names: map[string]struct{}{}}
}

// Add registers a component. It reports an error rather than panicking so a
// wiring mistake surfaces as a startup failure with a readable message.
func (r *Registry) Add(c Component) error {
	if c.Name == "" {
		return fmt.Errorf("component has no name")
	}
	if _, dup := r.names[c.Name]; dup {
		return fmt.Errorf("component %q is registered twice", c.Name)
	}
	if len(c.Roles) == 0 {
		return fmt.Errorf("component %q declares no roles: it could never run", c.Name)
	}
	for _, role := range c.Roles {
		if _, ok := lookupRole(string(role)); !ok {
			return fmt.Errorf("component %q declares unknown role %q", c.Name, role)
		}
	}
	if c.Mount == nil && c.Run == nil {
		return fmt.Errorf("component %q has neither Mount nor Run: it would be inert", c.Name)
	}
	r.names[c.Name] = struct{}{}
	r.components = append(r.components, c)
	return nil
}

// MustAdd is Add for static wiring that cannot fail at runtime.
func (r *Registry) MustAdd(c Component) {
	if err := r.Add(c); err != nil {
		panic(err)
	}
}

// Active returns the components enabled by set, in registration order.
func (r *Registry) Active(set Set) []Component {
	var out []Component
	for _, c := range r.components {
		for _, role := range c.Roles {
			if set.Has(role) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// ActiveNames returns the sorted names of the active components.
func (r *Registry) ActiveNames(set Set) []string {
	active := r.Active(set)
	names := make([]string, len(active))
	for i, c := range active {
		names[i] = c.Name
	}
	sort.Strings(names)
	return names
}

// Handler builds the HTTP handler for the active set.
//
// The health endpoint is always mounted regardless of role: a process that is
// running at all must be able to say so, including a console-only process
// with no API surface.
func (r *Registry) Handler(set Set) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	for _, c := range r.Active(set) {
		if c.Mount != nil {
			c.Mount(mux)
		}
	}
	return mux
}

// Runners returns the background loops for the active set.
func (r *Registry) Runners(set Set) []Component {
	var out []Component
	for _, c := range r.Active(set) {
		if c.Run != nil {
			out = append(out, c)
		}
	}
	return out
}
