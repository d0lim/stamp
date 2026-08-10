package runtime

import (
	"context"
	"fmt"
	"sort"

	"github.com/d0lim/stamp/internal/api"
)

// Component is one registerable subsystem: a set of HTTP routes, a background
// loop, or both.
//
// Routes are [api.Route] values rather than mux registrations. A route names
// the listener surface it belongs on, and stamp serves three separate listeners
// rather than three path prefixes on one, so a component that handed the
// registry a single mux could not say which listener it meant. Going through
// the route type also keeps the surface-to-credential table in [api] the one
// place R40 is decided: a check route that asked for no credential is a route
// that fails to mount, and a startup failure is the only place that is cheap.
//
// Routes and Run are both optional. A component with neither is a registration
// error — it would be silently inert, which is exactly the failure mode the
// role flag is supposed to make visible.
type Component struct {
	// Name identifies the component in logs and health output.
	Name string

	// Roles lists the roles that activate this component. A component is
	// active when any one of them is in the active set.
	Roles []Role

	// Routes are the endpoints the component offers. They are mounted only
	// when the component is active: an inactive role's routes are absent from
	// the router rather than mounted and refused.
	Routes []api.Route

	// Run executes a background loop (refresher, sweeper, consumer). Called
	// only when the component is active. It must return when ctx is cancelled.
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
	if len(c.Routes) == 0 && c.Run == nil {
		return fmt.Errorf("component %q has neither routes nor a runner: it would be inert", c.Name)
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

// Mount attaches the active components' routes to the server.
//
// Only active components are visited, so an inactive role's routes are never
// registered on any surface — a request for one gets the router's 404 rather
// than a handler that refuses. The difference matters: a refusal tells a caller
// the endpoint exists here and declined, and that is a different operational
// fact from "this process does not run that subsystem".
//
// The health endpoint is not mounted here. [api.Server] gives every surface one
// unconditionally, because a process that is running at all must be able to say
// so, including a console-only process with no API surface.
func (r *Registry) Mount(set Set, srv *api.Server) error {
	if srv == nil {
		return fmt.Errorf("runtime: mounting requires a server")
	}
	for _, c := range r.Active(set) {
		if len(c.Routes) == 0 {
			continue
		}
		if err := srv.Mount(routes(c.Routes)); err != nil {
			return fmt.Errorf("component %s: %w", c.Name, err)
		}
	}
	return nil
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

// routes adapts a route slice to [api.Provider], which is the seam the server
// mounts through.
type routes []api.Route

func (r routes) Routes() []api.Route { return r }
