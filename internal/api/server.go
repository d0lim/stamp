// Package api serves STAMP's HTTP surfaces: the AuthZEN-compatible check
// endpoint a policy enforcement point calls, the console endpoints an operator
// calls, and the callback endpoint an external system calls back into.
//
// Three properties hold the package together.
//
// The three surfaces are three listeners, not three path prefixes on one. A
// deployment binds the PEP surface to an internal network, the console to an
// operator network, and the callback to wherever the external system can reach
// — and a route mounted on one is not reachable on another, because the other
// listener's router has never heard of it. Path-prefix separation would make
// that guarantee depend on a proxy rule somewhere else being right.
//
// Authentication is a property of the route, chosen from a closed set and
// checked against the surface at mount time. A PEP route can only be mounted
// with a workload credential requirement, so R40's "reject before evaluation"
// is not something a handler has to remember: a handler that skipped it could
// not have been mounted.
//
// The router is a seam. Later units hand the server their routes through
// [Provider] rather than reaching for a mux, so the surface split and the
// authentication table stay in one place as endpoints are added.
package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/d0lim/stamp/internal/identity"
)

// Surface names one of the three listeners a stamp process can expose.
type Surface string

// The listeners. They are separate processes' worth of exposure decisions even
// when one process serves all three, which is why they are named rather than
// derived from a path prefix.
const (
	// SurfacePEP carries the check and decide endpoints. Its callers are
	// workloads holding client credentials.
	SurfacePEP Surface = "pep"
	// SurfaceConsole carries operator and approver endpoints. Its callers are
	// people holding end-user tokens.
	SurfaceConsole Surface = "console"
	// SurfaceCallback carries the endpoints external systems call back into
	// when an external challenge completes. It is separate from the other two
	// because it is the one surface a deployment may have to expose beyond its
	// own perimeter.
	SurfaceCallback Surface = "callback"
)

// Surfaces returns every surface, in declaration order.
func Surfaces() []Surface { return []Surface{SurfacePEP, SurfaceConsole, SurfaceCallback} }

// Valid reports whether s is one of the declared surfaces.
func (s Surface) Valid() bool {
	for _, known := range Surfaces() {
		if s == known {
			return true
		}
	}
	return false
}

// Auth names the credential a route requires.
type Auth string

// The credential requirements a route may declare.
const (
	// AuthWorkload admits only a workload credential: a client-credentials
	// token or a client certificate.
	AuthWorkload Auth = "workload"
	// AuthUser admits only an end-user token.
	AuthUser Auth = "user"
	// AuthPublic admits an unauthenticated request. It exists for callback
	// endpoints, whose caller proves itself with the challenge correlator and
	// a payload signature rather than with a credential, and for liveness
	// probes. It is not mountable on the PEP or console surfaces.
	AuthPublic Auth = "public"
	// AuthStatic admits an unauthenticated request for the console's own
	// static bundle and its operator configuration document.
	//
	// It is a separate value from AuthPublic rather than a relaxation of the
	// console surface's entry in [allowedAuth], because the two say different
	// things. A browser performing a top level navigation cannot present a
	// bearer token, so the bundle has to be reachable without one; a console
	// *API* route that asked for no credential would still be a mistake, and
	// keeping AuthPublic off the console surface is what keeps that a mount
	// time failure. AuthStatic is mountable on the console surface alone.
	AuthStatic Auth = "static"
)

// needsCredential reports whether an auth kind is enforced by the identity
// middleware. The two unauthenticated kinds are enforced by what the handler
// behind them is allowed to be, not by a credential check.
func needsCredential(a Auth) bool { return a == AuthWorkload || a == AuthUser }

// allowedAuth is the surface-to-credential table, checked at mount time.
//
// It is a table rather than a rule inside each handler because that is what
// makes the guarantee auditable: R40 holds for the PEP surface if this map
// holds, and nothing else has to be read to confirm it.
var allowedAuth = map[Surface][]Auth{
	SurfacePEP:      {AuthWorkload},
	SurfaceConsole:  {AuthUser, AuthStatic},
	SurfaceCallback: {AuthWorkload, AuthPublic},
}

// Route is one endpoint offered to the server.
type Route struct {
	// Name identifies the route in errors and in [Server.Mounted].
	Name string
	// Surface is the listener the route belongs on.
	Surface Surface
	// Pattern is a net/http routing pattern, method included, such as
	// "POST /access/v1/evaluation".
	Pattern string
	// Auth is the credential the route requires.
	Auth Auth
	// Handler serves the route, already able to assume the credential check
	// passed.
	Handler http.Handler
}

// Provider is a feature module offering routes to the server.
//
// This is the seam later units extend: a module returns its routes and the
// composition root mounts them, so adding an endpoint never means reaching
// into the router or restating the authentication rule.
type Provider interface {
	// Routes returns the module's routes.
	Routes() []Route
}

// Config configures a [Server].
type Config struct {
	// Identity authenticates callers. Required unless every mounted route is
	// AuthPublic.
	Identity *identity.Middleware
	// Addresses gives the listen address for each surface a process serves. A
	// surface with no entry is not listened on at all — which is how a
	// deployment runs a PEP tier with no console reachable anywhere.
	Addresses map[Surface]string
	// ReadHeaderTimeout bounds how long a client may take to send headers.
	// Zero selects DefaultReadHeaderTimeout.
	ReadHeaderTimeout time.Duration
	// ShutdownTimeout bounds graceful shutdown. Zero selects
	// DefaultShutdownTimeout.
	ShutdownTimeout time.Duration
}

// Timeouts applied when [Config] leaves them unset.
const (
	// DefaultReadHeaderTimeout bounds the header phase of a request, which is
	// the phase an unauthenticated peer can hold open.
	DefaultReadHeaderTimeout = 10 * time.Second
	// DefaultShutdownTimeout bounds graceful shutdown.
	DefaultShutdownTimeout = 15 * time.Second
)

// Server owns one router per surface and the listeners in front of them.
type Server struct {
	cfg Config

	mu      sync.Mutex
	muxes   map[Surface]*http.ServeMux
	mounted map[Surface][]Route
	seen    map[Surface]map[string]string
}

// New builds a server with an empty router for every surface.
//
// Every surface gets a router whether or not it is listened on, so that mount
// time validation does not depend on deployment configuration: a route on a
// surface this process does not serve is a route that is simply unreachable,
// not a startup error that would make the role flags and the route table have
// to agree.
func New(cfg Config) (*Server, error) {
	for surface := range cfg.Addresses {
		if !surface.Valid() {
			return nil, fmt.Errorf("api: unknown surface %q in addresses", surface)
		}
	}
	if cfg.ReadHeaderTimeout <= 0 {
		cfg.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = DefaultShutdownTimeout
	}
	s := &Server{
		cfg:     cfg,
		muxes:   make(map[Surface]*http.ServeMux, len(Surfaces())),
		mounted: make(map[Surface][]Route, len(Surfaces())),
		seen:    make(map[Surface]map[string]string, len(Surfaces())),
	}
	for _, surface := range Surfaces() {
		mux := http.NewServeMux()
		mux.Handle("GET /healthz", healthHandler(surface))
		s.muxes[surface] = mux
		s.seen[surface] = map[string]string{"GET /healthz": "healthz"}
	}
	return s, nil
}

// Mount adds every provider's routes.
//
// It is all-or-nothing per call only in the sense that the first rejection
// stops it; a rejected route is a wiring mistake, and a process that started
// with half a route table would serve 404s that look like a policy problem.
func (s *Server) Mount(providers ...Provider) error {
	for _, p := range providers {
		if p == nil {
			return errors.New("api: nil route provider")
		}
		for _, route := range p.Routes() {
			if err := s.mount(route); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) mount(r Route) error {
	switch {
	case r.Name == "":
		return errors.New("api: route has no name")
	case r.Handler == nil:
		return fmt.Errorf("api: route %q has no handler", r.Name)
	case !r.Surface.Valid():
		return fmt.Errorf("api: route %q names unknown surface %q", r.Name, r.Surface)
	case r.Pattern == "":
		return fmt.Errorf("api: route %q has no pattern", r.Name)
	}
	allowed := allowedAuth[r.Surface]
	if !containsAuth(allowed, r.Auth) {
		return fmt.Errorf("api: route %q asks for %q on the %s surface, which admits only %s",
			r.Name, r.Auth, r.Surface, joinAuth(allowed))
	}
	if needsCredential(r.Auth) && s.cfg.Identity == nil {
		return fmt.Errorf("api: route %q requires a %s credential but no identity middleware is configured",
			r.Name, r.Auth)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, dup := s.seen[r.Surface][r.Pattern]; dup {
		return fmt.Errorf("api: route %q collides with %q on %s %s", r.Name, existing, r.Surface, r.Pattern)
	}
	s.seen[r.Surface][r.Pattern] = r.Name
	s.muxes[r.Surface].Handle(r.Pattern, s.authenticate(r))
	s.mounted[r.Surface] = append(s.mounted[r.Surface], r)
	return nil
}

func (s *Server) authenticate(r Route) http.Handler {
	switch r.Auth {
	case AuthWorkload:
		return s.cfg.Identity.RequireWorkload(r.Handler)
	case AuthUser:
		return s.cfg.Identity.RequireUser(r.Handler)
	default:
		return r.Handler
	}
}

// Handler returns the router for one surface.
//
// A route mounted on another surface is not reachable through it. That is the
// separation, expressed as three routers rather than as a rule about paths.
func (s *Server) Handler(surface Surface) http.Handler {
	s.mu.Lock()
	defer s.mu.Unlock()
	mux, ok := s.muxes[surface]
	if !ok {
		return http.NotFoundHandler()
	}
	return mux
}

// Mounted returns the routes mounted on a surface, in mount order.
func (s *Server) Mounted(surface Surface) []Route {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Route, len(s.mounted[surface]))
	copy(out, s.mounted[surface])
	return out
}

// Listeners is a bound, not yet serving, set of surface listeners.
type Listeners struct {
	server    *Server
	listeners map[Surface]net.Listener
	servers   map[Surface]*http.Server
}

// Listen binds every surface that has an address configured.
//
// Binding is separated from serving so that a caller — a test, or a process
// that must report readiness — can learn the actual addresses before any
// request is accepted.
func (s *Server) Listen() (*Listeners, error) {
	l := &Listeners{
		server:    s,
		listeners: make(map[Surface]net.Listener),
		servers:   make(map[Surface]*http.Server),
	}
	for _, surface := range Surfaces() {
		addr, ok := s.cfg.Addresses[surface]
		if !ok || addr == "" {
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("api: listen on %s surface: %w", surface, err)
		}
		l.listeners[surface] = ln
		l.servers[surface] = &http.Server{
			Handler:           s.Handler(surface),
			ReadHeaderTimeout: s.cfg.ReadHeaderTimeout,
		}
	}
	if len(l.listeners) == 0 {
		return nil, errors.New("api: no surface has a listen address configured")
	}
	return l, nil
}

// Addr reports the bound address of a surface, empty when it is not served.
func (l *Listeners) Addr(surface Surface) string {
	ln, ok := l.listeners[surface]
	if !ok {
		return ""
	}
	return ln.Addr().String()
}

// Surfaces returns the bound surfaces, in declaration order.
func (l *Listeners) Surfaces() []Surface {
	var out []Surface
	for _, surface := range Surfaces() {
		if _, ok := l.listeners[surface]; ok {
			out = append(out, surface)
		}
	}
	return out
}

// Serve accepts on every bound surface until the context is cancelled, then
// shuts them all down gracefully.
func (l *Listeners) Serve(ctx context.Context) error {
	errs := make(chan error, len(l.listeners))
	var wg sync.WaitGroup
	for surface, ln := range l.listeners {
		wg.Add(1)
		go func(surface Surface, ln net.Listener) {
			defer wg.Done()
			if err := l.servers[surface].Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- fmt.Errorf("api: %s surface: %w", surface, err)
			}
		}(surface, ln)
	}

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), l.server.cfg.ShutdownTimeout)
	defer cancel()
	for surface, srv := range l.servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			errs <- fmt.Errorf("api: %s surface shutdown: %w", surface, err)
		}
	}
	wg.Wait()
	close(errs)

	var joined []error
	for err := range errs {
		joined = append(joined, err)
	}
	return errors.Join(joined...)
}

// Close releases every bound listener without serving.
func (l *Listeners) Close() error {
	var errs []error
	for _, ln := range l.listeners {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func healthHandler(surface Surface) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Stamp-Surface", string(surface))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
}

func containsAuth(list []Auth, want Auth) bool {
	for _, a := range list {
		if a == want {
			return true
		}
	}
	return false
}

func joinAuth(list []Auth) string {
	parts := make([]string, len(list))
	for i, a := range list {
		parts[i] = string(a)
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}
