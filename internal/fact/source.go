// Package fact serves the synchronous fact plane: the contract a policy's
// declared fact source is executed through, the two v1 implementations (a
// static list and an HTTP call), the TTL cache in front of them, and the egress
// gate that decides what may be dialled at all.
//
// Three properties hold the package together.
//
// The declaration is the execution parameter. A source's freshness bound, its
// call timeout, and what happens when it fails are fixed once, in the
// declaration, and every call reads them from there. No call site passes its
// own timeout and no call site decides for itself what a failure means, because
// a control that each caller re-states is a control that one caller eventually
// states differently.
//
// The policy author is assumed to be outside the trust boundary. Authoring a
// policy must never become infrastructure access, so the two things a
// declaration could otherwise use to reach into the deployment are taken away
// from it: the call target is admitted only by the operator's egress allowlist,
// and failing open is admitted only by an operator-level flag. Both are load
// time gates. A policy set that asks for either without the operator having
// granted it is rejected before it is ever stored, not accepted and then
// refused at call time, because a refusal that arrives at call time is a
// refusal that arrives during an outage.
//
// A failure is reported, never guessed at. Every lookup that cannot answer
// comes back as a *Failure carrying a stable machine-readable reason and the
// failure behaviour its declaration fixed, and the same record goes to the
// auditor. The evaluator decides allow or deny; this package's job is to make
// sure the evaluator is never left inferring why.
package fact

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/d0lim/stamp/internal/policy"
)

// Reason is a stable, machine-readable classification of a failed fact lookup.
//
// Reasons are part of the audit contract: an operator greps for them and a
// dashboard groups by them, so neither is parsing English. They name what went
// wrong at the fact plane, never what the evaluator should do about it — that
// is carried separately by the declaration's failure behaviour.
type Reason string

// The fact lookup failure reasons.
const (
	// ReasonUnknownSource means no declaration by that name is registered.
	ReasonUnknownSource Reason = "fact_unknown_source"
	// ReasonBadArgument means the arguments did not match the declared signature.
	ReasonBadArgument Reason = "fact_bad_argument"
	// ReasonTimeout means the declared timeout elapsed before the source answered.
	ReasonTimeout Reason = "fact_timeout"
	// ReasonEgressBlocked means the egress gate refused the destination.
	ReasonEgressBlocked Reason = "fact_egress_blocked"
	// ReasonRedirect means the remote answered with a redirect, which is never followed.
	ReasonRedirect Reason = "fact_redirect"
	// ReasonTransport means the call failed below the HTTP status layer.
	ReasonTransport Reason = "fact_transport"
	// ReasonStatus means the remote answered with a non-200 status.
	ReasonStatus Reason = "fact_status"
	// ReasonTooLarge means the response body exceeded the configured cap.
	ReasonTooLarge Reason = "fact_response_too_large"
	// ReasonDecode means the response could not be read as the declared return type.
	ReasonDecode Reason = "fact_decode"
)

// Failure is the error every unsuccessful lookup returns.
//
// It carries both halves an evaluator needs and an auditor records: Reason says
// what went wrong, and OnError says what the declaration fixed as the behaviour
// for this source failing. OnError is resolved at load — a declaration only
// carries allow here if the operator flag admitted it — so a caller reading
// this field is reading a decision that was already checked, not one it is
// being asked to make.
type Failure struct {
	// Source is the declared source name the lookup was for.
	Source string
	// Reason classifies the failure.
	Reason Reason
	// OnError is the failure behaviour the declaration fixed.
	OnError policy.OnError
	// At is when the failure was recorded.
	At time.Time
	// Detail is a human-readable elaboration. It never carries response bodies.
	Detail string
	// Err is the underlying error, when there was one.
	Err error
}

// Error renders the failure as one line.
func (f *Failure) Error() string {
	var b strings.Builder
	b.WriteString("fact source ")
	b.WriteString(strconv.Quote(f.Source))
	b.WriteString(": ")
	b.WriteString(string(f.Reason))
	if f.Detail != "" {
		b.WriteString(": ")
		b.WriteString(f.Detail)
	}
	if f.Err != nil {
		b.WriteString(": ")
		b.WriteString(f.Err.Error())
	}
	return b.String()
}

// Unwrap exposes the underlying error to errors.Is and errors.As.
func (f *Failure) Unwrap() error { return f.Err }

// FailsClosed reports whether the evaluator must deny on this failure.
//
// This is the single place the default lives. A declaration that said nothing
// about failure gets deny, and a declaration that said allow only reached the
// registry because the operator flag admitted it, so a caller that asks this
// question never has to know either rule.
func (f *Failure) FailsClosed() bool { return f.OnError != policy.OnErrorAllow }

// AuditReason returns the stable string an audit record carries for this
// failure.
func (f *Failure) AuditReason() string { return string(f.Reason) }

// Auditor receives a record of every fact lookup that failed.
//
// The fact plane reports; it does not store. The durable, hash-chained audit
// log belongs to the store unit, and a synchronous check path must not be able
// to block on it, so implementations are expected to be non-blocking.
type Auditor interface {
	// RecordFactFailure records one failed lookup. ctx is the caller's context,
	// which may already be cancelled when the failure was a timeout.
	RecordFactFailure(ctx context.Context, f *Failure)
}

// AuditorFunc adapts a function to the Auditor interface.
type AuditorFunc func(ctx context.Context, f *Failure)

// RecordFactFailure calls fn.
func (fn AuditorFunc) RecordFactFailure(ctx context.Context, f *Failure) { fn(ctx, f) }

// Value is one typed fact, either an argument to a lookup or its result.
//
// Data uses the same canonical Go representations the policy package's literals
// use — bool, int64, float64, string, time.Time in UTC, time.Duration, and
// []any for a list — so a value crossing between the two packages never needs a
// conversion that could quietly widen a type.
type Value struct {
	// Type is the declared type of the value.
	Type policy.Type
	// Data is the value itself, in the canonical representation for Type.
	Data any
}

// Bool returns a bool value.
func Bool(v bool) Value { return Value{Type: policy.TypeBool, Data: v} }

// Int returns an int value.
func Int(v int64) Value { return Value{Type: policy.TypeInt, Data: v} }

// Double returns a double value.
func Double(v float64) Value { return Value{Type: policy.TypeDouble, Data: v} }

// String returns a string value.
func String(v string) Value { return Value{Type: policy.TypeString, Data: v} }

// Timestamp returns a timestamp value, normalized to UTC.
func Timestamp(v time.Time) Value { return Value{Type: policy.TypeTimestamp, Data: v.UTC()} }

// Duration returns a duration value.
func Duration(v time.Duration) Value { return Value{Type: policy.TypeDuration, Data: v} }

// List returns a list value with the given element type.
func List(elem policy.Type, values ...any) Value {
	data := make([]any, len(values))
	copy(data, values)
	return Value{Type: policy.ListOf(elem), Data: data}
}

// CheckType reports whether the value's data matches the given declared type.
func (v Value) CheckType(t policy.Type) error {
	if v.Type != t {
		return fmt.Errorf("expected type %s, got %s", t, v.Type)
	}
	if t.IsList() {
		items, ok := v.Data.([]any)
		if !ok {
			return fmt.Errorf("expected []any for %s, got %T", t, v.Data)
		}
		elem := t.Elem()
		for i, item := range items {
			if !scalarMatches(elem, item) {
				return fmt.Errorf("element %d: expected %s, got %T", i, elem, item)
			}
		}
		return nil
	}
	if !scalarMatches(t, v.Data) {
		return fmt.Errorf("expected %s, got %T", t, v.Data)
	}
	return nil
}

// clone returns a copy that shares no mutable state with v, so a caller cannot
// reach back through a returned list and edit a cached or declared value.
func (v Value) clone() Value {
	items, ok := v.Data.([]any)
	if !ok {
		return v
	}
	out := make([]any, len(items))
	copy(out, items)
	return Value{Type: v.Type, Data: out}
}

func scalarMatches(t policy.Type, data any) bool {
	switch t {
	case policy.TypeBool:
		_, ok := data.(bool)
		return ok
	case policy.TypeInt:
		_, ok := data.(int64)
		return ok
	case policy.TypeDouble:
		_, ok := data.(float64)
		return ok
	case policy.TypeString:
		_, ok := data.(string)
		return ok
	case policy.TypeTimestamp:
		_, ok := data.(time.Time)
		return ok
	case policy.TypeDuration:
		_, ok := data.(time.Duration)
		return ok
	default:
		return false
	}
}

// Declaration is everything needed to execute one fact source.
//
// It is the join of two halves written by two different people. The signature
// half — name, kind, parameters, return type, failure behaviour — comes from
// the policy schema and is authored with the policy. The transport half — TTL,
// timeout, target, static values — is deployment configuration and is authored
// by the operator. The policy schema deliberately does not carry the transport
// half, because a field a policy author can write is a field a policy author
// can use to point the deployment somewhere.
type Declaration struct {
	// Name is the declared source name. It matches a policy.SourceDecl name.
	Name string
	// Kind selects the implementation. Only static and http are served here.
	Kind policy.SourceKind
	// Params is the positional parameter list, in calling order.
	Params []policy.Param
	// Returns is the declared result type.
	Returns policy.Type
	// OnError is the failure behaviour. Empty means the safe default, deny.
	OnError policy.OnError
	// TTL bounds how stale an answer may be. Required for http, unused for static.
	TTL time.Duration
	// Timeout bounds one remote call. Required for http, unused for static.
	Timeout time.Duration
	// URL is the http call target. It must be admitted by the egress allowlist.
	URL string
	// Values is the list a static source returns, in the canonical
	// representation for the element type of Returns.
	Values []any
}

// SourceDecl returns the policy-schema half of the declaration, so a caller can
// compare a deployment's transport configuration against the schema a policy
// set was written against.
func (d Declaration) SourceDecl() policy.SourceDecl {
	params := make([]policy.Param, len(d.Params))
	copy(params, d.Params)
	onErr := d.OnError
	if onErr == "" {
		onErr = policy.DefaultOnError
	}
	return policy.SourceDecl{
		Name:    d.Name,
		Kind:    d.Kind,
		Params:  params,
		Returns: d.Returns,
		OnError: onErr,
	}
}

// FromSourceDecl starts a declaration from a policy schema's source signature.
// The caller fills in the transport half.
func FromSourceDecl(sd policy.SourceDecl) Declaration {
	params := make([]policy.Param, len(sd.Params))
	copy(params, sd.Params)
	return Declaration{
		Name:    sd.Name,
		Kind:    sd.Kind,
		Params:  params,
		Returns: sd.Returns,
		OnError: sd.OnError,
	}
}

// Source fetches one fact. Implementations are safe for concurrent use and do
// no caching of their own — the registry owns the cache, so that the freshness
// bound is applied uniformly no matter which implementation serves a source.
type Source interface {
	// Name reports the declared source name.
	Name() string
	// Fetch performs one lookup. It returns a *Failure on error, with Reason
	// set; the registry fills in the failure behaviour and audits the record.
	Fetch(ctx context.Context, args []Value) (Value, error)
}

// Config is the operator's deployment configuration for the fact plane.
type Config struct {
	// Egress configures which destinations outbound fact calls may reach.
	Egress EgressConfig
	// AllowFailOpen is the operator-level flag that admits declarations asking
	// to fail open. With it unset, such a declaration is rejected at load.
	AllowFailOpen bool
	// MaxCacheEntries bounds the TTL cache. Zero selects DefaultMaxCacheEntries.
	// The cache is keyed partly by lookup arguments, which are request-derived,
	// so an unbounded cache would be a memory amplifier reachable from outside.
	MaxCacheEntries int
	// Now overrides the clock. Tests use it to age cache entries; production
	// leaves it nil for time.Now.
	Now func() time.Time
	// Audit receives a record of every failed lookup. Nil discards them.
	Audit Auditor
}

// DefaultMaxCacheEntries is the TTL cache bound applied when Config leaves it
// unset.
const DefaultMaxCacheEntries = 4096

// ErrLoad is the sentinel every load-time rejection wraps, so a caller can tell
// "this deployment refuses to serve this policy set" from a runtime failure
// without matching on message text.
var ErrLoad = errors.New("fact source declaration rejected at load")

// Registry holds the resolved, load-checked fact sources of one deployment and
// is the surface the evaluator calls.
//
// Construction is the load gate. Everything a policy author could otherwise use
// to reach the deployment — the call target, failing open — is checked here,
// once, against operator configuration. A registry that exists is a registry
// whose every source was admitted.
type Registry struct {
	cfg     Config
	gate    *Gate
	client  *http.Client
	cache   *cache
	now     func() time.Time
	sources map[string]*resolvedSource
}

type resolvedSource struct {
	decl Declaration
	src  Source
}

// NewRegistry resolves declarations into executable sources, rejecting at load
// anything the operator's configuration does not admit.
//
// Rejections are load errors wrapping ErrLoad, and they are collected rather
// than reported one at a time, so an operator fixing a deployment sees the
// whole list in one pass.
func NewRegistry(decls []Declaration, cfg Config) (*Registry, error) {
	gate, err := NewGate(cfg.Egress)
	if err != nil {
		return nil, fmt.Errorf("%w: egress: %w", ErrLoad, err)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	maxEntries := cfg.MaxCacheEntries
	if maxEntries <= 0 {
		maxEntries = DefaultMaxCacheEntries
	}
	r := &Registry{
		cfg:     cfg,
		gate:    gate,
		client:  newEgressClient(gate),
		cache:   newCache(maxEntries, now),
		now:     now,
		sources: make(map[string]*resolvedSource, len(decls)),
	}

	var errs []error
	for _, decl := range decls {
		if _, dup := r.sources[decl.Name]; dup {
			errs = append(errs, fmt.Errorf("%w: source %q: declared more than once", ErrLoad, decl.Name))
			continue
		}
		resolved, err := r.resolve(decl)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		r.sources[decl.Name] = resolved
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return r, nil
}

// resolve checks one declaration against operator configuration and builds its
// source.
func (r *Registry) resolve(decl Declaration) (*resolvedSource, error) {
	// Rejections keep the underlying error in the chain, so a caller can ask
	// errors.Is whether a load failed because of the egress gate rather than
	// matching on the message.
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: source %q: %s", ErrLoad, decl.Name, fmt.Sprintf(format, args...))
	}
	failWith := func(err error) error {
		return fmt.Errorf("%w: source %q: %w", ErrLoad, decl.Name, err)
	}
	if !policy.ValidIdent(decl.Name) {
		return nil, fail("name is not a valid identifier")
	}
	if !decl.Returns.Valid() {
		return nil, fail("return type %q is not a valid type", decl.Returns)
	}
	seen := make(map[string]struct{}, len(decl.Params))
	for _, p := range decl.Params {
		if !policy.ValidIdent(p.Name) {
			return nil, fail("parameter %q is not a valid identifier", p.Name)
		}
		if !p.Type.Valid() {
			return nil, fail("parameter %q has invalid type %q", p.Name, p.Type)
		}
		if _, dup := seen[p.Name]; dup {
			return nil, fail("parameter %q is declared more than once", p.Name)
		}
		seen[p.Name] = struct{}{}
	}

	onErr := decl.OnError
	if onErr == "" {
		onErr = policy.DefaultOnError
	}
	if !onErr.Valid() {
		return nil, fail("on_error %q is not a valid failure behaviour", onErr)
	}
	// The operator flag, not the declaration, is what grants fail-open. A
	// policy author who writes it without the flag finds out here, at load,
	// rather than during the outage the declaration was written for.
	if onErr == policy.OnErrorAllow && !r.cfg.AllowFailOpen {
		return nil, fail("on_error: allow requires the operator fail-open flag, which is not enabled on this deployment")
	}
	decl.OnError = onErr

	switch decl.Kind {
	case policy.SourceStatic:
		src, err := newStaticSource(decl)
		if err != nil {
			return nil, failWith(err)
		}
		return &resolvedSource{decl: decl, src: src}, nil
	case policy.SourceHTTP:
		src, err := r.resolveHTTP(decl)
		if err != nil {
			return nil, failWith(err)
		}
		return &resolvedSource{decl: decl, src: src}, nil
	case policy.SourceEvent, policy.SourceIdPGroup:
		return nil, fail("kind %q is not served by the synchronous fact plane", decl.Kind)
	default:
		return nil, fail("kind %q is not a declared source kind", decl.Kind)
	}
}

func (r *Registry) resolveHTTP(decl Declaration) (Source, error) {
	if decl.Values != nil {
		return nil, errors.New("static values are not meaningful for an http source")
	}
	if decl.TTL <= 0 {
		return nil, errors.New("ttl must be positive; the freshness bound of a decision is not allowed to be implicit")
	}
	if decl.Timeout <= 0 {
		return nil, errors.New("timeout must be positive")
	}
	if decl.URL == "" {
		return nil, errors.New("url is required")
	}
	// The first of the egress gate's two checks. The same gate runs again at
	// call time, so a destination is admitted by exactly one rule set whether
	// it is reached by declaration or by redirect.
	if err := r.gate.CheckURL(decl.URL); err != nil {
		return nil, err
	}
	if err := r.gate.Preflight(context.Background(), decl.URL); err != nil {
		return nil, err
	}
	return newHTTPSource(decl, r.gate, r.client, r.cfg.Egress.maxResponseBytes()), nil
}

// VerifySchema checks a policy schema against this deployment, and is the load
// gate for a policy set as a whole.
//
// Two things are checked. Every synchronous source the schema declares must be
// backed by a matching transport declaration with the same signature, so a
// policy that names a source this deployment cannot serve is refused before it
// is stored. And every source declaration asking to fail open — of any kind,
// including the ones other units serve — is refused unless the operator flag is
// set, because that flag is a property of the deployment and not of the source
// implementation.
func (r *Registry) VerifySchema(s *policy.Schema) error {
	if s == nil {
		return nil
	}
	var errs []error
	for i := range s.Sources {
		sd := s.Sources[i]
		onErr := sd.OnError
		if onErr == "" {
			onErr = policy.DefaultOnError
		}
		if onErr == policy.OnErrorAllow && !r.cfg.AllowFailOpen {
			errs = append(errs, fmt.Errorf("%w: source %q: on_error: allow requires the operator fail-open flag, which is not enabled on this deployment", ErrLoad, sd.Name))
		}
		if sd.Kind != policy.SourceStatic && sd.Kind != policy.SourceHTTP {
			continue
		}
		resolved, ok := r.sources[sd.Name]
		if !ok {
			errs = append(errs, fmt.Errorf("%w: source %q: declared by the schema but not configured on this deployment", ErrLoad, sd.Name))
			continue
		}
		if err := sameSignature(resolved.decl.SourceDecl(), sd); err != nil {
			errs = append(errs, fmt.Errorf("%w: source %q: %w", ErrLoad, sd.Name, err))
		}
	}
	return errors.Join(errs...)
}

func sameSignature(configured, declared policy.SourceDecl) error {
	if configured.Kind != declared.Kind {
		return fmt.Errorf("configured as kind %q, declared as %q", configured.Kind, declared.Kind)
	}
	if configured.Returns != declared.Returns {
		return fmt.Errorf("configured to return %q, declared to return %q", configured.Returns, declared.Returns)
	}
	if len(configured.Params) != len(declared.Params) {
		return fmt.Errorf("configured with %d parameters, declared with %d", len(configured.Params), len(declared.Params))
	}
	for i := range configured.Params {
		if configured.Params[i] != declared.Params[i] {
			return fmt.Errorf("parameter %d: configured as %s %s, declared as %s %s",
				i, configured.Params[i].Name, configured.Params[i].Type,
				declared.Params[i].Name, declared.Params[i].Type)
		}
	}
	if configured.OnError != declared.OnError {
		return fmt.Errorf("configured with on_error %q, declared with %q", configured.OnError, declared.OnError)
	}
	return nil
}

// Names returns the configured source names, sorted.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.sources))
	for name := range r.sources {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Declaration returns the resolved declaration for a source.
func (r *Registry) Declaration(name string) (Declaration, bool) {
	resolved, ok := r.sources[name]
	if !ok {
		return Declaration{}, false
	}
	return resolved.decl, true
}

// Lookup resolves one fact, serving it from cache when the declaration's TTL
// still covers it and fetching it otherwise.
//
// This is the call the evaluator binds each declared source function to. On
// failure it returns a *Failure that already carries the declaration's failure
// behaviour, and the same record has already gone to the auditor.
func (r *Registry) Lookup(ctx context.Context, name string, args ...Value) (Value, error) {
	resolved, ok := r.sources[name]
	if !ok {
		return Value{}, r.record(ctx, &Failure{
			Source: name,
			Reason: ReasonUnknownSource,
			Detail: "no such source is configured on this deployment",
		}, policy.OnErrorDeny)
	}
	if err := checkArgs(resolved.decl, args); err != nil {
		return Value{}, r.record(ctx, &Failure{
			Source: name,
			Reason: ReasonBadArgument,
			Detail: err.Error(),
		}, resolved.decl.OnError)
	}

	key := cacheKey(name, args)
	if v, hit := r.cache.get(key); hit {
		return v, nil
	}

	callCtx := ctx
	if resolved.decl.Timeout > 0 {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, resolved.decl.Timeout)
		defer cancel()
	}

	v, err := resolved.src.Fetch(callCtx, args)
	if err != nil {
		f := asFailure(name, err)
		// The timeout is the declaration's, so a context that expired during
		// the call is reported as the declared timeout elapsing rather than as
		// a generic transport error.
		if f.Reason == ReasonTransport && callCtx.Err() != nil && ctx.Err() == nil {
			f.Reason = ReasonTimeout
			f.Detail = "declared timeout of " + resolved.decl.Timeout.String() + " elapsed"
		}
		// A TTL-expired entry is never resurrected as a substitute answer. The
		// cache holds nothing to fall back to here by construction: get()
		// evicts on expiry rather than retaining a stale copy.
		return Value{}, r.record(ctx, f, resolved.decl.OnError)
	}
	if err := v.CheckType(resolved.decl.Returns); err != nil {
		return Value{}, r.record(ctx, &Failure{
			Source: name,
			Reason: ReasonDecode,
			Detail: err.Error(),
		}, resolved.decl.OnError)
	}
	if resolved.decl.TTL > 0 {
		r.cache.put(key, v, resolved.decl.TTL)
	}
	return v.clone(), nil
}

// Close releases the connections the registry's HTTP client is holding.
func (r *Registry) Close() {
	r.client.CloseIdleConnections()
}

func (r *Registry) record(ctx context.Context, f *Failure, onErr policy.OnError) error {
	if onErr == "" {
		onErr = policy.DefaultOnError
	}
	f.OnError = onErr
	f.At = r.now()
	if r.cfg.Audit != nil {
		r.cfg.Audit.RecordFactFailure(ctx, f)
	}
	return f
}

func asFailure(name string, err error) *Failure {
	var f *Failure
	if errors.As(err, &f) {
		if f.Source == "" {
			f.Source = name
		}
		return f
	}
	return &Failure{Source: name, Reason: ReasonTransport, Err: err}
}

func checkArgs(decl Declaration, args []Value) error {
	if len(args) != len(decl.Params) {
		return fmt.Errorf("expected %d arguments, got %d", len(decl.Params), len(args))
	}
	for i, p := range decl.Params {
		if err := args[i].CheckType(p.Type); err != nil {
			return fmt.Errorf("argument %d (%s): %w", i, p.Name, err)
		}
	}
	return nil
}
