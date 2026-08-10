package stream

// source.go is the read side: the asynchronous fact source a policy reaches
// when it asks for a trailing aggregate, and the load gate in front of it.
//
// The evaluator never touches this file's subject matter directly. It states
// [engine.SourceResolver] and gets a batch answered; whether an answer came
// from a bucket table or from an HTTP call is not its business. That is why
// [Sources] takes a fallback resolver rather than being registered alongside
// one: the evaluator gets exactly one resolver, and splitting a batch by
// source name belongs here, next to the knowledge of which names these are.
//
// Two rules are enforced at load rather than at call time, and both for the
// same reason: a refusal that arrives at call time arrives during the outage
// it was written for.
//
// A freshness limit is only declarable against an adapter that can report
// ingestion lag. An adapter that cannot report it says so statically, and a
// source fed by one cannot carry a limit — the alternative is a limit
// evaluated against an unknown, which reads as "fresh" precisely when
// ingestion has stopped.
//
// A window may not be wider than the deduplication state can cover. Past that
// horizon the dedup row for an event is gone while a window still reaches its
// bucket, so a replay would be added a second time inside an answer somebody
// is about to enforce a limit with.
//
// A velocity source may not fail open. R37 fixes the direction — ingestion lag
// past the limit denies — and a velocity limit that failed open would be a
// limit that switches itself off exactly when the ingestion path breaks, which
// is the cheapest attack on it there is.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// Failure reasons for a velocity lookup. They join the fact plane's reason
// vocabulary rather than starting a second one, because an operator greps one
// audit stream and a dashboard groups one set of labels.
const (
	// ReasonLagUnknown means the source's adapter has confirmed nothing yet,
	// or cannot report lag at all. An unknown lag is not a small lag.
	ReasonLagUnknown fact.Reason = "fact_ingest_lag_unknown"
	// ReasonStale means ingestion lag exceeded the declared freshness limit.
	ReasonStale fact.Reason = "fact_ingest_lag_exceeded"
	// ReasonAggregate means the bucket query itself failed.
	ReasonAggregate fact.Reason = "fact_aggregate_unavailable"
)

// Declaration is the operator half of one velocity source.
//
// It splits the same way [fact.Declaration] does and for the same reason. The
// signature half — name, parameters, return type — is authored with the policy
// and appears in the schema. The rest is deployment configuration: which
// metric the source reads, how wide its buckets are, which adapter feeds it,
// how stale it may get. A policy author who could write those fields could
// point a limit at another tenant's metric or widen its own window until the
// limit stopped biting.
type Declaration struct {
	// Name is the declared source name, matching a policy.SourceDecl of kind
	// event.
	Name string
	// Metric is the aggregate this source reads.
	Metric string
	// Adapter names the ingestion adapter feeding Metric. It is what joins a
	// declared freshness limit to a lag report.
	Adapter string
	// Window is the trailing window summed on lookup. It must be a whole
	// number of buckets, because the bucket width is the precision the storage
	// actually has.
	Window time.Duration
	// BucketWidth is the fixed bucket width. It must agree with the
	// aggregator's spec for Metric.
	BucketWidth time.Duration
	// Freshness is the ingestion lag limit. Zero declares none. A non-zero
	// value requires an adapter that reports lag.
	Freshness time.Duration
	// AllowDeduction admits negative deltas for Metric at the port. It is
	// stated here because the source declaration is where R37 puts it; the
	// credential still needs its own separate permission to send one.
	AllowDeduction bool
	// Params is the positional parameter list. A velocity source takes exactly
	// one string: the subject whose aggregate is being read.
	Params []policy.Param
	// Returns is the declared result type: double for the value sum, int for
	// the event count.
	Returns policy.Type
	// OnError is the failure behaviour. Only deny is admissible.
	OnError policy.OnError
}

// SourceDecl returns the policy-schema half of the declaration.
func (d Declaration) SourceDecl() policy.SourceDecl {
	params := make([]policy.Param, len(d.Params))
	copy(params, d.Params)
	onErr := d.OnError
	if onErr == "" {
		onErr = policy.DefaultOnError
	}
	return policy.SourceDecl{
		Name:    d.Name,
		Kind:    policy.SourceEvent,
		Params:  params,
		Returns: d.Returns,
		OnError: onErr,
	}
}

// MetricSpec returns the aggregation settings this declaration implies.
func (d Declaration) MetricSpec() MetricSpec {
	return MetricSpec{Metric: d.Metric, BucketWidth: d.BucketWidth, AllowDeduction: d.AllowDeduction}
}

// MetricSpecsFor returns the aggregation settings a set of declarations
// implies, deduplicated by metric and sorted.
//
// It is a free function rather than a method so that the wiring order comes
// out straight: declarations, then the aggregator, then the adapters, then the
// sources. Requiring a [Sources] to compute an [Aggregator]'s configuration
// would tie that knot the other way and force a composition root to build the
// sources twice — once against a placeholder adapter and again against the
// real one — which is the kind of dance that gets copied into production
// wiring and then quietly diverges from the test that established it.
func MetricSpecsFor(decls []Declaration) []MetricSpec {
	seen := make(map[string]MetricSpec, len(decls))
	for _, decl := range decls {
		seen[decl.Metric] = decl.MetricSpec()
	}
	out := make([]MetricSpec, 0, len(seen))
	for _, spec := range seen {
		out = append(out, spec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Metric < out[j].Metric })
	return out
}

// indexDeclarations builds the name lookup an adapter needs to map a source to
// its metric. It performs no validation: [NewSources] is the load gate, and a
// process whose declarations it rejected never starts its adapters.
func indexDeclarations(decls []Declaration) map[string]Declaration {
	out := make(map[string]Declaration, len(decls))
	for _, decl := range decls {
		out[decl.Name] = decl
	}
	return out
}

// SourcesConfig configures a [Sources].
type SourcesConfig struct {
	// Aggregator holds the buckets these sources read. Required.
	Aggregator *Aggregator
	// Adapters are the configured ingestion adapters, looked up by name.
	Adapters []Adapter
	// Fallback answers the calls in a batch that name a source this resolver
	// does not own — in practice the synchronous fact plane. Nil makes an
	// unknown call an error, which is the right answer for a deployment that
	// declared no synchronous sources.
	Fallback engine.SourceResolver
	// Now overrides the clock. Nil means time.Now.
	Now func() time.Time
	// Audit receives a record of every failed lookup, exactly as the
	// synchronous plane's does.
	Audit fact.Auditor
}

// Sources is the load-checked set of velocity sources one deployment serves.
//
// Construction is the load gate: a Sources that exists is one whose every
// declaration was admitted.
type Sources struct {
	cfg      SourcesConfig
	agg      *Aggregator
	adapters map[string]Adapter
	decls    map[string]Declaration
	now      func() time.Time
}

var _ engine.SourceResolver = (*Sources)(nil)

// NewSources resolves velocity declarations against this deployment.
//
// Rejections wrap [fact.ErrLoad] — the same sentinel the synchronous plane
// uses — so a composition root can tell "this deployment refuses to serve this
// policy set" from a runtime failure without caring which plane refused. They
// are collected rather than reported one at a time, so an operator fixing a
// deployment sees the whole list in one pass.
func NewSources(decls []Declaration, cfg SourcesConfig) (*Sources, error) {
	if cfg.Aggregator == nil {
		return nil, fmt.Errorf("%w: velocity sources require an aggregator", fact.ErrLoad)
	}
	s := &Sources{
		cfg:      cfg,
		agg:      cfg.Aggregator,
		adapters: make(map[string]Adapter, len(cfg.Adapters)),
		decls:    make(map[string]Declaration, len(decls)),
		now:      cfg.Now,
	}
	if s.now == nil {
		s.now = time.Now
	}
	for _, a := range cfg.Adapters {
		if a == nil {
			return nil, fmt.Errorf("%w: a nil adapter was configured", fact.ErrLoad)
		}
		if _, dup := s.adapters[a.Name()]; dup {
			return nil, fmt.Errorf("%w: adapter %q is configured twice", fact.ErrLoad, a.Name())
		}
		s.adapters[a.Name()] = a
	}

	var errs []error
	for _, decl := range decls {
		if _, dup := s.decls[decl.Name]; dup {
			errs = append(errs, fmt.Errorf("%w: source %q: declared more than once", fact.ErrLoad, decl.Name))
			continue
		}
		resolved, err := s.resolve(decl)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.decls[decl.Name] = resolved
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return s, nil
}

func (s *Sources) resolve(decl Declaration) (Declaration, error) {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: source %q: %s", fact.ErrLoad, decl.Name, fmt.Sprintf(format, args...))
	}
	if !policy.ValidIdent(decl.Name) {
		return decl, fail("name is not a valid identifier")
	}
	if decl.Metric == "" {
		return decl, fail("no metric is configured")
	}
	spec, ok := s.agg.Spec(decl.Metric)
	if !ok {
		return decl, fail("metric %q is not aggregated by this deployment", decl.Metric)
	}
	if decl.BucketWidth != spec.BucketWidth {
		return decl, fail("bucket width %s disagrees with the aggregator's %s for metric %q",
			decl.BucketWidth, spec.BucketWidth, decl.Metric)
	}
	if decl.AllowDeduction != spec.AllowDeduction {
		return decl, fail("deduction permission disagrees with the aggregator's for metric %q", decl.Metric)
	}

	switch {
	case decl.Window <= 0:
		return decl, fail("window must be positive")
	case decl.Window < decl.BucketWidth:
		return decl, fail("window %s is narrower than one %s bucket", decl.Window, decl.BucketWidth)
	case decl.Window%decl.BucketWidth != 0:
		return decl, fail("window %s is not a whole number of %s buckets; the bucket width is the precision this source has",
			decl.Window, decl.BucketWidth)
	case decl.Window > store.MaxDeclarableWindow:
		// The dedup rows are kept for the widest declarable window plus slack.
		// A window past that reaches buckets whose events no longer have a
		// dedup row, so a replay would be counted a second time inside an
		// answer a limit is about to be enforced with.
		return decl, fail("window %s exceeds the maximum declarable window %s, past which deduplication state is no longer retained",
			decl.Window, store.MaxDeclarableWindow)
	}

	if decl.Adapter == "" {
		return decl, fail("no ingestion adapter is configured")
	}
	adapter, ok := s.adapters[decl.Adapter]
	if !ok {
		return decl, fail("ingestion adapter %q is not configured on this deployment", decl.Adapter)
	}
	if decl.Freshness < 0 {
		return decl, fail("freshness limit must not be negative")
	}
	if decl.Freshness > 0 && !adapter.ReportsLag() {
		return decl, fail("declares a freshness limit of %s, but adapter %q declares it cannot report ingestion lag",
			decl.Freshness, decl.Adapter)
	}

	onErr := decl.OnError
	if onErr == "" {
		onErr = policy.DefaultOnError
	}
	if onErr != policy.OnErrorDeny {
		return decl, fail("on_error %q is not admissible for a velocity source: a limit that fails open is a limit that switches itself off when ingestion breaks",
			onErr)
	}
	decl.OnError = onErr

	if len(decl.Params) != 1 || decl.Params[0].Type != policy.TypeString {
		return decl, fail("takes exactly one string parameter, the subject whose aggregate is read")
	}
	if !policy.ValidIdent(decl.Params[0].Name) {
		return decl, fail("parameter %q is not a valid identifier", decl.Params[0].Name)
	}
	if decl.Returns != policy.TypeDouble && decl.Returns != policy.TypeInt {
		return decl, fail("returns %q; a velocity source returns double for the value sum or int for the event count",
			decl.Returns)
	}
	return decl, nil
}

// Names returns the configured velocity source names, sorted.
func (s *Sources) Names() []string {
	out := make([]string, 0, len(s.decls))
	for name := range s.decls {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Declaration returns the resolved declaration for a source.
func (s *Sources) Declaration(name string) (Declaration, bool) {
	decl, ok := s.decls[name]
	return decl, ok
}

// Adapter returns the ingestion adapter feeding a source.
func (s *Sources) Adapter(name string) (Adapter, bool) {
	decl, ok := s.decls[name]
	if !ok {
		return nil, false
	}
	adapter, ok := s.adapters[decl.Adapter]
	return adapter, ok
}

// Lag reports the ingestion lag behind one source.
func (s *Sources) Lag(name string, now time.Time) (time.Duration, bool) {
	adapter, ok := s.Adapter(name)
	if !ok {
		return 0, false
	}
	return adapter.Lag(now)
}

// VerifySchema checks a policy schema's event sources against this deployment.
//
// It is the counterpart of [fact.Registry.VerifySchema], which skips event
// sources precisely because they are served here. Between the two, every
// source a schema declares is checked by exactly one of them.
func (s *Sources) VerifySchema(schema *policy.Schema) error {
	if schema == nil {
		return nil
	}
	var errs []error
	for i := range schema.Sources {
		sd := schema.Sources[i]
		if sd.Kind != policy.SourceEvent {
			continue
		}
		decl, ok := s.decls[sd.Name]
		if !ok {
			errs = append(errs, fmt.Errorf("%w: source %q: declared by the schema as an event source but not configured on this deployment",
				fact.ErrLoad, sd.Name))
			continue
		}
		if err := sameEventSignature(decl.SourceDecl(), sd); err != nil {
			errs = append(errs, fmt.Errorf("%w: source %q: %w", fact.ErrLoad, sd.Name, err))
		}
	}
	return errors.Join(errs...)
}

func sameEventSignature(configured, declared policy.SourceDecl) error {
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
	onErr := declared.OnError
	if onErr == "" {
		onErr = policy.DefaultOnError
	}
	if onErr != policy.OnErrorDeny {
		return fmt.Errorf("declared with on_error %q; a velocity source may only fail closed", onErr)
	}
	return nil
}

// Lookup resolves one velocity source.
//
// The freshness check comes before the bucket query and not after. A stale
// source has no answer worth reading, and reading one anyway would put a
// number in front of an operator that looks like a total and is in fact
// whatever arrived before ingestion stopped.
func (s *Sources) Lookup(ctx context.Context, name string, args ...fact.Value) (fact.Value, error) {
	decl, ok := s.decls[name]
	if !ok {
		return fact.Value{}, s.record(ctx, &fact.Failure{
			Source: name,
			Reason: fact.ReasonUnknownSource,
			Detail: "no velocity source by that name is configured on this deployment",
		})
	}
	if len(args) != 1 {
		return fact.Value{}, s.record(ctx, &fact.Failure{
			Source: name,
			Reason: fact.ReasonBadArgument,
			Detail: fmt.Sprintf("expected 1 argument, got %d", len(args)),
		})
	}
	subject, ok := args[0].Data.(string)
	if !ok || args[0].Type != policy.TypeString {
		return fact.Value{}, s.record(ctx, &fact.Failure{
			Source: name,
			Reason: fact.ReasonBadArgument,
			Detail: fmt.Sprintf("expected a string subject, got %s", args[0].Type),
		})
	}

	now := s.now()
	if decl.Freshness > 0 {
		if f := s.checkFreshness(decl, now); f != nil {
			return fact.Value{}, s.record(ctx, f)
		}
	}

	window, err := s.agg.Window(ctx, decl.Metric, subject, decl.Window, now)
	if err != nil {
		return fact.Value{}, s.record(ctx, &fact.Failure{
			Source: name,
			Reason: ReasonAggregate,
			Detail: "the bucket query failed",
			Err:    err,
		})
	}
	if decl.Returns == policy.TypeInt {
		return fact.Int(window.Count), nil
	}
	return fact.Double(window.Sum), nil
}

func (s *Sources) checkFreshness(decl Declaration, now time.Time) *fact.Failure {
	adapter, ok := s.adapters[decl.Adapter]
	if !ok {
		return &fact.Failure{
			Source: decl.Name,
			Reason: ReasonLagUnknown,
			Detail: fmt.Sprintf("adapter %q is not running in this process", decl.Adapter),
		}
	}
	lag, reported := adapter.Lag(now)
	if !reported {
		return &fact.Failure{
			Source: decl.Name,
			Reason: ReasonLagUnknown,
			Detail: fmt.Sprintf("adapter %q has confirmed no events, so its ingestion lag is unknown", decl.Adapter),
		}
	}
	if lag > decl.Freshness {
		return &fact.Failure{
			Source: decl.Name,
			Reason: ReasonStale,
			Detail: fmt.Sprintf("ingestion lag %s exceeds the declared freshness limit %s", lag, decl.Freshness),
		}
	}
	return nil
}

// ResolveSources implements [engine.SourceResolver].
//
// The batch is split by name: calls this deployment serves as velocity sources
// are answered here, and the rest go to the fallback in one batch of their own
// so that the synchronous plane still sees a batch rather than a call at a
// time.
func (s *Sources) ResolveSources(ctx context.Context, calls []engine.SourceCall) (*engine.Facts, error) {
	var mine, theirs []engine.SourceCall
	for _, call := range calls {
		if _, ok := s.decls[call.Name]; ok {
			mine = append(mine, call)
			continue
		}
		theirs = append(theirs, call)
	}

	facts := engine.NewFacts()
	if len(theirs) > 0 {
		if s.cfg.Fallback == nil {
			return nil, fmt.Errorf("stream: fact source %q is not configured on this deployment", theirs[0].Name)
		}
		delegated, err := s.cfg.Fallback.ResolveSources(ctx, theirs)
		if err != nil {
			return nil, err
		}
		for _, call := range theirs {
			v, ok := delegated.Value(call)
			if !ok {
				return nil, fmt.Errorf("stream: fact source %q was not answered by the fact plane", call.Name)
			}
			facts.Set(call, v)
		}
	}

	for _, call := range mine {
		decl := s.decls[call.Name]
		if len(call.Args) != 1 {
			return nil, fmt.Errorf("stream: velocity source %q takes 1 argument, condition passed %d",
				call.Name, len(call.Args))
		}
		v, err := s.Lookup(ctx, call.Name, fact.Value{Type: decl.Params[0].Type, Data: call.Args[0]})
		if err != nil {
			return nil, fmt.Errorf("stream: velocity source %q: %w", call.Name, err)
		}
		facts.Set(call, v.Data)
	}
	return facts, nil
}

func (s *Sources) record(ctx context.Context, f *fact.Failure) error {
	// Every velocity source fails closed; the load gate refused any other
	// value, so this is a restatement rather than a choice made here.
	f.OnError = policy.OnErrorDeny
	f.At = s.now()
	if s.cfg.Audit != nil {
		s.cfg.Audit.RecordFactFailure(ctx, f)
	}
	return f
}
