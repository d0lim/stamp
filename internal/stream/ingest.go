package stream

// ingest.go is the HTTP ingest adapter: the second implementation of the
// ingestion port, and the one that lets a deployment run velocity limits with
// no broker at all.
//
// It exists for two reasons that are worth keeping separate. It is a feature —
// the demo bundle and any small installation ingest over HTTP and never
// operate Kafka. And it is the proof that the port is a seam: this adapter has
// no offsets, no partitions and no consumer group to hide behind the boundary,
// so a port that had leaked any of those could not have been implemented here.
// Building it alongside the Kafka adapter rather than after it is what keeps
// the port from setting into a Kafka shape.
//
// Being a write surface, it carries the obligations of one. Authentication and
// the audit of a refused caller happen at the HTTP boundary, above this file.
// What this file adds is the part specific to ingestion:
//
// A credential is bound to the (source, metric) pairs it may write. Without
// that, any credential that can ingest anything can inflate or deflate any
// subject's aggregate on any metric — which is a way both to block another
// tenant's transactions and to keep one's own under a limit.
//
// Permission to send a deduction is granted separately from permission to
// write the metric. Adding to a total and subtracting from it are different
// powers; only the second one can erase the evidence of an earlier event, so
// only the second one is worth granting on its own terms.
//
// The metric is never read from the request. It comes from the named source's
// declaration, because a metric taken from the body would be a metric chosen
// after the scope check was written and before it was applied.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Ingest-specific rejection sentinels.
var (
	// ErrNoIngestGrant means the authenticated caller holds no ingest
	// credential at all on this deployment.
	ErrNoIngestGrant = fmt.Errorf("%w: the caller holds no ingest grant", ErrRejected)
	// ErrUnknownSource means the batch named a source this deployment does not
	// serve.
	ErrUnknownSource = fmt.Errorf("%w: no such velocity source", ErrRejected)
	// ErrDeductionNotPermitted means the credential may write the metric but
	// was not separately granted permission to send deductions.
	ErrDeductionNotPermitted = fmt.Errorf("%w: the credential is not permitted to send deduction deltas", ErrRejected)
	// ErrBatchTooLarge means the batch exceeded the configured event cap.
	ErrBatchTooLarge = fmt.Errorf("%w: too many events in one batch", ErrRejected)
	// ErrNotAccepting means the adapter has no sink to deliver into.
	ErrNotAccepting = errors.New("stream: the ingest adapter is not accepting events")
)

// Ingest defaults.
const (
	// DefaultMaxBatchEvents caps one ingest batch. The batch is applied in a
	// single transaction, so the cap is also the bound on how long one
	// unprivileged request can hold a connection.
	DefaultMaxBatchEvents = 500
	// DefaultMaxRateEntries bounds the rate limiter's table. Its keys are
	// request-derived, so an unbounded table is a memory amplifier reachable
	// from outside.
	DefaultMaxRateEntries = 8192
)

// ScopeEntry binds a credential to one (source, metric) pair.
//
// Both halves are named even though a source determines its metric, because
// the pair is what an operator writes and what an auditor reads. A scope entry
// whose metric disagrees with the source's declaration is a configuration
// mistake, and it is refused at load rather than resolved in favour of one of
// the two.
type ScopeEntry struct {
	Source string
	Metric string
}

// String renders the pair for messages and audit detail.
func (s ScopeEntry) String() string { return s.Source + "/" + s.Metric }

// RateLimit is a token bucket's parameters. A zero value means no limit, which
// is only reachable when an operator configured none.
type RateLimit struct {
	// PerSecond is the sustained refill rate in events per second.
	PerSecond float64
	// Burst is the bucket size. Zero with a positive rate means one second's
	// worth.
	Burst float64
}

func (r RateLimit) unlimited() bool { return r.PerSecond <= 0 }

func (r RateLimit) withDefaults() RateLimit {
	if r.Burst <= 0 {
		r.Burst = r.PerSecond
	}
	return r
}

// IngestCredential is one operator-configured ingest grant.
type IngestCredential struct {
	// CallerID is the authenticated caller identifier this grant belongs to.
	CallerID string
	// Scope is the set of (source, metric) pairs the credential may write.
	// Anything outside it is refused.
	Scope []ScopeEntry
	// AllowDeduction grants permission to send negative deltas. It is separate
	// from the source declaration's own deduction permission: both must say
	// yes, because one describes what the metric supports and the other
	// describes what this credential is trusted with.
	AllowDeduction bool
	// Rate limits the credential as a whole. Zero uses the deployment default.
	Rate RateLimit
	// SubjectRate limits events per subject for this credential. Zero uses the
	// deployment default. It is separate from Rate so that a credential with a
	// generous overall budget still cannot spend all of it on one subject.
	SubjectRate RateLimit
}

// IngestEvent is one event as an ingest caller sends it.
//
// It carries no metric and no caller: the metric comes from the named source's
// declaration and the caller comes from the verified credential, so neither is
// something a request body can choose.
type IngestEvent struct {
	// EventID is the producer-assigned identifier.
	EventID string
	// Subject is whose aggregate the event contributes to.
	Subject string
	// Value is the delta.
	Value float64
	// ProducedAt is the producer's timestamp.
	ProducedAt time.Time
}

// IngestBatch is one ingest request.
type IngestBatch struct {
	// Source names the velocity source being written.
	Source string
	// Events are the events, in no particular order.
	Events []IngestEvent
}

// IngestConfig configures an [Ingest].
type IngestConfig struct {
	// Name is the adapter name a source declaration joins on. Required.
	Name string
	// Declarations are the velocity source declarations, which is how a source
	// name resolves to a metric. It is the same slice [NewSources] is given —
	// the adapter is built before the sources so that the sources can be built
	// against the real adapter rather than a placeholder.
	Declarations []Declaration
	// Sink receives accepted batches. Required.
	Sink Sink
	// Credentials are the operator-configured ingest grants.
	Credentials []IngestCredential
	// DefaultRate applies to a credential that configured none.
	DefaultRate RateLimit
	// DefaultSubjectRate applies per subject to a credential that configured
	// none.
	DefaultSubjectRate RateLimit
	// MaxBatchEvents caps one batch. Zero selects DefaultMaxBatchEvents.
	MaxBatchEvents int
	// MaxRateEntries bounds the rate limiter table. Zero selects
	// DefaultMaxRateEntries.
	MaxRateEntries int
	// Now overrides the clock. Nil means time.Now.
	Now func() time.Time
}

// Ingest is the HTTP ingest adapter.
type Ingest struct {
	name     string
	decls    map[string]Declaration
	sink     Sink
	creds    map[string]resolvedCredential
	maxBatch int
	now      func() time.Time
	lag      LagTracker
	limiter  *Limiter
}

type resolvedCredential struct {
	IngestCredential
	scope map[ScopeEntry]struct{}
}

var _ Adapter = (*Ingest)(nil)

// NewIngest builds the HTTP ingest adapter.
//
// Every scope entry is checked against the configured sources here. An entry
// naming a source this deployment does not serve, or naming the wrong metric
// for a source it does serve, is a typo that would otherwise grant nothing and
// be discovered as a mysterious refusal in production.
func NewIngest(cfg IngestConfig) (*Ingest, error) {
	switch {
	case cfg.Name == "":
		return nil, errors.New("stream: the ingest adapter requires a name")
	case len(cfg.Declarations) == 0:
		return nil, errors.New("stream: the ingest adapter requires the velocity source declarations")
	case cfg.Sink == nil:
		return nil, errors.New("stream: the ingest adapter requires a sink")
	}
	i := &Ingest{
		name:     cfg.Name,
		decls:    indexDeclarations(cfg.Declarations),
		sink:     cfg.Sink,
		creds:    make(map[string]resolvedCredential, len(cfg.Credentials)),
		maxBatch: cfg.MaxBatchEvents,
		now:      cfg.Now,
	}
	if i.maxBatch <= 0 {
		i.maxBatch = DefaultMaxBatchEvents
	}
	if i.now == nil {
		i.now = time.Now
	}
	maxEntries := cfg.MaxRateEntries
	if maxEntries <= 0 {
		maxEntries = DefaultMaxRateEntries
	}
	i.limiter = NewLimiter(maxEntries, i.now)

	for _, cred := range cfg.Credentials {
		if cred.CallerID == "" {
			return nil, errors.New("stream: an ingest credential has no caller identifier")
		}
		if _, dup := i.creds[cred.CallerID]; dup {
			return nil, fmt.Errorf("stream: ingest credential %q is configured twice", cred.CallerID)
		}
		if len(cred.Scope) == 0 {
			return nil, fmt.Errorf("stream: ingest credential %q has an empty scope: it could write nothing", cred.CallerID)
		}
		resolved := resolvedCredential{
			IngestCredential: cred,
			scope:            make(map[ScopeEntry]struct{}, len(cred.Scope)),
		}
		for _, entry := range cred.Scope {
			decl, ok := i.decls[entry.Source]
			if !ok {
				return nil, fmt.Errorf("stream: ingest credential %q is scoped to source %q, which is not configured",
					cred.CallerID, entry.Source)
			}
			if entry.Metric != decl.Metric {
				return nil, fmt.Errorf("stream: ingest credential %q scopes source %q to metric %q, but that source reads metric %q",
					cred.CallerID, entry.Source, entry.Metric, decl.Metric)
			}
			resolved.scope[entry] = struct{}{}
		}
		if resolved.Rate.unlimited() {
			resolved.Rate = cfg.DefaultRate
		}
		if resolved.SubjectRate.unlimited() {
			resolved.SubjectRate = cfg.DefaultSubjectRate
		}
		resolved.Rate = resolved.Rate.withDefaults()
		resolved.SubjectRate = resolved.SubjectRate.withDefaults()
		i.creds[cred.CallerID] = resolved
	}
	return i, nil
}

// Name implements [Adapter].
func (i *Ingest) Name() string { return i.name }

// ReportsLag implements [Adapter]. An ingest batch carries producer
// timestamps, so this adapter always can.
func (i *Ingest) ReportsLag() bool { return true }

// Lag implements [Adapter].
func (i *Ingest) Lag(now time.Time) (time.Duration, bool) { return i.lag.Lag(now) }

// Run implements [Adapter].
//
// There is no loop to run: the transport is the request handler, and events
// arrive through [Ingest.Submit] whenever a caller sends them. Run exists
// because the port is stated once for both adapters, and it waits for
// shutdown. A port that could not accommodate an adapter with nothing to poll
// would be a port describing a consumer loop, which is a broker concept
// wearing a neutral name.
//
// The sink argument is ignored. This adapter's sink is fixed at construction
// because [Ingest.Submit] is called from a request handler that has no
// relationship with whoever called Run — a route can be mounted in a process
// that does not run background components at all, and it must accept events
// there.
func (i *Ingest) Run(ctx context.Context, _ Sink) error {
	if i.sink == nil {
		return ErrNotAccepting
	}
	<-ctx.Done()
	return nil
}

// Scopes returns the (source, metric) pairs a credential may write, sorted.
// It exists so a deployment can show an operator what a credential can do
// without the operator reading the wiring.
func (i *Ingest) Scopes(callerID string) []ScopeEntry {
	cred, ok := i.creds[callerID]
	if !ok {
		return nil
	}
	out := make([]ScopeEntry, 0, len(cred.scope))
	for entry := range cred.scope {
		out = append(out, entry)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].String() < out[b].String() })
	return out
}

// Submit accepts one batch from an authenticated caller.
//
// The order of the checks is the point. Scope is checked before the rate limit
// so that an out-of-scope caller cannot spend a budget it was never entitled
// to; the rate limit is checked before the sink so that a flood never reaches
// the database; and the metric is filled in from the declaration rather than
// from the request at every step.
func (i *Ingest) Submit(ctx context.Context, callerID string, batch IngestBatch) (Result, error) {
	if callerID == "" {
		return Result{}, ErrNoCaller
	}
	cred, ok := i.creds[callerID]
	if !ok {
		return Result{}, fmt.Errorf("%w: %s", ErrNoIngestGrant, callerID)
	}
	decl, ok := i.decls[batch.Source]
	if !ok {
		// A caller learns that the source is not writable by them, not whether
		// it exists: the two answers are the same one on purpose.
		return Result{}, fmt.Errorf("%w: %q", ErrUnknownSource, batch.Source)
	}
	entry := ScopeEntry{Source: batch.Source, Metric: decl.Metric}
	if _, granted := cred.scope[entry]; !granted {
		return Result{}, fmt.Errorf("%w: %s", ErrOutOfScope, entry)
	}
	if len(batch.Events) == 0 {
		return Result{}, nil
	}
	if len(batch.Events) > i.maxBatch {
		return Result{}, fmt.Errorf("%w: %d events, the cap is %d", ErrBatchTooLarge, len(batch.Events), i.maxBatch)
	}

	events := make([]Event, len(batch.Events))
	for n, in := range batch.Events {
		if in.Value < 0 && !cred.AllowDeduction {
			return Result{}, fmt.Errorf("%w: %s on %s", ErrDeductionNotPermitted, callerID, entry)
		}
		events[n] = Event{
			CallerID:   callerID,
			EventID:    in.EventID,
			Metric:     decl.Metric,
			SubjectID:  in.Subject,
			Value:      in.Value,
			ProducedAt: in.ProducedAt,
		}
	}

	if err := i.charge(cred, callerID, events); err != nil {
		return Result{}, err
	}

	res, err := i.sink.Accept(ctx, events)
	if err != nil {
		return Result{}, err
	}
	i.lag.Observe(events)
	return res, nil
}

// charge spends the caller's budget and each subject's budget for the batch.
//
// Both are spent before anything is applied, and neither is refunded when a
// later check fails. A refund would make a rejected batch free, and a batch
// that is free to send is a batch that can be sent forever.
func (i *Ingest) charge(cred resolvedCredential, callerID string, events []Event) error {
	if !cred.Rate.unlimited() {
		if !i.limiter.Allow("caller\x1f"+callerID, cred.Rate, float64(len(events))) {
			return fmt.Errorf("%w: caller %s", ErrRateLimited, callerID)
		}
	}
	if cred.SubjectRate.unlimited() {
		return nil
	}
	counts := make(map[string]float64, len(events))
	for _, e := range events {
		counts[e.SubjectID]++
	}
	for subject, n := range counts {
		// The key includes the caller so that one caller flooding a subject
		// cannot exhaust another caller's budget for the same subject, which
		// would turn a rate limit into a denial-of-service tool.
		if !i.limiter.Allow("subject\x1f"+callerID+"\x1f"+subject, cred.SubjectRate, n) {
			return fmt.Errorf("%w: subject %s", ErrRateLimited, subject)
		}
	}
	return nil
}

// Limiter is a bounded table of token buckets.
//
// The bound is the security-relevant part. Keys derive from request content —
// the subject identifier in particular — so an unbounded table would let an
// authenticated caller grow the process's memory by inventing subjects. When
// the table is full it is swept of buckets that have refilled to full, and a
// sweep that frees nothing refuses the request: a limiter that cannot record a
// charge has not applied a limit.
//
// It is exported, and it is exported here rather than moved somewhere neutral,
// because the decide surface needs the same limiter and already speaks this
// package's [RateLimit] — the shape four `STAMP_INGEST_RATE_*` variables are
// written in and the one the decide path was told to reuse rather than reinvent.
// Two copies of a sweep-or-refuse table is the thing worth avoiding: the refusal
// on a full table is the subtle half, and a second copy of it would be a second
// chance to get it wrong. Nothing about the type is stream-specific; it charges
// a key a cost against a rate.
type Limiter struct {
	mu      sync.Mutex
	max     int
	now     func() time.Time
	entries map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	at     time.Time
	// limit is stored per bucket rather than read from the request being
	// charged, because two credentials can have different rates and the sweep
	// has to know whether *this* bucket has refilled — not whether it would
	// have under whichever caller happened to arrive when the table filled up.
	limit RateLimit
}

// NewLimiter builds a limiter whose table holds at most max buckets.
func NewLimiter(max int, now func() time.Time) *Limiter {
	return &Limiter{max: max, now: now, entries: make(map[string]*tokenBucket)}
}

// Allow charges key the given cost against limit and reports whether the budget
// covered it. It never refunds: a charge that a later check rejects still costs
// the caller, because a rejected request that is free is a request that can be
// sent forever.
func (l *Limiter) Allow(key string, limit RateLimit, cost float64) bool {
	if limit.unlimited() {
		return true
	}
	limit = limit.withDefaults()
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= l.max && l.sweepLocked(now) == 0 {
			return false
		}
		b = &tokenBucket{tokens: limit.Burst, at: now, limit: limit}
		l.entries[key] = b
	}
	// A reconfigured rate takes effect on the next charge rather than at the
	// next restart, and never carries more tokens across than the new burst.
	b.limit = limit
	b.tokens = min(b.tokens, limit.Burst)

	if elapsed := now.Sub(b.at); elapsed > 0 {
		b.tokens = min(limit.Burst, b.tokens+elapsed.Seconds()*limit.PerSecond)
		b.at = now
	}
	if b.tokens < cost {
		return false
	}
	b.tokens -= cost
	return true
}

// sweepLocked drops buckets that have refilled to full and therefore carry no
// information: recreating one costs nothing an attacker could exploit, because
// a full bucket is what a new key would get anyway.
func (l *Limiter) sweepLocked(now time.Time) int {
	freed := 0
	for key, b := range l.entries {
		refilled := b.tokens + now.Sub(b.at).Seconds()*b.limit.PerSecond
		if refilled >= b.limit.Burst {
			delete(l.entries, key)
			freed++
		}
	}
	return freed
}
