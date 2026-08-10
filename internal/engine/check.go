package engine

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/d0lim/stamp/internal/policy"
)

// Additional grounds a check-path deny can carry.
//
// Both are refusals the evaluator itself never produces: they come from the
// serving instance's own condition rather than from the request. They live
// beside the evaluator's reasons because a caller reading a deny must be able
// to tell "your request was refused" from "this instance is not fit to judge",
// and an operator alerts on exactly that difference.
const (
	// ReasonPolicySetStale is the ground for a deny by an instance whose
	// policy set could not be refreshed within the staleness deadline. Before
	// that deadline the instance keeps judging on the old version; after it,
	// it stops judging at all.
	ReasonPolicySetStale Reason = "policy_set_stale"
	// ReasonAuditUnavailable is the ground for a deny by an instance whose
	// audit buffer is saturated while the operator has selected fail-closed.
	// It is produced by the serving surface, which owns the buffer.
	ReasonAuditUnavailable Reason = "audit_unavailable"
	// ReasonEvaluationFailed is the ground for a request whose evaluation
	// could not complete — an unresolved fact, a condition that errored. It is
	// a deny because "we could not tell" and "the answer is no" must give the
	// caller the same instruction, and only the reason differs.
	ReasonEvaluationFailed Reason = "evaluation_failed"
)

// DenyResult builds a deny with an explicit ground, for the refusals a serving
// surface owns rather than the evaluator.
//
// There is deliberately no matching constructor for an allow. Denying is
// always safe to express from outside this package; allowing is what the two
// evaluator invariants exist to constrain, and an exported allow constructor
// would hand any caller the bypass that [allowCheck]'s Checkable argument
// closes off.
func DenyResult(reason Reason) CheckResult {
	return CheckResult{decision: Deny, reason: reason}
}

// Revision names one immutable version of the effective policy set.
//
// It is opaque to the engine and is only ever compared for equality: the store
// decides what it looks like, and the check service uses it to tell "the set I
// am holding" from "the set that is now in force" without diffing policies.
type Revision string

// SnapshotLoader produces the current effective policy set.
//
// This is the whole of the check path's coupling to storage. A check instance
// holds no shared state — it polls this, compares the revision, and swaps its
// evaluator — which is what makes the tier horizontally scalable without a
// cache invalidation protocol between instances.
type SnapshotLoader interface {
	// LoadSnapshot returns the effective snapshot and the revision that names
	// it. Returning the same revision as the previous call means nothing
	// changed, and the returned snapshot may then be discarded.
	LoadSnapshot(ctx context.Context) (*Snapshot, Revision, error)
}

// SnapshotLoaderFunc adapts a function to [SnapshotLoader].
type SnapshotLoaderFunc func(ctx context.Context) (*Snapshot, Revision, error)

// LoadSnapshot calls f.
func (f SnapshotLoaderFunc) LoadSnapshot(ctx context.Context) (*Snapshot, Revision, error) {
	return f(ctx)
}

// Defaults for the refresh knobs, matching the requirement's stated values.
const (
	// DefaultRefreshInterval bounds how long a newly effective policy version
	// takes to reach every check instance.
	DefaultRefreshInterval = 5 * time.Second
	// DefaultStalenessDeadline bounds how long an instance may keep judging on
	// a policy set it has failed to refresh.
	DefaultStalenessDeadline = 60 * time.Second
)

// CheckConfig configures a [CheckService].
type CheckConfig struct {
	// Loader supplies the effective policy set. Required.
	Loader SnapshotLoader
	// RefreshInterval is how often the set is polled. Zero selects
	// DefaultRefreshInterval.
	RefreshInterval time.Duration
	// StalenessDeadline is how long a failing refresh is tolerated before the
	// instance stops judging. Zero selects DefaultStalenessDeadline.
	//
	// It is a separate knob from RefreshInterval on purpose. Tying the two
	// together would mean that an ordinary database failover — seconds of
	// unavailability on a five second poll — dropped the whole check tier into
	// deny at once, which is a far larger outage than the one it was reacting
	// to.
	StalenessDeadline time.Duration
	// Cache is the compile cache. It is process-local by construction: entries
	// are keyed by policy version, so a fleet shares nothing and needs no
	// invalidation message. Nil creates one.
	Cache *Cache
	// Resolver is the fact plane. Nil means policies reaching a fact source
	// fail closed.
	Resolver SourceResolver
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// CheckStats is a snapshot of one instance's freshness and cache counters.
type CheckStats struct {
	// Revision names the policy set the instance is currently judging on.
	Revision Revision
	// LastRefresh is when the set was last confirmed against the store.
	LastRefresh time.Time
	// StaleFor is how long it has been since that confirmation. It is the
	// staleness metric an operator alerts on: it rises while refreshes fail
	// and returns to zero on the first success.
	StaleFor time.Duration
	// FailClosed reports whether StaleFor has passed the deadline, so that
	// this instance is denying every request.
	FailClosed bool
	// Refreshes, RefreshFailures and Swaps count polls, failed polls, and
	// polls that actually replaced the snapshot.
	Refreshes       uint64
	RefreshFailures uint64
	Swaps           uint64
	// LastError is the most recent refresh failure, empty when the last poll
	// succeeded.
	LastError string
	// Cache reports the compile cache counters.
	Cache CacheStats
}

// CheckService is one check instance's view of the effective policy set.
//
// It owns three things and nothing else: the current evaluator, the compile
// cache behind it, and the freshness of both. Everything about it is
// process-local — no instance can observe another's cache, and no instance
// tells another to invalidate — so scaling the tier is adding processes.
//
// Freshness is a poll, not a subscription, and its failure mode is staged.
// While refreshes succeed the instance judges on the current version. While
// they fail it keeps judging on the version it has and reports rising
// staleness. Past the deadline it stops judging: [CheckService.Evaluate]
// returns a deny with ReasonPolicySetStale, which is a refusal to answer rather
// than an answer.
type CheckService struct {
	loader   SnapshotLoader
	interval time.Duration
	deadline time.Duration
	cache    *Cache
	resolver SourceResolver
	now      func() time.Time

	mu        sync.RWMutex
	evaluator *CheckEvaluator
	snapshot  *Snapshot
	revision  Revision
	freshAt   time.Time
	lastErr   string

	refreshes atomic.Uint64
	failures  atomic.Uint64
	swaps     atomic.Uint64
}

// NewCheckService builds a check instance and loads the policy set once.
//
// The initial load must succeed. An instance that started without a policy set
// would deny everything with a ground that says the policy set is missing,
// which reads to an operator like a policy problem rather than a boot problem;
// failing the boot puts the real cause in front of them instead.
func NewCheckService(ctx context.Context, cfg CheckConfig) (*CheckService, error) {
	if cfg.Loader == nil {
		return nil, errors.New("engine: check service requires a snapshot loader")
	}
	s := &CheckService{
		loader:   cfg.Loader,
		interval: cfg.RefreshInterval,
		deadline: cfg.StalenessDeadline,
		cache:    cfg.Cache,
		resolver: cfg.Resolver,
		now:      cfg.Now,
	}
	if s.interval <= 0 {
		s.interval = DefaultRefreshInterval
	}
	if s.deadline <= 0 {
		s.deadline = DefaultStalenessDeadline
	}
	if s.cache == nil {
		s.cache = NewCache()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if err := s.Refresh(ctx); err != nil {
		return nil, fmt.Errorf("engine: initial policy load: %w", err)
	}
	return s, nil
}

// Refresh polls the loader once and swaps the snapshot when the revision moved.
//
// A poll that returns the revision already held still counts as freshness:
// what the staleness deadline measures is the last time this instance could
// confirm what the effective set is, not the last time it changed.
func (s *CheckService) Refresh(ctx context.Context) error {
	s.refreshes.Add(1)
	snap, rev, err := s.loader.LoadSnapshot(ctx)
	if err != nil {
		s.failures.Add(1)
		s.mu.Lock()
		s.lastErr = err.Error()
		s.mu.Unlock()
		return err
	}
	if snap == nil {
		s.failures.Add(1)
		err := errors.New("snapshot loader returned no snapshot")
		s.mu.Lock()
		s.lastErr = err.Error()
		s.mu.Unlock()
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.freshAt = s.now()
	s.lastErr = ""
	if s.evaluator != nil && s.revision == rev {
		return nil
	}
	var opts []Option
	opts = append(opts, WithCache(s.cache))
	if s.resolver != nil {
		opts = append(opts, WithSourceResolver(s.resolver))
	}
	s.snapshot = snap
	s.evaluator = NewCheckEvaluator(snap, opts...)
	s.revision = rev
	s.swaps.Add(1)
	return nil
}

// Run polls until the context is cancelled.
//
// A failing poll does not stop the loop: the staleness deadline, not the
// error, decides when this instance stops judging. Run is the shape a role
// registry's background component expects.
func (s *CheckService) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = s.Refresh(ctx)
		}
	}
}

// Evaluate answers a check request against the currently held policy set.
//
// The staleness gate runs before the evaluator, not after it: an instance past
// its deadline does not know what the effective policy set is, so any answer it
// gave — including a permissive one derived from a policy that may since have
// been tightened — would be a guess.
func (s *CheckService) Evaluate(ctx context.Context, in Input) (CheckResult, error) {
	s.mu.RLock()
	evaluator, freshAt := s.evaluator, s.freshAt
	s.mu.RUnlock()

	if evaluator == nil || s.staleFor(freshAt) > s.deadline {
		return DenyResult(ReasonPolicySetStale), nil
	}
	return evaluator.Evaluate(ctx, in)
}

// Revision reports the policy set the instance is judging on.
func (s *CheckService) Revision() Revision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revision
}

// Schema returns the schema of the held snapshot, for surfaces that have to
// interpret a request against it. The caller must not modify it.
func (s *CheckService) Schema() *policy.Schema {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.snapshot == nil {
		return nil
	}
	return s.snapshot.Schema()
}

// Resolver returns the fact plane the instance evaluates through, so a
// one-off evaluation such as a dry run resolves facts the same way a served
// request does.
func (s *CheckService) Resolver() SourceResolver { return s.resolver }

// Stats reports freshness and cache counters.
func (s *CheckService) Stats() CheckStats {
	s.mu.RLock()
	rev, freshAt, lastErr := s.revision, s.freshAt, s.lastErr
	s.mu.RUnlock()

	stale := s.staleFor(freshAt)
	return CheckStats{
		Revision:        rev,
		LastRefresh:     freshAt,
		StaleFor:        stale,
		FailClosed:      stale > s.deadline,
		Refreshes:       s.refreshes.Load(),
		RefreshFailures: s.failures.Load(),
		Swaps:           s.swaps.Load(),
		LastError:       lastErr,
		Cache:           s.cache.Stats(),
	}
}

func (s *CheckService) staleFor(freshAt time.Time) time.Duration {
	if freshAt.IsZero() {
		return s.deadline + time.Nanosecond
	}
	d := s.now().Sub(freshAt)
	if d < 0 {
		return 0
	}
	return d
}

// NodeTrace is one condition node's contribution to a dry run.
type NodeTrace struct {
	// Pointer is a JSON Pointer into the policy document, using the same
	// scheme the validator's diagnostics use, so a form can put a node's
	// result on the same row it would put a validation error.
	Pointer string `json:"pointer"`
	// Kind is the node's shape: all, any, not, compare, or member.
	Kind string `json:"kind"`
	// Result is whether the node held. It is nil when the node could not be
	// evaluated, which is a third outcome and not a false.
	Result *bool `json:"result"`
	// Error explains a nil Result.
	Error string `json:"error,omitempty"`
}

// TraceResult is the outcome of a dry run: what matched, what each condition
// node did, and what would have happened.
type TraceResult struct {
	// Matched reports whether the policy applies to the request at all — its
	// action and the entity types it binds — before any condition is consulted.
	Matched bool `json:"matched"`
	// Holds reports whether the whole condition held.
	Holds bool `json:"holds"`
	// Nodes are the per-node results in document order, root first.
	Nodes []NodeTrace `json:"nodes"`
	// Challenges are the challenges that would fire. They are populated only
	// when the policy both matched and held, because a challenge attached to a
	// policy that does not apply fires nothing.
	Challenges []policy.Challenge `json:"-"`
	// SourceCalls are the fact source calls the condition reached, resolved in
	// one batch exactly as a served request would resolve them.
	SourceCalls []SourceCall `json:"-"`
	// Decision and Reason are the verdict the check path would have returned.
	Decision Decision `json:"-"`
	Reason   Reason   `json:"-"`
	// Error is set when evaluation could not complete.
	Error string `json:"error,omitempty"`
}

// Trace evaluates one unsaved policy against one sample request, without
// touching the compile cache and without storing anything.
//
// Bypassing the cache is the point rather than an omission. A dry run's subject
// is a document that has no version identifier, because it was never stored;
// caching a compilation under a key that does not name a stored revision would
// let an unsaved draft serve a later request. The compilations here are
// therefore thrown away with the call.
//
// The two evaluator invariants hold here too, and for the same structural
// reason: the verdict comes from [Classify], so a challenge-bearing draft
// reports requires_decision rather than allow, and a draft that does not apply
// to the sample reports no_matching_policy.
func Trace(ctx context.Context, s *policy.Schema, p *policy.Policy, in Input, resolver SourceResolver) (*TraceResult, error) {
	if s == nil {
		return nil, errors.New("engine: trace needs a schema")
	}
	if p == nil {
		return nil, errors.New("engine: trace needs a policy")
	}

	res := &TraceResult{Matched: matches(p, in)}
	binding, err := bind(s, in)
	if err != nil {
		return nil, err
	}
	program, err := compileProgram(s, p)
	if err != nil {
		return nil, err
	}
	calls, err := program.SourceCalls(binding)
	if err != nil {
		return nil, err
	}
	facts, err := resolveCalls(ctx, resolver, calls)
	if err != nil {
		return nil, err
	}
	res.SourceCalls = calls

	holds, err := program.Evaluate(ctx, binding, facts)
	switch {
	case err != nil:
		res.Error = err.Error()
	default:
		res.Holds = holds
	}
	res.Nodes = traceNodes(ctx, s, p, binding, facts)

	switch {
	case !res.Matched:
		res.Decision, res.Reason = Deny, ReasonNoMatchingPolicy
	case res.Error != "" || !res.Holds:
		res.Decision, res.Reason = Deny, ReasonConditionNotMet
	default:
		switch c := Classify(p).(type) {
		case Gated:
			res.Decision, res.Reason = Deny, ReasonRequiresDecision
			res.Challenges = c.Challenges()
		case Checkable:
			result := allowCheck(c)
			res.Decision, res.Reason = result.Decision(), result.Reason()
		}
	}
	return res, nil
}

// resolveCalls performs the one fact batch a trace needs. It mirrors the served
// path's contract — every call the condition can reach, resolved before any
// condition runs — so a dry run cannot report a result the served path would
// not reproduce.
func resolveCalls(ctx context.Context, resolver SourceResolver, calls []SourceCall) (*Facts, error) {
	if len(calls) == 0 {
		return nil, nil
	}
	if resolver == nil {
		return nil, fmt.Errorf("%w: no fact source resolver is configured", ErrUnresolvedFact)
	}
	facts, err := resolver.ResolveSources(ctx, calls)
	if err != nil {
		return nil, fmt.Errorf("resolving fact sources: %w", err)
	}
	return facts, nil
}

// traceNodes evaluates every node of the condition on its own, so that an
// author reading a false at the root can see which row produced it.
//
// Each node is compiled as if it were the whole condition. That reuses the one
// compiler rather than adding a second evaluation path for explanation, which
// is what keeps the explanation from disagreeing with the verdict.
func traceNodes(ctx context.Context, s *policy.Schema, p *policy.Policy, b *Binding, facts *Facts) []NodeTrace {
	var out []NodeTrace
	var walk func(n policy.Node, pointer string)
	walk = func(n policy.Node, pointer string) {
		if n == nil {
			return
		}
		trace := NodeTrace{Pointer: pointer, Kind: nodeKind(n)}
		sub := *p
		sub.Condition = n
		if program, err := compileProgram(s, &sub); err != nil {
			trace.Error = err.Error()
		} else if held, err := program.Evaluate(ctx, b, facts); err != nil {
			trace.Error = err.Error()
		} else {
			value := held
			trace.Result = &value
		}
		out = append(out, trace)

		if logic, ok := n.(policy.Logic); ok {
			if logic.Op == policy.LogicNot {
				if len(logic.Operands) == 1 {
					walk(logic.Operands[0], pointer+"/not")
				}
				return
			}
			for i, operand := range logic.Operands {
				walk(operand, pointer+"/"+string(logic.Op)+"/"+strconv.Itoa(i))
			}
		}
	}
	walk(p.Condition, "/condition")
	return out
}

func nodeKind(n policy.Node) string {
	switch v := n.(type) {
	case policy.Logic:
		return string(v.Op)
	case policy.Compare:
		return "compare"
	case policy.Member:
		if v.Negate {
			return "not_in"
		}
		return "in"
	default:
		return "unknown"
	}
}
