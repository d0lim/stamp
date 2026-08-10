// Package engine compiles validated policies into cel-go programs, caches the
// compilation by policy version, and evaluates access requests against them.
//
// Two invariants hold on every path through this package, and both are carried
// by the code's shape rather than by configuration.
//
// A policy that carries challenges can never be allowed by the stateless check
// path. Policies are sorted at snapshot time into Checkable and Gated, the two
// implementations of a closed Candidate interface, and the functions that build
// an allowing result take a Checkable. A Gated value cannot be converted into a
// Checkable, so a check-path allow for a challenge-bearing policy is not a
// program that can be written — not a branch that has to remember to run.
//
// A request that no policy matches is denied with ReasonNoMatchingPolicy, on
// both paths. The answer comes from a function that takes no arguments and is
// returned before facts are fetched or any condition is evaluated. No Option
// this package exposes reaches it, which is the point: policy authorship must
// not be able to open the door that an empty or newly emptied policy set closes.
package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/d0lim/stamp/internal/policy"
)

// Entity is one bound participant of a request.
type Entity struct {
	// Type names the declared entity type. An empty Type means the role is not
	// bound, which no policy binding that role can match.
	Type string
	// ID identifies the instance.
	ID string
	// Attributes carries the values a condition may read. Every key must be an
	// attribute the schema declares for Type.
	Attributes map[string]any
}

// Input is one access evaluation request.
type Input struct {
	// Action names the operation being attempted.
	Action string
	// Subject is the actor.
	Subject Entity
	// Resource is the thing being acted on.
	Resource Entity
	// Context is optional ambient information.
	Context Entity
}

func (in Input) entity(r policy.Role) Entity {
	switch r {
	case policy.RoleSubject:
		return in.Subject
	case policy.RoleResource:
		return in.Resource
	case policy.RoleContext:
		return in.Context
	default:
		return Entity{}
	}
}

// PolicyVersion pairs a stored policy with the revision identifier its compiled
// program is cached under. The identifier is opaque to the engine; the store
// decides what it looks like.
type PolicyVersion struct {
	// Version identifies the policy revision. It must not be empty.
	Version string
	// Policy is the validated policy.
	Policy policy.Policy
}

// Snapshot is one immutable version of a policy set, with every policy already
// classified.
//
// Classification happens here, once, rather than at each evaluation. An
// evaluator never holds an unclassified policy, so there is no point in the
// evaluation path where the check on challenges could be skipped.
type Snapshot struct {
	schema  policy.Schema
	entries []snapshotEntry
}

type snapshotEntry struct {
	version   Version
	candidate Candidate
}

// NewSnapshot builds an evaluable snapshot from a schema revision and the
// policies stored against it.
//
// Every version identifier is required, because a compiled program is cached
// under the pair and an empty identifier would let two revisions share one cache
// entry — which is a wrong decision, not a slow one.
func NewSnapshot(schemaVersion string, schema policy.Schema, policies []PolicyVersion) (*Snapshot, error) {
	if schemaVersion == "" {
		return nil, errors.New("schema version is required")
	}
	snap := &Snapshot{schema: schema, entries: make([]snapshotEntry, 0, len(policies))}
	for i := range policies {
		if policies[i].Version == "" {
			return nil, fmt.Errorf("policy %q: version is required", policies[i].Policy.ID)
		}
		// Held by value rather than by a pointer into the caller's slice, so a
		// snapshot cannot change under an evaluator that is already using it.
		p := policies[i].Policy
		snap.entries = append(snap.entries, snapshotEntry{
			version:   Version{Schema: schemaVersion, Policy: policies[i].Version},
			candidate: Classify(&p),
		})
	}
	return snap, nil
}

// Len reports how many policies the snapshot holds.
func (s *Snapshot) Len() int { return len(s.entries) }

// Schema returns the schema the snapshot's policies are written against. The
// caller must not modify it: the compiled programs in the cache were built
// against this schema and a snapshot names one immutable version of it.
func (s *Snapshot) Schema() *policy.Schema { return &s.schema }

// Candidates returns the snapshot's classified policies in evaluation order.
func (s *Snapshot) Candidates() []Candidate {
	out := make([]Candidate, len(s.entries))
	for i, e := range s.entries {
		out[i] = e.candidate
	}
	return out
}

func (s *Snapshot) match(in Input) []snapshotEntry {
	var out []snapshotEntry
	for _, e := range s.entries {
		if matches(e.candidate.Policy(), in) {
			out = append(out, e)
		}
	}
	return out
}

// matches reports whether a policy applies to a request's shape: the action it
// governs and the entity types it binds. The condition is not consulted here —
// a policy that matches but whose condition does not hold is a different outcome
// from a policy that never applied at all.
func matches(p *policy.Policy, in Input) bool {
	if p == nil || !hasAction(p, in.Action) {
		return false
	}
	for _, role := range policy.Roles() {
		bound, ok := p.EntityFor(role)
		if !ok {
			continue
		}
		if in.entity(role).Type != bound {
			return false
		}
	}
	return true
}

func hasAction(p *policy.Policy, action string) bool {
	for _, a := range p.Actions {
		if a == action {
			return true
		}
	}
	return false
}

// Option configures an evaluator.
//
// There is deliberately no option here that touches what happens when no policy
// matches, or what the check path does with a challenge-bearing policy. Those
// are the two evaluator invariants, and an invariant with a configuration knob
// is a default.
type Option func(*core)

// WithCache makes an evaluator share a compile cache with other evaluators. A
// nil cache is ignored, so an evaluator always has one.
func WithCache(c *Cache) Option {
	return func(e *core) {
		if c != nil {
			e.cache = c
		}
	}
}

// WithSourceResolver supplies the fact plane an evaluator resolves declared
// sources through. An evaluator without one fails closed on any policy whose
// condition reaches a fact source.
func WithSourceResolver(r SourceResolver) Option {
	return func(e *core) { e.resolver = r }
}

type core struct {
	snapshot *Snapshot
	cache    *Cache
	resolver SourceResolver
}

func newCore(snap *Snapshot, opts ...Option) *core {
	c := &core{snapshot: snap, cache: NewCache()}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// evaluate runs the part of an evaluation both paths share and returns the
// classified policies that apply.
//
// The second return value distinguishes "no policy matched" from "policies
// matched but none applied". Collapsing the two would make the fail-closed
// answer for an empty policy set indistinguishable from an ordinary condition
// miss, and the requirement is specifically about the empty case.
func (c *core) evaluate(ctx context.Context, in Input) (applicable []Candidate, resolved FactSnapshot, matched bool, err error) {
	entries := c.snapshot.match(in)
	if len(entries) == 0 {
		return nil, FactSnapshot{}, false, nil
	}
	binding, err := bind(&c.snapshot.schema, in)
	if err != nil {
		return nil, FactSnapshot{}, true, err
	}
	programs := make([]*Program, len(entries))
	var calls []SourceCall
	seen := make(map[string]struct{})
	for i, e := range entries {
		prg, err := c.cache.Compile(e.version, &c.snapshot.schema, e.candidate.Policy())
		if err != nil {
			return nil, FactSnapshot{}, true, err
		}
		programs[i] = prg
		sites, err := prg.SourceCalls(binding)
		if err != nil {
			return nil, FactSnapshot{}, true, err
		}
		for _, call := range sites {
			if _, dup := seen[call.key()]; dup {
				continue
			}
			seen[call.key()] = struct{}{}
			calls = append(calls, call)
		}
	}
	facts, err := c.resolve(ctx, calls)
	if err != nil {
		return nil, FactSnapshot{}, true, err
	}
	// The snapshot is frozen here, between resolution and evaluation, because
	// this is the one moment at which "the facts this evaluation rested on" is
	// a set rather than a history: the batch is complete, and no condition has
	// run yet to make some of it look more relevant than the rest.
	frozen := newFactSnapshot(calls, facts)
	for i, prg := range programs {
		holds, err := prg.Evaluate(ctx, binding, facts)
		if err != nil {
			return nil, frozen, true, err
		}
		if holds {
			applicable = append(applicable, entries[i].candidate)
		}
	}
	return applicable, frozen, true, nil
}

// resolve fetches every fact the matched policies can reach, in one batch,
// before any condition runs. Batching is not only an efficiency choice: it makes
// the set of facts a decision rested on a function of the request rather than of
// which operand CEL happened to short-circuit.
func (c *core) resolve(ctx context.Context, calls []SourceCall) (*Facts, error) {
	if len(calls) == 0 {
		return nil, nil
	}
	if c.resolver == nil {
		return nil, fmt.Errorf("%w: no fact source resolver is configured", ErrUnresolvedFact)
	}
	facts, err := c.resolver.ResolveSources(ctx, calls)
	if err != nil {
		return nil, fmt.Errorf("resolving fact sources: %w", err)
	}
	return facts, nil
}

// CheckEvaluator evaluates the stateless check path.
//
// The path is stateless in the strong sense: it issues nothing, waits for
// nothing, and therefore cannot satisfy a challenge. Its result type is separate
// from the decision path's for that reason — a caller holding one of these
// cannot express an allow for a policy that demands a challenge, because the
// only allowing constructor on this path takes a Checkable.
type CheckEvaluator struct{ core *core }

// NewCheckEvaluator returns a check-path evaluator over a snapshot.
func NewCheckEvaluator(snap *Snapshot, opts ...Option) *CheckEvaluator {
	return &CheckEvaluator{core: newCore(snap, opts...)}
}

// Cache returns the compile cache the evaluator uses.
func (e *CheckEvaluator) Cache() *Cache { return e.core.cache }

// Evaluate answers a check request.
//
// A Gated policy that applies ends the evaluation in a requires-decision deny
// even if an ungated policy would otherwise have allowed. The restrictive answer
// wins because the permissive one would be exactly the bypass the invariant
// exists to prevent: attaching a challenge to a policy must never be weakened by
// the presence of another policy.
func (e *CheckEvaluator) Evaluate(ctx context.Context, in Input) (CheckResult, error) {
	// The check path drops the resolved facts. It creates no decision object,
	// so it has nothing to freeze them onto and nothing that could later claim
	// to have rested on them.
	applicable, _, matched, err := e.core.evaluate(ctx, in)
	if err != nil {
		return CheckResult{}, err
	}
	if !matched {
		return checkNoMatchingPolicy(), nil
	}
	var allowed *Checkable
	for _, candidate := range applicable {
		// The Candidate interface is closed over these two implementations, so
		// there is no third case and no default to fall through to.
		switch c := candidate.(type) {
		case Gated:
			return checkRequiresDecision(c), nil
		case Checkable:
			if allowed == nil {
				match := c
				allowed = &match
			}
		}
	}
	if allowed == nil {
		return checkConditionNotMet(), nil
	}
	return allowCheck(*allowed), nil
}

// DecideEvaluator evaluates the stateful decision path.
//
// This is the only path that can turn a challenge-bearing policy into anything
// other than a deny, and even here it does not produce an allow: it produces the
// challenges that must be satisfied first. Resolving them belongs to the
// decision lifecycle, not to the evaluator.
type DecideEvaluator struct{ core *core }

// NewDecideEvaluator returns a decision-path evaluator over a snapshot.
func NewDecideEvaluator(snap *Snapshot, opts ...Option) *DecideEvaluator {
	return &DecideEvaluator{core: newCore(snap, opts...)}
}

// Cache returns the compile cache the evaluator uses.
func (e *DecideEvaluator) Cache() *Cache { return e.core.cache }

// Evaluate answers a decision request. Every applicable gated policy
// contributes its challenges, so a request covered by two of them has to satisfy
// both rather than whichever was evaluated first.
func (e *DecideEvaluator) Evaluate(ctx context.Context, in Input) (DecideResult, error) {
	applicable, facts, matched, err := e.core.evaluate(ctx, in)
	if err != nil {
		return DecideResult{}, err
	}
	if !matched {
		return decideNoMatchingPolicy(), nil
	}
	var gates []Gated
	var allowed *Checkable
	for _, candidate := range applicable {
		switch c := candidate.(type) {
		case Gated:
			gates = append(gates, c)
		case Checkable:
			if allowed == nil {
				match := c
				allowed = &match
			}
		}
	}
	if len(gates) > 0 {
		return decideChallenge(gates, facts), nil
	}
	if allowed == nil {
		return decideConditionNotMet(facts), nil
	}
	return allowDecide(*allowed, facts), nil
}
