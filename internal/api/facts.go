package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/fact"
)

// ErrFactFailOpen reports a fact lookup that failed under a declaration the
// operator has permitted to fail open.
//
// It is returned rather than acted on. The evaluator's contract is that a
// resolver error fails the evaluation closed, and there is no representation of
// "this source failed but the decision should be allow" anywhere between the
// two packages — a fabricated fact value cannot express it either, because the
// condition reading it may be negated. So the resolver reports the case
// distinctly and denies, and turning it into an allow is left to the unit that
// owns the fail-open flag rather than invented here.
var ErrFactFailOpen = errors.New("api: fact source failed under a fail-open declaration")

// FactResolver adapts the fact plane's registry to the evaluator's batch
// resolver contract.
//
// The two packages meet only here: the engine states a port that takes every
// call a condition can reach and answers them before evaluation starts, and the
// registry serves one call at a time with its own cache, timeout and egress
// rules. This is composition glue rather than a subsystem, and it lives in this
// package because the composition root that would otherwise own it is the role
// registry's wiring, which a parallel unit owns.
type FactResolver struct {
	registry *fact.Registry
}

// NewFactResolver adapts a fact registry.
func NewFactResolver(r *fact.Registry) (*FactResolver, error) {
	if r == nil {
		return nil, errors.New("api: fact resolver requires a registry")
	}
	return &FactResolver{registry: r}, nil
}

// ResolveSources answers every call in the batch, or fails the evaluation.
//
// Calls are served in order rather than concurrently. The batch is small — it
// is the distinct source calls of the policies one request matched — and the
// registry's cache absorbs the repeats, so the concurrency would buy latency
// only on a cold cache while making the failure ordering nondeterministic.
func (f *FactResolver) ResolveSources(ctx context.Context, calls []engine.SourceCall) (*engine.Facts, error) {
	facts := engine.NewFacts()
	for _, call := range calls {
		decl, ok := f.registry.Declaration(call.Name)
		if !ok {
			return nil, fmt.Errorf("api: fact source %q is not configured on this deployment", call.Name)
		}
		if len(decl.Params) != len(call.Args) {
			return nil, fmt.Errorf("api: fact source %q takes %d arguments, condition passed %d",
				call.Name, len(decl.Params), len(call.Args))
		}
		args := make([]fact.Value, len(call.Args))
		for i, arg := range call.Args {
			args[i] = fact.Value{Type: decl.Params[i].Type, Data: arg}
		}
		value, err := f.registry.Lookup(ctx, call.Name, args...)
		if err != nil {
			var failure *fact.Failure
			if errors.As(err, &failure) && !failure.FailsClosed() {
				return nil, fmt.Errorf("%w: %w", ErrFactFailOpen, err)
			}
			return nil, fmt.Errorf("api: fact source %q: %w", call.Name, err)
		}
		facts.Set(call, value.Data)
	}
	return facts, nil
}

var _ engine.SourceResolver = (*FactResolver)(nil)
