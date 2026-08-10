package engine

import (
	"context"
	"sync"
	"testing"

	"github.com/d0lim/stamp/internal/policy"
)

// benchCondition is representative rather than minimal: a compile cache that
// only helps trivial conditions would not be worth having.
func benchCondition() policy.Node {
	return policy.All(
		policy.Compare{Left: policy.Field(policy.RoleSubject, "level"), Op: policy.OpGe, Right: policy.Int(3)},
		policy.Compare{Left: policy.Field(policy.RoleResource, "amount"), Op: policy.OpLt, Right: policy.Int(1000)},
		policy.Compare{Left: policy.Field(policy.RoleContext, "hour"), Op: policy.OpLe, Right: policy.Int(18)},
		policy.In(policy.Field(policy.RoleSubject, "dept"), policy.List(policy.TypeString, "eng", "ops")),
		policy.Any(
			policy.Compare{Left: policy.Field(policy.RoleSubject, "admin"), Op: policy.OpEq, Right: policy.Bool(true)},
			policy.Compare{Left: policy.Field(policy.RoleResource, "owner"), Op: policy.OpEq, Right: policy.String("u1")},
		),
	)
}

// TestReevaluatingAPolicyVersionUsesTheCache is the cache scenario: the same
// version compiles once no matter how often it is evaluated.
func TestReevaluatingAPolicyVersionUsesTheCache(t *testing.T) {
	t.Parallel()
	snap := newTestSnapshot(t, ungated("p", benchCondition()))
	eval := NewCheckEvaluator(snap)
	for range 32 {
		if _, err := eval.Evaluate(context.Background(), baseInput()); err != nil {
			t.Fatalf("evaluate: %v", err)
		}
	}
	stats := eval.Cache().Stats()
	if stats.Compilations != 1 {
		t.Fatalf("compiled %d times, want 1", stats.Compilations)
	}
	if stats.Misses != 1 {
		t.Fatalf("missed %d times, want 1", stats.Misses)
	}
	if stats.Hits != 31 {
		t.Fatalf("hit %d times, want 31", stats.Hits)
	}
	if stats.Entries != 1 {
		t.Fatalf("holds %d entries, want 1", stats.Entries)
	}
}

// TestCacheIsSharedAndKeyedByVersion covers the two halves of the key and the
// sharing a stateless check fleet depends on.
func TestCacheIsSharedAndKeyedByVersion(t *testing.T) {
	t.Parallel()
	set := newTestSet(t, ungated("p", benchCondition()))
	cache := NewCache()

	newEval := func(schemaVersion, policyVersion string) *CheckEvaluator {
		snap, err := NewSnapshot(schemaVersion, set.Schema, []PolicyVersion{{Version: policyVersion, Policy: set.Policies[0]}})
		if err != nil {
			t.Fatalf("NewSnapshot: %v", err)
		}
		return NewCheckEvaluator(snap, WithCache(cache))
	}

	for _, eval := range []*CheckEvaluator{
		newEval("schema@1", "p@1"),
		newEval("schema@1", "p@1"),
	} {
		if _, err := eval.Evaluate(context.Background(), baseInput()); err != nil {
			t.Fatalf("evaluate: %v", err)
		}
	}
	if got := cache.Stats().Compilations; got != 1 {
		t.Fatalf("two evaluators sharing a cache compiled %d times, want 1", got)
	}

	if _, err := newEval("schema@1", "p@2").Evaluate(context.Background(), baseInput()); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got := cache.Stats().Compilations; got != 2 {
		t.Fatalf("a new policy revision compiled %d times in total, want 2", got)
	}

	if _, err := newEval("schema@2", "p@1").Evaluate(context.Background(), baseInput()); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got := cache.Stats().Compilations; got != 3 {
		t.Fatalf("a new schema revision compiled %d times in total, want 3", got)
	}
}

// TestCacheCompilesOnceUnderConcurrency runs with -race in CI, so it also covers
// the cache's own synchronization.
func TestCacheCompilesOnceUnderConcurrency(t *testing.T) {
	t.Parallel()
	snap := newTestSnapshot(t, ungated("p", benchCondition()))
	eval := NewCheckEvaluator(snap)

	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := eval.Evaluate(context.Background(), baseInput()); err != nil {
				t.Errorf("evaluate: %v", err)
			}
		}()
	}
	wg.Wait()

	stats := eval.Cache().Stats()
	if stats.Compilations != 1 {
		t.Fatalf("compiled %d times under concurrency, want 1", stats.Compilations)
	}
	if stats.Hits+stats.Misses != 64 {
		t.Fatalf("counted %d lookups, want 64", stats.Hits+stats.Misses)
	}
}

// BenchmarkCompileCache is the verification the unit asks for. "cached" reuses a
// warm cache the way a check instance does; "uncached" pays compilation on every
// request, which is what the engine would do without the cache. The gap is the
// cache's whole justification.
func BenchmarkCompileCache(b *testing.B) {
	set := &policy.Set{Schema: testSchema(), Policies: []policy.Policy{ungated("p", benchCondition())}}
	set.Normalize()
	if diags := policy.Validate(set); len(diags) > 0 {
		b.Fatalf("fixture does not validate:\n%s", diags.Error())
	}
	snap, err := NewSnapshot("schema@1", set.Schema, []PolicyVersion{{Version: "p@1", Policy: set.Policies[0]}})
	if err != nil {
		b.Fatal(err)
	}
	in := baseInput()

	b.Run("cached", func(b *testing.B) {
		eval := NewCheckEvaluator(snap)
		if _, err := eval.Evaluate(context.Background(), in); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			if _, err := eval.Evaluate(context.Background(), in); err != nil {
				b.Fatal(err)
			}
		}
		if got := eval.Cache().Stats().Compilations; got != 1 {
			b.Fatalf("compiled %d times, want 1", got)
		}
	})

	b.Run("uncached", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			eval := NewCheckEvaluator(snap, WithCache(NewCache()))
			if _, err := eval.Evaluate(context.Background(), in); err != nil {
				b.Fatal(err)
			}
		}
	})
}
