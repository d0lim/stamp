package engine_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/policy"
)

// Each test parses its own copy of these documents. Normalization rewrites the
// condition tree in place, so two policy sets must never share one.
const checkDocuments = `
apiVersion: stamp/v1
kind: Schema
entities:
  - name: user
    attributes: {id: string, level: int}
  - name: doc
    attributes: {id: string}
actions: [read]
---
apiVersion: stamp/v1
kind: Policy
id: read-allowlist
subject: user
resource: doc
actions: [read]
condition:
  left: {field: subject.id}
  in: [alice]
`

// tightenedDocuments is the same set with the allowlist narrowed, which is the
// revision a refresh has to reach the evaluator with.
const tightenedDocuments = `
apiVersion: stamp/v1
kind: Schema
entities:
  - name: user
    attributes: {id: string, level: int}
  - name: doc
    attributes: {id: string}
actions: [read]
---
apiVersion: stamp/v1
kind: Policy
id: read-allowlist
subject: user
resource: doc
actions: [read]
condition:
  left: {field: subject.id}
  in: [bob]
`

func mustSnapshot(t *testing.T, documents, revision string) *engine.Snapshot {
	t.Helper()
	set, err := policy.Load(strings.NewReader(documents))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	versions := make([]engine.PolicyVersion, len(set.Policies))
	for i := range set.Policies {
		versions[i] = engine.PolicyVersion{Version: revision, Policy: set.Policies[i]}
	}
	snap, err := engine.NewSnapshot(revision, set.Schema, versions)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return snap
}

func readRequest(id string) engine.Input {
	return engine.Input{
		Action:   "read",
		Subject:  engine.Entity{Type: "user", ID: id, Attributes: map[string]any{"id": id}},
		Resource: engine.Entity{Type: "doc", ID: "doc-1", Attributes: map[string]any{"id": "doc-1"}},
	}
}

// swappableLoader is a store stand-in whose revision and failure behaviour a
// test can move.
type swappableLoader struct {
	mu       sync.Mutex
	snapshot *engine.Snapshot
	revision string
	err      error
	calls    atomic.Int64
}

func (l *swappableLoader) LoadSnapshot(context.Context) (*engine.Snapshot, engine.Revision, error) {
	l.calls.Add(1)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return nil, "", l.err
	}
	return l.snapshot, engine.Revision(l.revision), nil
}

func (l *swappableLoader) set(snap *engine.Snapshot, revision string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.snapshot, l.revision, l.err = snap, revision, nil
}

func (l *swappableLoader) fail(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.err = err
}

// clock is a hand-wound clock: staleness is a duration, and a real clock would
// make these tests either slow or flaky.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestJudgmentSwitchesToTheNewVersionWithinTheRefreshInterval(t *testing.T) {
	t.Parallel()
	loader := &swappableLoader{snapshot: mustSnapshot(t, checkDocuments, "rev-1"), revision: "rev-1"}
	service, err := engine.NewCheckService(t.Context(), engine.CheckConfig{
		Loader:          loader,
		RefreshInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	if result, err := service.Evaluate(t.Context(), readRequest("alice")); err != nil || !result.Allowed() {
		t.Fatalf("before the revision: %v %v", result.Reason(), err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = service.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	loader.set(mustSnapshot(t, tightenedDocuments, "rev-2"), "rev-2")

	// The poll interval is the bound the requirement states, so the deadline
	// here is a generous multiple of it rather than an arbitrary sleep.
	deadline := time.Now().Add(2 * time.Second)
	for {
		result, err := service.Evaluate(t.Context(), readRequest("alice"))
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if !result.Allowed() {
			if result.Reason() != engine.ReasonConditionNotMet {
				t.Fatalf("after the revision: reason %q", result.Reason())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the new policy version did not reach the evaluator within the refresh window")
		}
		time.Sleep(time.Millisecond)
	}

	if got := service.Revision(); got != "rev-2" {
		t.Fatalf("revision: want rev-2, got %q", got)
	}
	if stats := service.Stats(); stats.Swaps < 2 {
		t.Fatalf("swaps: want at least 2, got %d", stats.Swaps)
	}
}

// R24's staged failure: inside the grace window the instance keeps judging on
// what it has and reports rising staleness; past the deadline it stops judging.
// The two knobs are separate so that an ordinary failover does not deny.
func TestStaleGraceWindowThenFailClosed(t *testing.T) {
	t.Parallel()
	c := &clock{now: time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)}
	loader := &swappableLoader{snapshot: mustSnapshot(t, checkDocuments, "rev-1"), revision: "rev-1"}
	service, err := engine.NewCheckService(t.Context(), engine.CheckConfig{
		Loader:            loader,
		RefreshInterval:   5 * time.Second,
		StalenessDeadline: 60 * time.Second,
		Now:               c.Now,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	loader.fail(errors.New("database unreachable"))

	// Inside the grace window: the refresh fails, the old version still judges,
	// and the staleness metric rises.
	c.advance(30 * time.Second)
	if err := service.Refresh(t.Context()); err == nil {
		t.Fatal("refresh should have reported the loader failure")
	}
	result, err := service.Evaluate(t.Context(), readRequest("alice"))
	if err != nil || !result.Allowed() {
		t.Fatalf("inside the grace window the old version must still judge: %v %v", result.Reason(), err)
	}
	stats := service.Stats()
	if stats.StaleFor != 30*time.Second {
		t.Fatalf("staleness metric: want 30s, got %s", stats.StaleFor)
	}
	if stats.FailClosed {
		t.Fatal("an instance inside the grace window reported itself fail-closed")
	}
	if stats.RefreshFailures != 1 || stats.LastError == "" {
		t.Fatalf("refresh failure not reported: %+v", stats)
	}

	// Past the deadline: the instance no longer knows what is in force, so it
	// stops answering rather than answering from memory.
	c.advance(31 * time.Second)
	result, err = service.Evaluate(t.Context(), readRequest("alice"))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Allowed() {
		t.Fatal("an instance past the staleness deadline allowed a request")
	}
	if result.Reason() != engine.ReasonPolicySetStale {
		t.Fatalf("reason: want %q, got %q", engine.ReasonPolicySetStale, result.Reason())
	}
	if !service.Stats().FailClosed {
		t.Fatal("stats do not report the instance as fail-closed")
	}

	// Recovery clears it: the staleness metric measures the last confirmation,
	// not the last change.
	loader.set(mustSnapshot(t, checkDocuments, "rev-1"), "rev-1")
	if err := service.Refresh(t.Context()); err != nil {
		t.Fatalf("refresh after recovery: %v", err)
	}
	if stats := service.Stats(); stats.StaleFor != 0 || stats.FailClosed {
		t.Fatalf("recovery did not clear staleness: %+v", stats)
	}
	if result, err := service.Evaluate(t.Context(), readRequest("alice")); err != nil || !result.Allowed() {
		t.Fatalf("after recovery: %v %v", result.Reason(), err)
	}
}

func TestRefreshWithoutARevisionChangeKeepsTheCompiledPrograms(t *testing.T) {
	t.Parallel()
	loader := &swappableLoader{snapshot: mustSnapshot(t, checkDocuments, "rev-1"), revision: "rev-1"}
	service, err := engine.NewCheckService(t.Context(), engine.CheckConfig{Loader: loader})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := service.Evaluate(t.Context(), readRequest("alice")); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	before := service.Stats()

	for range 5 {
		if err := service.Refresh(t.Context()); err != nil {
			t.Fatalf("refresh: %v", err)
		}
	}
	if _, err := service.Evaluate(t.Context(), readRequest("alice")); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	after := service.Stats()
	if after.Swaps != before.Swaps {
		t.Fatalf("an unchanged revision swapped the snapshot: %d -> %d", before.Swaps, after.Swaps)
	}
	if after.Cache.Compilations != before.Cache.Compilations {
		t.Fatalf("an unchanged revision recompiled: %d -> %d",
			before.Cache.Compilations, after.Cache.Compilations)
	}
}

func TestCheckServiceRequiresAnInitialLoad(t *testing.T) {
	t.Parallel()
	loader := &swappableLoader{}
	loader.fail(errors.New("cold start"))
	if _, err := engine.NewCheckService(t.Context(), engine.CheckConfig{Loader: loader}); err == nil {
		t.Fatal("a service with no policy set was allowed to start")
	}
	if _, err := engine.NewCheckService(t.Context(), engine.CheckConfig{}); err == nil {
		t.Fatal("a service with no loader was allowed to start")
	}
}

func TestInstancesShareNoStateBeyondTheCompileCache(t *testing.T) {
	t.Parallel()
	cache := engine.NewCache()
	loader := &swappableLoader{snapshot: mustSnapshot(t, checkDocuments, "rev-1"), revision: "rev-1"}

	first, err := engine.NewCheckService(t.Context(), engine.CheckConfig{Loader: loader, Cache: cache})
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := engine.NewCheckService(t.Context(), engine.CheckConfig{Loader: loader, Cache: cache})
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if _, err := first.Evaluate(t.Context(), readRequest("alice")); err != nil {
		t.Fatalf("first evaluate: %v", err)
	}
	if _, err := second.Evaluate(t.Context(), readRequest("alice")); err != nil {
		t.Fatalf("second evaluate: %v", err)
	}
	// One compilation served both: the cache is keyed by policy version, which
	// is what lets a shared cache be correct without any invalidation protocol.
	if got := cache.Stats().Compilations; got != 1 {
		t.Fatalf("compilations: want 1, got %d", got)
	}

	// A revision only the second instance has picked up does not disturb the
	// first: nothing about one instance's snapshot is visible to the other.
	loader.set(mustSnapshot(t, tightenedDocuments, "rev-2"), "rev-2")
	if err := second.Refresh(t.Context()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if first.Revision() != "rev-1" || second.Revision() != "rev-2" {
		t.Fatalf("revisions leaked between instances: %q %q", first.Revision(), second.Revision())
	}
}

func TestConcurrentEvaluationDuringRefresh(t *testing.T) {
	t.Parallel()
	loader := &swappableLoader{snapshot: mustSnapshot(t, checkDocuments, "rev-1"), revision: "rev-1"}
	service, err := engine.NewCheckService(t.Context(), engine.CheckConfig{Loader: loader})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for range 25 {
				if i%4 == 0 {
					_ = service.Refresh(t.Context())
					continue
				}
				if _, err := service.Evaluate(t.Context(), readRequest("alice")); err != nil {
					t.Errorf("evaluate: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
