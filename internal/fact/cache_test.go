package fact

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/policy"
)

// countingRegistry stands up a fact endpoint that counts how many times it was
// actually called, which is the only way to tell a cache hit from a fast miss.
func countingRegistry(t *testing.T, decl Declaration, clock *fakeClock, body func() string) (*Registry, *atomic.Int64, *httptest.Server) {
	t.Helper()
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(body()))
	}))
	t.Cleanup(server.Close)

	res := newFakeResolver()
	res.set("facts.test", "127.0.0.1")
	target := hostSwap(t, server.URL, "facts.test")
	decl.URL = target + "/fact"

	r, err := NewRegistry([]Declaration{decl}, Config{
		Now: clock.now,
		Egress: EgressConfig{
			Allow:         []string{originOfURL(t, target)},
			AllowLoopback: true,
			Resolve:       res.resolve,
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)
	return r, &calls, server
}

// R14: within the declared TTL the answer comes from cache and the remote is
// not called; past it, the answer is fetched again. The freshness limit of a
// decision is what the declaration said it was.
func TestWithinTTLServesFromCacheAndAfterwardsRefetches(t *testing.T) {
	clock := newFakeClock()
	decl := httpDeclWithParams(policy.TypeInt)
	decl.TTL = 30 * time.Second
	r, calls, _ := countingRegistry(t, decl, clock, func() string { return `{"value": 1}` })

	if _, err := r.Lookup(context.Background(), "risk"); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("remote calls after the first lookup = %d, want 1", got)
	}

	clock.advance(29 * time.Second)
	if _, err := r.Lookup(context.Background(), "risk"); err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("a lookup inside the TTL called the remote %d times, want 0 more", got-1)
	}

	clock.advance(2 * time.Second) // now 31s in: past the declared TTL
	if _, err := r.Lookup(context.Background(), "risk"); err != nil {
		t.Fatalf("third lookup: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("remote calls after expiry = %d, want 2", got)
	}
}

// The boundary belongs to the miss side. An entry that has reached its expiry
// is expired; TTL is a bound on staleness, not a rounding hint.
func TestTTLBoundaryCountsAsExpired(t *testing.T) {
	clock := newFakeClock()
	decl := httpDeclWithParams(policy.TypeInt)
	decl.TTL = 30 * time.Second
	r, calls, _ := countingRegistry(t, decl, clock, func() string { return `{"value": 1}` })

	if _, err := r.Lookup(context.Background(), "risk"); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	clock.advance(30 * time.Second)
	if _, err := r.Lookup(context.Background(), "risk"); err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("remote calls = %d, want the entry to have expired exactly at the TTL", got)
	}
}

// R36: an expired entry is not a fallback. When the remote is down the answer
// is a failure, not the last good value — a stale answer served during an
// outage is a decision made on facts nobody is checking any more.
func TestExpiredEntryIsNotServedWhenTheRemoteIsDown(t *testing.T) {
	clock := newFakeClock()
	decl := httpDeclWithParams(policy.TypeInt)
	decl.TTL = 30 * time.Second
	r, _, server := countingRegistry(t, decl, clock, func() string { return `{"value": 1}` })

	v, err := r.Lookup(context.Background(), "risk")
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if v.Data != int64(1) {
		t.Fatalf("value = %#v", v.Data)
	}

	server.Close() // the remote goes away
	clock.advance(31 * time.Second)

	got, err := r.Lookup(context.Background(), "risk")
	if err == nil {
		t.Fatalf("expired entry was served as a substitute answer: %#v", got.Data)
	}
	f := mustFailure(t, err)
	if !f.FailsClosed() {
		t.Fatal("must fail closed")
	}
}

// The cached value is a copy. A caller that mutated the list it was handed
// would be editing every later evaluation's view of the world.
func TestCachedListsAreCopiedOut(t *testing.T) {
	clock := newFakeClock()
	decl := httpDeclWithParams(policy.ListOf(policy.TypeString))
	decl.TTL = time.Minute
	r, _, _ := countingRegistry(t, decl, clock, func() string { return `{"value": ["a", "b"]}` })

	first, err := r.Lookup(context.Background(), "risk")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	first.Data.([]any)[0] = "tampered"

	second, err := r.Lookup(context.Background(), "risk")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if second.Data.([]any)[0] != "a" {
		t.Fatalf("a caller edited the cached value: %#v", second.Data)
	}
}

// --- the key ------------------------------------------------------------------

// The key is the source identifier plus normalized arguments. Two lookups share
// an entry exactly when they are the same question.
func TestCacheKeyDistinguishesQuestions(t *testing.T) {
	distinct := []struct {
		name string
		args []Value
	}{
		{"no arguments", nil},
		{"int one", []Value{Int(1)}},
		{"double one", []Value{Double(1)}},
		{"string one", []Value{String("1")}},
		{"bool", []Value{Bool(true)}},
		{"duration", []Value{Duration(time.Second)}},
		{"two strings", []Value{String("a"), String("b")}},
		// Without length prefixing these two would encode identically, and a
		// caller could pick which cache entry they landed in by choosing a
		// separator byte.
		{"separator in the first argument", []Value{String("a\x1fb"), String("c")}},
		{"list", []Value{List(policy.TypeString, "a", "b")}},
		{"list reordered", []Value{List(policy.TypeString, "b", "a")}},
		{"list of one joined", []Value{List(policy.TypeString, "ab")}},
	}
	seen := map[string]string{}
	for _, tc := range distinct {
		key := cacheKey("src", tc.args)
		if other, dup := seen[key]; dup {
			t.Errorf("%q and %q share a cache key", tc.name, other)
		}
		seen[key] = tc.name
	}

	// And a different source never shares an entry with this one.
	if cacheKey("src", nil) == cacheKey("src2", nil) {
		t.Error("two sources share a cache key")
	}
	if cacheKey("srcx", []Value{String("y")}) == cacheKey("srcxy", nil) {
		t.Error("the source identifier bleeds into the arguments")
	}
}

// The same question asked two ways is one question: an instant is an instant
// whatever zone it was written in, and negative zero is zero.
func TestCacheKeyNormalizesEquivalentArguments(t *testing.T) {
	seoul := time.FixedZone("KST", 9*60*60)
	utc := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	local := utc.In(seoul)
	if cacheKey("src", []Value{Timestamp(utc)}) != cacheKey("src", []Value{Timestamp(local)}) {
		t.Error("the same instant in two zones produced two cache keys")
	}
	if cacheKey("src", []Value{Double(0)}) != cacheKey("src", []Value{Double(negZero())}) {
		t.Error("negative zero produced a different cache key from zero")
	}
}

func negZero() float64 {
	z := 0.0
	return -z
}

// --- the cache itself ----------------------------------------------------------

func TestCacheIsBounded(t *testing.T) {
	clock := newFakeClock()
	c := newCache(8, clock.now)
	for i := 0; i < 100; i++ {
		c.put(cacheKey("src", []Value{Int(int64(i))}), Int(int64(i)), time.Minute)
	}
	if got := c.len(); got > 8 {
		t.Fatalf("cache holds %d entries, want at most 8", got)
	}
}

func TestCacheEvictsExpiredEntriesFirst(t *testing.T) {
	clock := newFakeClock()
	c := newCache(2, clock.now)
	c.put("short", Int(1), time.Second)
	c.put("long", Int(2), time.Hour)
	clock.advance(2 * time.Second)
	c.put("new", Int(3), time.Hour)

	if _, ok := c.get("long"); !ok {
		t.Error("a live entry was evicted while an expired one was still held")
	}
	if _, ok := c.get("new"); !ok {
		t.Error("the new entry was not stored")
	}
}

func TestCacheRejectsNonPositiveTTL(t *testing.T) {
	c := newCache(8, newFakeClock().now)
	c.put("k", Int(1), 0)
	c.put("k2", Int(1), -time.Second)
	if c.len() != 0 {
		t.Fatalf("cache stored %d entries for non-positive TTLs", c.len())
	}
}

// The check path is concurrent by nature, so the cache is exercised under the
// race detector rather than trusted to be obviously correct.
func TestConcurrentLookupsAreSafe(t *testing.T) {
	clock := newFakeClock()
	decl := httpDeclWithParams(policy.ListOf(policy.TypeString), policy.Param{Name: "account", Type: policy.TypeString})
	decl.TTL = time.Minute
	r, _, _ := countingRegistry(t, decl, clock, func() string { return `{"value": ["a"]}` })

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			account := String(string(rune('a' + i%4)))
			v, err := r.Lookup(context.Background(), "risk", account)
			if err != nil {
				t.Errorf("Lookup: %v", err)
				return
			}
			if items := v.Data.([]any); len(items) != 1 {
				t.Errorf("value = %#v", v.Data)
			}
		}(i)
	}
	wg.Wait()
}
