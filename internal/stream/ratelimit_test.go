package stream_test

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/stream"
)

// The token bucket table became exported so that the decide surface could
// charge against the same implementation rather than a second copy of it. The
// rename is behaviour-preserving by construction — the ingest adapter's own
// tests exercise it through Submit and were not touched — and these tests pin
// the contract that is now public, so that a later change to it has to fail
// here rather than surprise a second caller.

func TestLimiterDoesNotRefund(t *testing.T) {
	at := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	l := stream.NewLimiter(16, func() time.Time { return at })
	limit := stream.RateLimit{PerSecond: 10, Burst: 2}

	for i := range 2 {
		if !l.Allow("k", limit, 1) {
			t.Fatalf("charge %d inside a burst of two was refused", i)
		}
	}
	// The caller of a refused charge does not get the tokens back. A rejected
	// request that is free is a request that can be sent forever.
	if l.Allow("k", limit, 1) {
		t.Fatal("a third charge inside a burst of two was admitted")
	}
	if l.Allow("k", limit, 1) {
		t.Fatal("the refused charge refunded the budget")
	}
}

func TestLimiterKeysAreIndependentAndRefill(t *testing.T) {
	at := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return at }
	l := stream.NewLimiter(16, now)
	limit := stream.RateLimit{PerSecond: 2, Burst: 1}

	if !l.Allow("a", limit, 1) {
		t.Fatal("the first key was refused")
	}
	if !l.Allow("b", limit, 1) {
		t.Fatal("a second key spent the first key's budget")
	}
	if l.Allow("a", limit, 1) {
		t.Fatal("the first key was admitted over its burst")
	}

	at = at.Add(500 * time.Millisecond)
	if !l.Allow("a", limit, 1) {
		t.Error("the budget did not refill at the configured rate")
	}
	// The refill never exceeds the burst, however long the wait: an hour of
	// accrual still cannot pay for a charge larger than the bucket.
	at = at.Add(time.Hour)
	if l.Allow("a", limit, 2) {
		t.Error("an hour of refill handed out more than the burst")
	}
}

// A full table is swept of buckets that have refilled, and a sweep that frees
// nothing refuses: a limiter that cannot record a charge has not applied a
// limit, so admitting the request is the one answer that would make the memory
// bound exploitable.
func TestLimiterRefusesWhenTheTableIsFullAndNothingCanBeSwept(t *testing.T) {
	at := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return at }
	l := stream.NewLimiter(2, now)
	limit := stream.RateLimit{PerSecond: 1, Burst: 4}

	if !l.Allow("a", limit, 1) || !l.Allow("b", limit, 1) {
		t.Fatal("the table refused before it was full")
	}
	for i := range 100 {
		if l.Allow("invented", limit, 1) {
			t.Fatalf("invented key %d was admitted with the table full and nothing sweepable", i)
		}
	}

	// Once the existing buckets have refilled to full they carry no information,
	// so dropping them costs nothing an attacker could exploit.
	at = at.Add(10 * time.Second)
	if !l.Allow("invented", limit, 1) {
		t.Error("a new key was refused after the table became sweepable")
	}
}

// An unlimited rate is admitted without a bucket being created at all, so a
// deployment that configured no limit cannot be made to allocate one.
func TestLimiterWithNoRateAdmitsWithoutRecording(t *testing.T) {
	at := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	l := stream.NewLimiter(1, func() time.Time { return at })
	for i := range 100 {
		if !l.Allow("key-"+string(rune('a'+i%26)), stream.RateLimit{}, 1) {
			t.Fatalf("charge %d against no limit was refused", i)
		}
	}
}

// ---------------------------------------------------------------------------
// concurrency
// ---------------------------------------------------------------------------
//
// The mutation audit of the previous round recorded the gap these tests close:
// the limiter had no dedicated concurrency test, and `-race` had only brushed
// it incidentally through whatever else happened to run in parallel. That is
// not a small omission for this type. It is R43's enforcement point, and a
// budget that leaks under contention makes R43 true on paper and false in the
// process — the surface reports that it limited, and the thing it was limiting
// went through.
//
// Two properties are asserted, and the second is the one that matters:
//
//  1. `-race` is clean. That is table stakes and it is what the mutex already
//     buys.
//  2. The budget is *exact*. After N concurrent charges against a burst of B
//     with a clock that does not move, exactly B are admitted — not B+1, which
//     is a leak, and not B-1, which is a limiter losing charges it accepted.
//     A test that asserted only "no panic, no race" would pass against a
//     limiter that admitted twice its burst.
//
// The charges are released together through a barrier: every goroutine is
// parked on the same channel and nothing charges until all of them are there.
// A concurrency test whose goroutines run one after another is a sequential
// test with extra machinery, and this is the cheapest way to be sure they did
// not. `peak` reports how many were inside the charge at once, which is the
// measurement that says the contention was real rather than hoped for.

// storm fires n charges from n goroutines released at the same instant.
//
// It returns how many were admitted and the highest number of goroutines that
// were inside charge simultaneously. The second return is the test's own
// control: without it, "the budget was exact" is a claim about a test that may
// have run sequentially.
func storm(n int, charge func(i int) bool) (admitted, peak int) {
	var (
		arrived sync.WaitGroup
		done    sync.WaitGroup
		release = make(chan struct{})

		ok      atomic.Int64
		inside  atomic.Int64
		highest atomic.Int64
	)
	arrived.Add(n)
	done.Add(n)
	for i := range n {
		go func() {
			defer done.Done()
			arrived.Done()
			<-release

			depth := inside.Add(1)
			for {
				high := highest.Load()
				if depth <= high || highest.CompareAndSwap(high, depth) {
					break
				}
			}
			allowed := charge(i)
			inside.Add(-1)

			if allowed {
				ok.Add(1)
			}
		}()
	}
	// Nothing charges until every goroutine exists and is parked.
	arrived.Wait()
	close(release)
	done.Wait()
	return int(ok.Load()), int(highest.Load())
}

// assertContended fails a concurrency test that turned out not to be one.
//
// It is skipped on a single-P runtime, where simultaneous execution is not a
// thing the scheduler can produce and the assertion would be a lie rather than
// a check. Everywhere else it holds easily: [stream.Limiter.AllowAt] takes a
// mutex, so contention parks goroutines *inside* the charge and the depth
// climbs well past two.
func assertContended(t *testing.T, peak, n int) {
	t.Helper()
	t.Logf("%d charges, %d of them inside the limiter at once", n, peak)
	if runtime.GOMAXPROCS(0) < 2 {
		return
	}
	if peak < 2 {
		t.Errorf("no two of the %d charges were ever inside the limiter at the same time: this ran "+
			"sequentially and asserts nothing about concurrency", n)
	}
}

// TestLimiterAdmitsExactlyTheBurstUnderConcurrentCharges is the leak assertion
// at its narrowest: one key, one budget, a clock that does not move, and far
// more charges than the bucket can pay for.
func TestLimiterAdmitsExactlyTheBurstUnderConcurrentCharges(t *testing.T) {
	const (
		burst   = 16
		charges = 512
	)
	at := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	l := stream.NewLimiter(64, func() time.Time { return at })
	// The rate is large and the clock is frozen, so any admission beyond the
	// burst is a lost charge rather than a refill: there is no elapsed time for
	// the bucket to earn a token in.
	limit := stream.RateLimit{PerSecond: 1000, Burst: burst}

	admitted, peak := storm(charges, func(int) bool { return l.Allow("one-key", limit, 1) })
	assertContended(t, peak, charges)

	if admitted != burst {
		t.Fatalf("%d of %d concurrent charges were admitted against a burst of %d. "+
			"more than the burst is a budget that leaks under contention, which makes R43's "+
			"refusal something the surface reports rather than something it does; fewer is a "+
			"limiter that lost charges it had already accepted", admitted, charges, burst)
	}
}

// TestTwoLimiterTablesStayExactWhenBothAreChargedAtOnce is the gap the mutation
// audit named, stated at the level the decide surface uses.
//
// The decide surface holds two of these tables and charges both on the way
// through one request: the caller's budget and then the subject's. Nothing had
// ever driven that pair concurrently, so "the two tables do not disturb each
// other" was an argument from their being separate maps rather than an
// observation. Here they are filled at the same instant by the same goroutines,
// and each one's budget has to come out exact — the one that binds spends
// exactly its burst, and the one that does not admits everything.
func TestTwoLimiterTablesStayExactWhenBothAreChargedAtOnce(t *testing.T) {
	const (
		burst   = 8
		charges = 256
		// Large enough for every invented key, so a refusal below is a spent
		// budget and never a full table.
		tableSize = charges * 2
	)
	at := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return at }
	tight := stream.RateLimit{PerSecond: 1000, Burst: burst}
	unbounded := stream.RateLimit{PerSecond: 1e6, Burst: 1e6}

	t.Run("the caller budget binds", func(t *testing.T) {
		callers := stream.NewLimiter(tableSize, now)
		subjects := stream.NewLimiter(tableSize, now)

		var subjectAdmitted atomic.Int64
		admitted, peak := storm(charges, func(i int) bool {
			// The order is the surface's: the caller is charged first, and the
			// subject's own table is being filled at the same time by every
			// other goroutine.
			ok := callers.Allow("one-caller", tight, 1)
			if subjects.Allow(fmt.Sprintf("subject-%d", i), unbounded, 1) {
				subjectAdmitted.Add(1)
			}
			return ok
		})
		assertContended(t, peak, charges)

		if admitted != burst {
			t.Errorf("the caller budget admitted %d of %d concurrent charges, want exactly %d",
				admitted, charges, burst)
		}
		if got := int(subjectAdmitted.Load()); got != charges {
			t.Errorf("the subject table admitted %d of %d charges against an unlimited budget: "+
				"pressure on one table must not spend the other's", got, charges)
		}
	})

	t.Run("the subject budget binds", func(t *testing.T) {
		callers := stream.NewLimiter(tableSize, now)
		subjects := stream.NewLimiter(tableSize, now)

		var callerAdmitted atomic.Int64
		admitted, peak := storm(charges, func(i int) bool {
			if callers.Allow(fmt.Sprintf("caller-%d", i), unbounded, 1) {
				callerAdmitted.Add(1)
			}
			return subjects.Allow("one-subject", tight, 1)
		})
		assertContended(t, peak, charges)

		if admitted != burst {
			t.Errorf("the subject budget admitted %d of %d concurrent charges, want exactly %d",
				admitted, charges, burst)
		}
		if got := int(callerAdmitted.Load()); got != charges {
			t.Errorf("the caller table admitted %d of %d charges against an unlimited budget", got, charges)
		}
	})
}

// TestAllowAtStaysExactWhenGoroutinesSupplyDifferentInstants covers the path
// the previous round created.
//
// [stream.Limiter.AllowAt] used to be reached through a wrapper that held the
// instant behind a second mutex; the wrapper is gone and the instant is a
// parameter, so "several goroutines charging one bucket with different
// instants" is new code and nothing exercised it. It is not a hypothetical
// shape either: a challenge handler is charged at the instant the decision is
// being evaluated at, and two evaluations in flight carry two different
// instants — including, unavoidably, a later one arriving first.
//
// The budget stays exact because the instants are spread across a window too
// narrow to earn a token at the configured rate. Anything admitted above the
// burst in that window came from the bucket being written by two goroutines at
// once and not from time passing.
func TestAllowAtStaysExactWhenGoroutinesSupplyDifferentInstants(t *testing.T) {
	const (
		burst   = 16
		charges = 512
		// The instants span 93ms at one token per second: 0.093 of a token,
		// which no charge can be paid out of.
		spread = 3 * time.Millisecond
		steps  = 32
	)
	base := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	l := stream.NewLimiter(64, func() time.Time { return base })
	limit := stream.RateLimit{PerSecond: 1, Burst: burst}

	// The instants are not handed out in order. Goroutine i takes its offset at
	// a stride coprime with the number of steps, so the bucket is charged
	// forwards and backwards in time rather than monotonically — the
	// interleaving a single-threaded test cannot produce at all.
	admitted, peak := storm(charges, func(i int) bool {
		offset := time.Duration((i*7)%steps) * spread
		return l.AllowAt("one-key", limit, 1, base.Add(offset))
	})
	assertContended(t, peak, charges)

	if admitted != burst {
		t.Fatalf("%d of %d charges were admitted against a burst of %d spread over %s at %g/s. "+
			"the window cannot pay for one token, so anything above the burst is the bucket being "+
			"written by two goroutines at once", admitted, charges, burst,
			time.Duration(steps)*spread, limit.PerSecond)
	}

	// And the bucket is not left holding an impossible balance. An hour later it
	// has refilled to the burst and no further, which is only true if the
	// arithmetic above kept its tokens inside [0, burst] throughout.
	after := base.Add(time.Hour)
	var refilled int
	for range burst + 4 {
		if l.AllowAt("one-key", limit, 1, after) {
			refilled++
		}
	}
	if refilled != burst {
		t.Errorf("the bucket paid for %d charges after refilling, want exactly the burst of %d: "+
			"a bucket left above its burst hands out capacity nobody configured", refilled, burst)
	}
}

// TestAllowAtNeverPaysMoreThanTheWindowEarned is the same path with a spread
// wide enough that refill is real.
//
// The exact count is not predictable here — it depends on the order the
// instants arrive in, which is the point — so the assertion is the invariant
// that holds whatever that order was: the bucket can never pay out more than it
// started with plus what the widest gap between two supplied instants earns. A
// limiter that let two goroutines each add the elapsed refill would break this
// and nothing else in this file would notice.
func TestAllowAtNeverPaysMoreThanTheWindowEarned(t *testing.T) {
	const (
		burst   = 4
		charges = 512
		steps   = 64
		spread  = time.Millisecond
	)
	base := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	l := stream.NewLimiter(64, func() time.Time { return base })
	limit := stream.RateLimit{PerSecond: 100, Burst: burst}

	window := time.Duration(steps-1) * spread
	ceiling := burst + int(window.Seconds()*limit.PerSecond)

	admitted, peak := storm(charges, func(i int) bool {
		offset := time.Duration((i*13)%steps) * spread
		return l.AllowAt("one-key", limit, 1, base.Add(offset))
	})
	assertContended(t, peak, charges)

	if admitted < burst {
		t.Errorf("%d charges admitted, want at least the burst of %d: the bucket starts full",
			admitted, burst)
	}
	if admitted > ceiling {
		t.Errorf("%d charges admitted, want at most %d — the burst plus the %s window at %g/s. "+
			"paying out more than elapsed time earned is refill applied twice",
			admitted, ceiling, window, limit.PerSecond)
	}
}
