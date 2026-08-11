package stream_test

import (
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
