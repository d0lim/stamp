package stream_test

// saturation_test.go observes the rate limiter at the size it actually runs at.
//
// `ingest_test.go` already pins the sweep-or-refuse behaviour, but it does so
// with `MaxRateEntries: 2` — two buckets, one of each kind, which proves the
// branch exists and says nothing about the boundary a deployment meets. The
// real bound is DefaultMaxRateEntries = 8192, and until this file nothing had
// ever driven the table there.
//
// The distinction matters because the refusal is the security-relevant half. An
// authenticated caller derives table keys from request content, so the table is
// the one structure it can grow from outside. What the bound promises is that a
// limiter which cannot record a charge refuses rather than admitting unmetered
// — and a promise about 8192 entries that has only ever been exercised at 2 is
// a promise about a different program.

import (
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/stream"
)

// budgetForSaturation is deliberately slow to refill. A bucket that refills
// within the test would be swept, and the point here is a table that cannot be
// swept: that is the state in which the refusal is the only thing standing
// between a caller and an unmetered request.
var budgetForSaturation = stream.RateLimit{PerSecond: 0.001, Burst: 2}

// TestLimiterRefusesANewKeyAtTheRealTableBound drives the table to
// DefaultMaxRateEntries with buckets that cannot be swept, then asks for one
// more key.
//
// Every charge happens at one fixed instant, so nothing refills and
// sweepLocked can free nothing. That is the worst case and the one worth
// pinning: the bound holds only if the refusal holds when the sweep fails.
func TestLimiterRefusesANewKeyAtTheRealTableBound(t *testing.T) {
	t.Parallel()
	at := time.Unix(1_760_000_000, 0)
	l := stream.NewLimiter(stream.DefaultMaxRateEntries, func() time.Time { return at })

	// Fill the table. Each key is charged once, leaving its bucket below full
	// so the sweep will not reclaim it.
	for i := range stream.DefaultMaxRateEntries {
		if !l.AllowAt(saturationKey(i), budgetForSaturation, 1, at) {
			t.Fatalf("filling the table was refused at entry %d of %d: the table did not reach its bound, "+
				"so this test never observed the boundary it exists for", i, stream.DefaultMaxRateEntries)
		}
	}

	// One more key has nowhere to be recorded and nothing can be freed.
	if l.AllowAt("one-past-the-bound", budgetForSaturation, 1, at) {
		t.Error("a new key was admitted with the table full and nothing sweepable: " +
			"the charge could not be recorded, so the request was served with no limit applied — " +
			"which is exactly what the bound exists to prevent, since table keys derive from request content")
	}

	// A key already in the table is still charged normally: the bound refuses
	// new entries, it does not stop enforcing on the ones it holds.
	if !l.AllowAt(saturationKey(0), budgetForSaturation, 1, at) {
		t.Error("an established key was refused while it still had burst: a full table stopped enforcing " +
			"limits on the callers it was already tracking")
	}
}

// TestLimiterAdmitsAgainOnceTheTableCanBeSwept is the other half. Without it the
// test above passes for a limiter that refuses everything forever once full,
// which would be a denial of service rather than a bound.
func TestLimiterAdmitsAgainOnceTheTableCanBeSwept(t *testing.T) {
	t.Parallel()
	at := time.Unix(1_760_000_000, 0)
	l := stream.NewLimiter(stream.DefaultMaxRateEntries, func() time.Time { return at })
	for i := range stream.DefaultMaxRateEntries {
		l.AllowAt(saturationKey(i), budgetForSaturation, 1, at)
	}
	if l.AllowAt("one-past-the-bound", budgetForSaturation, 1, at) {
		t.Fatal("the table was not saturated")
	}

	// Long enough for every bucket to refill to its burst, which is what makes
	// it sweepable — a full bucket carries no information a new key would not
	// get anyway.
	later := at.Add(time.Hour)
	if !l.AllowAt("one-past-the-bound", budgetForSaturation, 1, later) {
		t.Error("a new key was still refused after every bucket had refilled: the table never recovers, " +
			"so one burst of invented keys would lock out real callers permanently")
	}
}

// TestLimiterBoundIsTheConfiguredMaximum states the number in a place a reader
// will find it. `DefaultMaxRateEntries` appearing in a comment is not the same
// as the table actually holding that many, and this round found more than one
// claim in this repository that its own code did not keep.
func TestLimiterBoundIsTheConfiguredMaximum(t *testing.T) {
	t.Parallel()
	if stream.DefaultMaxRateEntries != 8192 {
		t.Errorf("DefaultMaxRateEntries = %d, want 8192: docs/operations/failure-modes.md names this number",
			stream.DefaultMaxRateEntries)
	}
}

func saturationKey(i int) string {
	// Distinct, cheap, and shaped like the subject identifiers that actually
	// key this table.
	return "subject-" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
