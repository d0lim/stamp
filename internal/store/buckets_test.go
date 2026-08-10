package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/store"
)

func TestDedupIsKeyedOnTheCaller(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	now := s.Now()

	ev := store.BucketEvent{
		CallerID: "adapter-a", EventID: "evt-1", Metric: "transfers",
		SubjectID: "u1", Value: 100, At: now, Width: time.Minute,
	}
	applied, err := s.RecordEvent(ctx, ev)
	if err != nil || !applied {
		t.Fatalf("first delivery: applied=%v err=%v", applied, err)
	}

	// At-least-once delivery means the same event arrives again.
	applied, err = s.RecordEvent(ctx, ev)
	if err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if applied {
		t.Fatal("a redelivered event was counted twice")
	}

	// A different caller using the same identifier must not be suppressed. If
	// the key were event_id alone, one caller could burn another's identifiers
	// by claiming them first.
	other := ev
	other.CallerID = "adapter-b"
	applied, err = s.RecordEvent(ctx, other)
	if err != nil {
		t.Fatalf("second caller: %v", err)
	}
	if !applied {
		t.Fatal("a second caller's event was swallowed by the first caller's identifier")
	}

	win, err := s.Window(ctx, "u1", "transfers", time.Minute, now.Add(-time.Minute), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	if win.Count != 2 || win.Sum != 200 {
		t.Fatalf("window = %d events summing %v, want 2 summing 200", win.Count, win.Sum)
	}
}

func TestBucketsAreFixedWidth(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)

	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	for i, at := range []time.Time{
		base.Add(5 * time.Second),
		base.Add(59 * time.Second),
		base.Add(61 * time.Second),
	} {
		if _, err := s.RecordEvent(ctx, store.BucketEvent{
			CallerID: "a", EventID: string(rune('a' + i)), Metric: "transfers",
			SubjectID: "u1", Value: 1, At: at, Width: time.Minute,
		}); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	var buckets int
	if err := s.Pool().QueryRow(ctx,
		`SELECT count(*) FROM velocity_buckets WHERE subject_id = 'u1'`).Scan(&buckets); err != nil {
		t.Fatalf("count buckets: %v", err)
	}
	if buckets != 2 {
		t.Fatalf("three events across a minute boundary produced %d buckets, want 2", buckets)
	}

	firstMinute, err := s.Window(ctx, "u1", "transfers", time.Minute, base, base.Add(time.Minute))
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	if firstMinute.Count != 2 {
		t.Fatalf("first minute has %d events, want 2", firstMinute.Count)
	}
}

func TestDedupRetentionCoversTheWidestDeclarableWindow(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	now := s.Now()

	// Retention shorter than the widest window a policy can declare would let a
	// redelivery inside that window be counted twice, so it is refused.
	if _, err := s.PruneProcessedEvents(ctx, time.Hour, now); err == nil {
		t.Fatal("a retention shorter than the maximum declarable window was accepted")
	}

	old := now.Add(-store.DefaultDedupRetention() - time.Hour)
	if _, err := s.RecordEvent(ctx, store.BucketEvent{
		CallerID: "a", EventID: "stale", Metric: "transfers",
		SubjectID: "u1", Value: 1, At: old, Width: time.Minute,
	}); err != nil {
		t.Fatalf("record stale event: %v", err)
	}
	if _, err := s.RecordEvent(ctx, store.BucketEvent{
		CallerID: "a", EventID: "fresh", Metric: "transfers",
		SubjectID: "u1", Value: 1, At: now, Width: time.Minute,
	}); err != nil {
		t.Fatalf("record fresh event: %v", err)
	}

	removed, err := s.PruneProcessedEvents(ctx, store.DefaultDedupRetention(), now)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 1 {
		t.Fatalf("pruned %d rows, want 1", removed)
	}

	var remaining string
	if err := s.Pool().QueryRow(ctx, `SELECT event_id FROM processed_events`).Scan(&remaining); err != nil {
		t.Fatalf("read remaining: %v", err)
	}
	if remaining != "fresh" {
		t.Fatalf("kept %q, want the fresh event", remaining)
	}
}

func TestBucketWidthIsBounded(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	for _, width := range []time.Duration{0, -time.Minute, store.MaxDeclarableWindow + time.Hour} {
		if _, err := s.RecordEvent(ctx, store.BucketEvent{
			CallerID: "a", EventID: "e", Metric: "m", SubjectID: "u1", Width: width,
		}); err == nil {
			t.Errorf("bucket width %s was accepted", width)
		}
	}
}

func TestDedupKeyRequiresEveryComponent(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	for _, ev := range []store.BucketEvent{
		{EventID: "e", Metric: "m", SubjectID: "u", Width: time.Minute},
		{CallerID: "c", Metric: "m", SubjectID: "u", Width: time.Minute},
		{CallerID: "c", EventID: "e", SubjectID: "u", Width: time.Minute},
	} {
		if _, err := s.RecordEvent(ctx, ev); err == nil {
			t.Errorf("event %+v was accepted with an incomplete dedup key", ev)
		}
	}
}
