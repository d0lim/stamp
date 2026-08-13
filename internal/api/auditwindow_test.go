package api_test

// auditwindow_test.go pins the size of the window `STAMP_AUDIT_FAIL_CLOSED`
// does not cover.
//
// The switch is on by default and its name reads as "no allow is served that is
// not in the audit chain". That is not what it does, and the difference was
// measured rather than argued: the buffer is asynchronous by R32's deliberate
// choice, so the surface finds out the chain is unreachable only when a flush
// fails, and every judgment between the chain going away and that failed flush
// is served and then dropped. internal/runtime's failure test measured 2 to 56
// such allows over 6 to 48ms at a 50ms flush interval.
//
// That window is a property of the trade, not a bug in it, and this round chose
// to describe it rather than to reverse R32 by appending synchronously on the
// check path. Describing it is only worth anything if the description stays
// true, so the tests here fix the one number the description depends on: **the
// window is one flush interval**. If detection ever comes to need two flushes,
// or a retry, or a consecutive-failure threshold, the window doubles or worse
// while every document about it keeps saying "about a second" — and these tests
// go red instead.

import (
	"context"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
)

// TestFailClosedEngagesOnTheFirstFailedFlush is the structural half, and it is
// the one that actually pins the window. It contains no timing at all: it
// drives exactly one flush and requires that one to be enough.
//
// The window's size is (time until the flusher next runs) × (flushes needed to
// detect). The first factor is the operator's, set by
// STAMP_AUDIT_FLUSH_INTERVAL. The second is this repository's, and this test is
// what holds it at one.
func TestFailClosedEngagesOnTheFirstFailedFlush(t *testing.T) {
	t.Parallel()
	writer := &recordingWriter{}
	buffer, err := api.NewAuditBuffer(api.AuditConfig{
		Writer:     writer,
		BatchSize:  16,
		FailClosed: true,
		// The interval is irrelevant here: Run is never started, and Flush is
		// called by hand so that "one flush" is a fact of the test rather than
		// an inference from a clock.
		FlushInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("build buffer: %v", err)
	}
	ctx := context.Background()

	// Before anything has failed the surface judges. A buffer that failed
	// closed on nothing would pass the assertion below for the wrong reason.
	buffer.Record(ctx, api.Event{Kind: api.EventCheck, CallerID: "svc-payments"})
	if buffer.FailClosed() {
		t.Fatal("the surface refused before any flush had failed: the window this test measures " +
			"would not exist and neither would the trade it comes from")
	}

	// The chain goes away. Nothing tells the buffer; it has to find out.
	writer.failNext.Store(true)
	if err := buffer.Flush(ctx); err == nil {
		t.Fatal("a flush against an unreachable chain reported success")
	}
	if !buffer.FailClosed() {
		t.Fatal("the surface was still judging after one failed flush: detection now costs more " +
			"than one flush, so the unaudited window is longer than STAMP_AUDIT_FLUSH_INTERVAL " +
			"and every document that says otherwise — README, docs/operations/failure-modes.md, " +
			"the comment on api.AuditConfig.FailClosed — is now wrong")
	}

	// And the window is not silent. The records served inside it are counted
	// and become a gap marker naming how many were lost, which is the whole of
	// what R32 asks for in exchange for the asynchrony.
	if stats := buffer.Stats(); !stats.Alerting || stats.Dropped == 0 {
		t.Errorf("stats after the failed flush = alerting:%v dropped:%d, want a counted loss",
			stats.Alerting, stats.Dropped)
	}
	writer.failNext.Store(false)
	if err := buffer.Flush(ctx); err != nil {
		t.Fatalf("flush after the chain came back: %v", err)
	}
	_, gaps := writer.snapshot()
	if len(gaps) == 0 {
		t.Fatal("the loss left no gap marker in the chain: an unaudited window that is invisible " +
			"is the failure the marker exists to prevent")
	}
	if gaps[0].Dropped == 0 {
		t.Errorf("the gap marker counts %d lost records", gaps[0].Dropped)
	}
}

// TestTheUnauditedWindowIsBoundedByTheFlushInterval is the timed half: it runs
// the flusher the deployment runs and measures how long the surface keeps
// judging after the chain becomes unreachable.
//
// Two intervals are measured because the claim in the documentation is a
// proportionality — "the bound is the flush interval, so with the shipped
// default of one second it is about a second of allows" — and a single
// measurement cannot tell a bound that scales from a constant that happens to
// fit. Neither is the shipped one second: a test that waited that long twice
// would be paying seconds of suite time to re-measure a linearity the first two
// points already establish.
func TestTheUnauditedWindowIsBoundedByTheFlushInterval(t *testing.T) {
	t.Parallel()
	for _, interval := range []time.Duration{200 * time.Millisecond, 400 * time.Millisecond} {
		t.Run(interval.String(), func(t *testing.T) {
			t.Parallel()
			writer := &recordingWriter{}
			// Unreachable from the start, so the clock below measures the
			// buffer's detection and not the moment a test flipped a flag.
			writer.failNext.Store(true)
			buffer, err := api.NewAuditBuffer(api.AuditConfig{
				Writer:        writer,
				BatchSize:     16,
				FailClosed:    true,
				FlushInterval: interval,
			})
			if err != nil {
				t.Fatalf("build buffer: %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- buffer.Run(ctx) }()

			// The window opens at the first judgment that needed chaining. A
			// buffer with nothing in it has nothing to fail on, which is the
			// same reason internal/runtime's failure test drains the buffer
			// before it kills the database.
			start := time.Now()
			buffer.Record(ctx, api.Event{Kind: api.EventCheck, CallerID: "svc-payments"})

			// One flush interval is the mechanism's answer. The allowance on
			// top is scheduling: the ticker fires up to one full interval after
			// the record, and the goroutine that services it has to be
			// scheduled. Half an interval is enough slack for a loaded CI
			// machine and is still less than the second flush a regression
			// would need, so detection that came to cost two flushes fails here
			// rather than quietly doubling the window.
			bound := interval + interval/2
			deadline := time.Now().Add(bound)
			for !buffer.FailClosed() {
				if time.Now().After(deadline) {
					t.Fatalf("the surface was still judging %s after the chain became unreachable, "+
						"with a %s flush interval: the unaudited window is bounded by one flush, "+
						"and a window that has grown past it invalidates what README and "+
						"docs/operations/failure-modes.md tell an operator to expect",
						time.Since(start).Round(time.Millisecond), interval)
				}
				time.Sleep(time.Millisecond)
			}
			t.Logf("the surface began refusing %s after the chain became unreachable, "+
				"with a %s flush interval", time.Since(start).Round(time.Millisecond), interval)

			cancel()
			<-done
		})
	}
}
