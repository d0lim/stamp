package api_test

// saturation_test.go observes what the audit buffer does when it fills up.
//
// R32 buys a cheap judgment path by making the audit asynchronous, and pays for
// it with a bounded queue that drops when it overflows. `auditwindow_test.go`
// pins the *time* half of that trade — how long the unaudited window is when the
// chain goes away. This file pins the *volume* half: at what point loss begins,
// that the loss is marked in the chain rather than silent, and that an operator
// is told.
//
// Both halves of R32 are asserted here, not just the marker. A gap marker that
// nobody is alerted about is a record of an outage that is discovered during the
// next audit rather than during the outage.
//
// Nothing here waits on a clock. `Run` drives flushes off a ticker, so a test
// that wanted a flush at a chosen moment would have to sleep; instead the
// interval is set past the end of the test and `Flush` is called by hand, which
// is the shape auditwindow_test.go already uses. The threshold that follows is
// therefore stated in events per flush interval — the unit the buffer actually
// decides in — rather than as a wall-clock rate, which would be a number about
// this machine.

import (
	"context"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
)

func saturableBuffer(t *testing.T, writer api.ChainWriter, failClosed bool) *api.AuditBuffer {
	t.Helper()
	b, err := api.NewAuditBuffer(api.AuditConfig{
		Writer:    writer,
		BatchSize: api.DefaultAuditBatchSize,
		// Past the end of the test: every flush below is deliberate.
		FlushInterval: time.Hour,
		FailClosed:    failClosed,
	})
	if err != nil {
		t.Fatalf("build buffer: %v", err)
	}
	return b
}

// TestTheAuditBufferDropsOnlyOnceItIsFull states the threshold.
//
// It is exactly the capacity, per flush interval — not a rate, and not a
// fraction of capacity. An operator sizing STAMP_AUDIT_FLUSH_INTERVAL against
// their traffic needs that number to be the real one, and this is the only place
// it is checked against the code rather than asserted in prose.
func TestTheAuditBufferDropsOnlyOnceItIsFull(t *testing.T) {
	t.Parallel()
	writer := &recordingWriter{}
	buffer := saturableBuffer(t, writer, false)
	ctx := context.Background()

	// Fill it to the brim. Nothing is lost yet: capacity events between two
	// flushes is the most the buffer promises to carry, and it carries them.
	for i := 0; i < api.DefaultAuditCapacity; i++ {
		buffer.Record(ctx, api.Event{Kind: api.EventCheck, CallerID: "svc-payments"})
	}
	if stats := buffer.Stats(); stats.Dropped != 0 {
		t.Fatalf("%d events were dropped at exactly capacity (%d): the buffer holds less than it claims, "+
			"so an operator sizing the flush interval against this number is sizing against the wrong one",
			stats.Dropped, api.DefaultAuditCapacity)
	}

	// One more has nowhere to go.
	buffer.Record(ctx, api.Event{Kind: api.EventCheck, CallerID: "svc-payments"})
	stats := buffer.Stats()
	if stats.Dropped != 1 {
		t.Errorf("dropped = %d after one event past capacity, want 1", stats.Dropped)
	}
	if !stats.Alerting {
		t.Error("the first lost record did not raise the alert: loss is being counted but nobody is told, " +
			"which is the half of R32 that turns an outage into an audit-time discovery")
	}
}

// TestSaturationLeavesAMarkedGapRatherThanASilentHole is the claim R32 actually
// makes. Loss is permitted; unrecorded loss is not.
func TestSaturationLeavesAMarkedGapRatherThanASilentHole(t *testing.T) {
	t.Parallel()
	writer := &recordingWriter{}
	buffer := saturableBuffer(t, writer, false)
	ctx := context.Background()

	const over = 500
	for i := 0; i < api.DefaultAuditCapacity+over; i++ {
		buffer.Record(ctx, api.Event{Kind: api.EventCheck, CallerID: "svc-payments"})
	}
	if err := buffer.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}

	_, gaps := writer.snapshot()
	if len(gaps) != 1 {
		t.Fatalf("the chain carries %d gap markers after a saturating burst, want 1: "+
			"records were lost and the chain does not say so, so verification reports a clean chain "+
			"that quietly skipped them", len(gaps))
	}
	if gaps[0].Dropped != over {
		t.Errorf("the gap marker names %d lost records, want %d: the marker exists but undercounts, "+
			"which is worse than no marker because it looks authoritative", gaps[0].Dropped, over)
	}
	if gaps[0].From.IsZero() || gaps[0].To.IsZero() {
		t.Error("the gap marker carries no window: an auditor can see that records were lost but not when")
	}
}

// TestTheSaturationAlertClearsOnlyAfterTheLossIsRecorded pins the latch.
//
// The comment on Flush says the alert must not clear on the first quiet moment,
// because a buffer saturating every few seconds would flicker the alert instead
// of holding it. That is a behavioural claim with two conditions — the loss
// marked, and the pressure gone — and neither was checked anywhere.
func TestTheSaturationAlertClearsOnlyAfterTheLossIsRecorded(t *testing.T) {
	t.Parallel()
	writer := &recordingWriter{}
	buffer := saturableBuffer(t, writer, false)
	ctx := context.Background()

	for i := 0; i < api.DefaultAuditCapacity+1; i++ {
		buffer.Record(ctx, api.Event{Kind: api.EventCheck, CallerID: "svc-payments"})
	}
	if !buffer.Alerting() {
		t.Fatal("saturation did not raise the alert")
	}

	// One flush writes the gap and drains the queue, so both clearing
	// conditions are met and the alert goes down.
	if err := buffer.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if buffer.Alerting() {
		t.Error("the alert was still up after the loss was marked and the queue drained: " +
			"an alert that never clears is one an operator learns to ignore")
	}
}

// TestSaturationStillAlertsWhileThePressureHolds is the other side of that
// latch, and the one that matters operationally: a buffer that is still full has
// not recovered, whatever the gap marker says.
func TestSaturationStillAlertsWhileThePressureHolds(t *testing.T) {
	t.Parallel()
	writer := &recordingWriter{}
	buffer := saturableBuffer(t, writer, false)
	ctx := context.Background()

	for i := 0; i < api.DefaultAuditCapacity+1; i++ {
		buffer.Record(ctx, api.Event{Kind: api.EventCheck, CallerID: "svc-payments"})
	}
	// The chain is unreachable, so the flush marks nothing and the queue stays
	// where it is.
	writer.failNext.Store(true)
	_ = buffer.Flush(ctx)
	if !buffer.Alerting() {
		t.Error("the alert cleared while the loss was still unrecorded and the buffer still full: " +
			"the operator is told the incident is over during the incident")
	}
}

// TestFailClosedFollowsSaturationNotOnlyChainFailure closes the loop between
// this file and auditwindow_test.go.
//
// FailClosed is documented as "the operator's option to stop judging instead" of
// accepting a marked gap. auditwindow_test.go proves it engages when the chain
// becomes unreachable. Nothing proved it engages under the other way records are
// lost — the buffer overflowing while the chain is perfectly healthy — which is
// the failure mode a traffic spike produces.
func TestFailClosedFollowsSaturationNotOnlyChainFailure(t *testing.T) {
	t.Parallel()
	writer := &recordingWriter{}
	buffer := saturableBuffer(t, writer, true)
	ctx := context.Background()

	if buffer.FailClosed() {
		t.Fatal("the surface refused before anything was lost")
	}
	for i := 0; i < api.DefaultAuditCapacity+1; i++ {
		buffer.Record(ctx, api.Event{Kind: api.EventCheck, CallerID: "svc-payments"})
	}
	if !buffer.FailClosed() {
		t.Error("a deployment that asked to stop judging rather than accept a gap kept judging " +
			"through a saturation loss: STAMP_AUDIT_FAIL_CLOSED covers an unreachable chain but not a " +
			"full buffer, so a traffic spike silently produces the outcome the operator opted out of")
	}
}

// TestTheSaturationBoundIsTheConfiguredCapacity puts the number where a reader
// looking for it will land.
func TestTheSaturationBoundIsTheConfiguredCapacity(t *testing.T) {
	t.Parallel()
	if api.DefaultAuditCapacity != 4096 {
		t.Errorf("DefaultAuditCapacity = %d, want 4096: docs/operations/failure-modes.md names this number",
			api.DefaultAuditCapacity)
	}
	if api.DefaultAuditAlertThreshold != 1 {
		t.Errorf("DefaultAuditAlertThreshold = %d, want 1: the documented promise is that the *first* "+
			"lost record alerts", api.DefaultAuditAlertThreshold)
	}
}
