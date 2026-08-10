package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/store"
)

// Event is one auditable thing the check surface did: a judgment, or an
// authentication attempt that never became one.
//
// Both kinds go through the same buffer because both are answers R40 and R32
// require the audit to contain — a surface that recorded its judgments but not
// its refusals could not show that it refused anything.
type Event struct {
	// Kind is EventCheck or EventAuth.
	Kind string `json:"kind"`
	// Time is when the event happened.
	Time time.Time `json:"time"`
	// CallerID is the authenticated caller, or "anonymous".
	CallerID string `json:"caller_id"`
	// Action, Subject and Resource identify the request. Subject and Resource
	// are rendered as "type:id".
	Action   string `json:"action,omitempty"`
	Subject  string `json:"subject,omitempty"`
	Resource string `json:"resource,omitempty"`
	// Decision and Reason are the verdict, for a check event.
	Decision string `json:"decision,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// PolicyID and Revision pin the judgment to what produced it.
	PolicyID string `json:"policy_id,omitempty"`
	Revision string `json:"revision,omitempty"`
	// Method and Path locate an authentication attempt.
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	// Allowed is whether an authentication attempt was let through.
	Allowed bool `json:"allowed,omitempty"`
}

// The event kinds the check surface produces.
const (
	// EventCheck is one check-path judgment.
	EventCheck = "check"
	// EventAuth is one authentication attempt at a served surface.
	EventAuth = "auth"
)

// Leaf renders the event as the Merkle leaf its batch is rooted over.
//
// It is exported because a batch row records only a root: without a way to
// recompute a leaf, an auditor holding the events could not check them against
// the chain, and "the chain contains what we think it contains" would be a
// belief rather than a check. The encoding is the struct's field order, fixed
// by the type rather than by map iteration, so two processes hashing the same
// event agree.
func (e Event) Leaf() []byte {
	data, err := json.Marshal(e)
	if err != nil {
		// A struct of scalars cannot fail to marshal; if it somehow did, a
		// hash of the error text still keeps the leaf count honest.
		data = []byte(err.Error())
	}
	sum := sha256.Sum256(data)
	return sum[:]
}

// ChainWriter is the slice of the audit chain the check surface uses.
//
// It is an interface rather than *store.AuditWriter so that the surface can be
// tested without a database, and so that the check path's dependency on the
// store is visibly two calls wide: a batch root, and a marker for what the
// batch lost.
type ChainWriter interface {
	// AppendCheckBatch appends one batched Merkle root.
	AppendCheckBatch(ctx context.Context, b store.CheckBatch) (store.AuditRecord, error)
	// AppendCheckGap appends one loss marker.
	AppendCheckGap(ctx context.Context, g store.CheckGap) (store.AuditRecord, error)
}

// Defaults for the buffer knobs an operator does not set.
const (
	// DefaultAuditCapacity bounds how many events may be waiting to be
	// chained. The bound is the point: an unbounded queue turns an audit
	// outage into a memory exhaustion outage.
	DefaultAuditCapacity = 4096
	// DefaultAuditBatchSize is how many events one chain row summarizes.
	DefaultAuditBatchSize = 256
	// DefaultAuditFlushInterval bounds how long an event waits before it is
	// chained, when the batch does not fill.
	DefaultAuditFlushInterval = time.Second
	// DefaultAuditAlertThreshold is how many lost events raise the alert.
	// One is deliberate: the first silently dropped audit record is already
	// the condition an operator wants to hear about.
	DefaultAuditAlertThreshold = 1
	// AuditDigestScheme labels the leaf digest construction in the chain row,
	// so a later reader knows how to recompute a root.
	AuditDigestScheme = "sha256-json-v1"
)

// AuditConfig configures an [AuditBuffer].
type AuditConfig struct {
	// Writer appends batch roots and loss markers. Required.
	Writer ChainWriter
	// Capacity bounds the queue. Zero selects DefaultAuditCapacity.
	Capacity int
	// BatchSize is the maximum events per chain row. Zero selects
	// DefaultAuditBatchSize.
	BatchSize int
	// FlushInterval is how often [AuditBuffer.Run] flushes. Zero selects
	// DefaultAuditFlushInterval.
	FlushInterval time.Duration
	// AlertThreshold is the number of lost events that raises the alert. Zero
	// selects DefaultAuditAlertThreshold.
	AlertThreshold int64
	// OnAlert is called once each time the alert is raised. It must not block.
	OnAlert func(AuditStats)
	// FailClosed makes the check surface deny while the alert is up. It is the
	// operator's choice between a gap in the audit and an outage, and R32
	// requires it to be a choice rather than a default.
	FailClosed bool
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// AuditStats is a snapshot of the buffer's counters.
type AuditStats struct {
	// Enqueued, Dropped and Flushed count events accepted, lost, and written
	// into the chain.
	Enqueued int64 `json:"enqueued"`
	Dropped  int64 `json:"dropped"`
	Flushed  int64 `json:"flushed"`
	// Batches and Gaps count chain rows of each kind.
	Batches int64 `json:"batches"`
	Gaps    int64 `json:"gaps"`
	// Queued is the current depth.
	Queued int `json:"queued"`
	// Capacity is the queue bound.
	Capacity int `json:"capacity"`
	// Alerting reports whether losses have crossed the threshold and have not
	// yet been recorded and drained.
	Alerting bool `json:"alerting"`
	// FailClosed reports whether the surface is currently denying because of
	// the alert.
	FailClosed bool `json:"fail_closed"`
	// LastFlush is when a chain row was last written.
	LastFlush time.Time `json:"last_flush"`
	// LastError is the most recent chain write failure.
	LastError string `json:"last_error,omitempty"`
}

// AuditBuffer is the asynchronous, bounded path from the check surface to the
// audit chain.
//
// It is asynchronous because the check path is the latency path: R32 already
// decided that check audit is batched into one chain row per batch rather than
// one row per request, and a synchronous append would put the chain's inherent
// serialization on every judgment.
//
// It is bounded because the alternative to bounded loss is unbounded memory.
// What it refuses to do is lose anything silently: every event either becomes a
// leaf of a batch root or is counted into a gap marker that names the window
// and the number of records missing from it, so chain verification reports a
// hole instead of a clean chain that quietly skipped a minute of traffic. The
// loss counter and the alert threshold are the operator's warning that this is
// happening, and FailClosed is their option to stop judging instead.
type AuditBuffer struct {
	writer    ChainWriter
	capacity  int
	batchSize int
	interval  time.Duration
	threshold int64
	onAlert   func(AuditStats)
	failClose bool
	now       func() time.Time

	mu       sync.Mutex
	queue    []Event
	enqueued int64
	dropped  int64
	flushed  int64
	batches  int64
	gaps     int64
	alerting bool
	lastErr  string
	lastFlsh time.Time

	// pending tracks the loss window that has not yet been marked in the
	// chain: how many records were lost, and between which two instants.
	pendingLost int64
	lostFrom    time.Time
	lostTo      time.Time
}

// NewAuditBuffer builds a buffer.
func NewAuditBuffer(cfg AuditConfig) (*AuditBuffer, error) {
	if cfg.Writer == nil {
		return nil, errors.New("api: audit buffer requires a chain writer")
	}
	b := &AuditBuffer{
		writer:    cfg.Writer,
		capacity:  cfg.Capacity,
		batchSize: cfg.BatchSize,
		interval:  cfg.FlushInterval,
		threshold: cfg.AlertThreshold,
		onAlert:   cfg.OnAlert,
		failClose: cfg.FailClosed,
		now:       cfg.Now,
	}
	if b.capacity <= 0 {
		b.capacity = DefaultAuditCapacity
	}
	if b.batchSize <= 0 {
		b.batchSize = DefaultAuditBatchSize
	}
	if b.interval <= 0 {
		b.interval = DefaultAuditFlushInterval
	}
	if b.threshold <= 0 {
		b.threshold = DefaultAuditAlertThreshold
	}
	if b.now == nil {
		b.now = time.Now
	}
	return b, nil
}

// Record enqueues an event. It never blocks and never fails: a full queue
// drops the event and counts it, which is the loss the gap marker will
// describe.
func (b *AuditBuffer) Record(_ context.Context, e Event) {
	if e.Time.IsZero() {
		e.Time = b.now()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.queue) >= b.capacity {
		b.dropLocked(e.Time, 1)
		return
	}
	b.queue = append(b.queue, e)
	b.enqueued++
}

// RecordAuth implements [identity.AuditSink].
//
// The middleware calls this on the request path, before the handler runs, so
// the only correct implementation is one that cannot block. Enqueuing is that
// implementation; the chain write happens on the flusher.
func (b *AuditBuffer) RecordAuth(ctx context.Context, rec identity.AuthRecord) {
	b.Record(ctx, Event{
		Kind:     EventAuth,
		Time:     rec.Time,
		CallerID: rec.CallerID,
		Reason:   rec.Reason,
		Method:   rec.HTTPMethod,
		Path:     rec.Path,
		Allowed:  rec.Allowed,
	})
}

// dropLocked counts a loss and widens the window the next gap marker covers.
func (b *AuditBuffer) dropLocked(at time.Time, n int64) {
	if at.IsZero() {
		at = b.now()
	}
	b.dropped += n
	b.pendingLost += n
	if b.lostFrom.IsZero() || at.Before(b.lostFrom) {
		b.lostFrom = at
	}
	if at.After(b.lostTo) {
		b.lostTo = at
	}
	if !b.alerting && b.dropped >= b.threshold {
		b.alerting = true
		if b.onAlert != nil {
			b.onAlert(b.statsLocked())
		}
	}
}

// Flush writes everything queued into the chain, and marks anything lost.
//
// The gap marker is written before the batch it precedes, so that a reader
// walking the chain sees the hole where it happened rather than after the
// records that survived it.
func (b *AuditBuffer) Flush(ctx context.Context) error {
	b.mu.Lock()
	batch := b.queue
	b.queue = nil
	lost, from, to := b.pendingLost, b.lostFrom, b.lostTo
	b.pendingLost, b.lostFrom, b.lostTo = 0, time.Time{}, time.Time{}
	b.mu.Unlock()

	var errs []error
	if lost > 0 {
		if _, err := b.writer.AppendCheckGap(ctx, store.CheckGap{
			From:    from,
			To:      to,
			Dropped: lost,
			Reason:  "audit buffer saturated",
		}); err != nil {
			errs = append(errs, fmt.Errorf("api: append audit gap: %w", err))
			b.mu.Lock()
			// The marker itself was lost. Put the window back so the next
			// flush tries again rather than letting the hole become invisible.
			b.pendingLost += lost
			if b.lostFrom.IsZero() || from.Before(b.lostFrom) {
				b.lostFrom = from
			}
			if to.After(b.lostTo) {
				b.lostTo = to
			}
			b.lastErr = err.Error()
			b.mu.Unlock()
		} else {
			b.mu.Lock()
			b.gaps++
			b.lastFlsh = b.now()
			b.mu.Unlock()
		}
	}

	for start := 0; start < len(batch); start += b.batchSize {
		end := min(start+b.batchSize, len(batch))
		chunk := batch[start:end]
		leaves := make([][]byte, len(chunk))
		for i, e := range chunk {
			leaves[i] = e.Leaf()
		}
		_, err := b.writer.AppendCheckBatch(ctx, store.CheckBatch{
			From:   chunk[0].Time,
			To:     chunk[len(chunk)-1].Time,
			Count:  len(chunk),
			Root:   store.MerkleRoot(leaves),
			Digest: AuditDigestScheme,
		})
		b.mu.Lock()
		if err != nil {
			// A batch that could not be chained is lost exactly as a dropped
			// event is, and is accounted for the same way.
			b.dropLocked(chunk[len(chunk)-1].Time, int64(len(chunk)))
			b.lastErr = err.Error()
			errs = append(errs, fmt.Errorf("api: append audit batch: %w", err))
		} else {
			b.batches++
			b.flushed += int64(len(chunk))
			b.lastFlsh = b.now()
			b.lastErr = ""
		}
		b.mu.Unlock()
	}

	b.mu.Lock()
	// The alert clears only once the loss is recorded in the chain and the
	// pressure that caused it is gone. Clearing it on the first quiet moment
	// would hide a buffer that is saturating every few seconds.
	if b.alerting && b.pendingLost == 0 && len(b.queue) <= b.capacity/2 {
		b.alerting = false
	}
	b.mu.Unlock()

	return errors.Join(errs...)
}

// Run flushes on an interval until the context is cancelled, then flushes once
// more so that a clean shutdown does not manufacture a gap.
func (b *AuditBuffer) Run(ctx context.Context) error {
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return b.Flush(context.WithoutCancel(ctx))
		case <-ticker.C:
			_ = b.Flush(ctx)
		}
	}
}

// FailClosed reports whether the surface must deny.
//
// It is true only when the operator asked for it and the buffer is actually
// alerting; a deployment that did not ask keeps judging and accepts a marked
// gap in its audit instead.
func (b *AuditBuffer) FailClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failClose && b.alerting
}

// Alerting reports whether losses have crossed the threshold.
func (b *AuditBuffer) Alerting() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.alerting
}

// Stats returns a snapshot of the counters.
func (b *AuditBuffer) Stats() AuditStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.statsLocked()
}

func (b *AuditBuffer) statsLocked() AuditStats {
	return AuditStats{
		Enqueued:   b.enqueued,
		Dropped:    b.dropped,
		Flushed:    b.flushed,
		Batches:    b.batches,
		Gaps:       b.gaps,
		Queued:     len(b.queue),
		Capacity:   b.capacity,
		Alerting:   b.alerting,
		FailClosed: b.failClose && b.alerting,
		LastFlush:  b.lastFlsh,
		LastError:  b.lastErr,
	}
}

var (
	_ identity.AuditSink = (*AuditBuffer)(nil)
	_ ChainWriter        = (*store.AuditWriter)(nil)
)
