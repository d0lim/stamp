// Package stream is STAMP's event ingestion plane: the broker-neutral port
// events arrive through, the two v1 adapters behind it (Kafka and HTTP
// ingest), the fixed-width bucket aggregator they feed, and the velocity fact
// source a policy reads the aggregate through.
//
// Four properties hold the package together.
//
// The port names no broker. What crosses it is "an event arrived" and
// "processing is confirmed up to here" — there is no offset, no partition and
// no consumer group anywhere in [Event], [Sink] or [Adapter]. That is not
// tidiness: a port carrying an offset is a port only Kafka can implement, and
// the HTTP ingest adapter, which has no offsets to carry, is the standing
// proof that this one is a seam rather than a Kafka interface with a different
// name. The seam is also what removes the broker from the demo bundle, and
// what lets every aggregation test in this package run with no broker at all.
//
// Idempotency is the core's job, not the adapter's. An adapter promises
// at-least-once and nothing more; deduplication happens in the aggregator,
// keyed by the producer-assigned event identifier and namespaced by the
// caller. Requiring anything stronger from an adapter would rule out every
// broker whose redelivery semantics differ from Kafka's, which is the same as
// having no port. The identifier comes from the producer rather than from the
// broker for the same reason — a broker-assigned identifier is a concept the
// port would have to name.
//
// Every event carries a producer timestamp, and every adapter can be asked for
// its ingestion lag: now minus the producer timestamp of the most recently
// confirmed event, clamped at zero. Freshness judgement depends on that value,
// so an adapter that cannot report it declares as much and a policy that
// declares a freshness limit against it is refused at load rather than
// silently evaluated against an unknown.
//
// The write surfaces are authorized per credential. An ingest credential is
// bound to the (source, metric) pairs it may write, and permission to send a
// deduction is granted separately from permission to write the metric at all —
// because a credential that can add to a subject's total and a credential that
// can subtract from it are two different powers, and only the second one can
// erase evidence of the first.
package stream

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

// Rejection sentinels. Every one of them wraps [ErrRejected], so a caller that
// only needs to know "this event will never be accepted, no matter how often
// it is redelivered" can ask that one question — which is exactly the question
// an at-least-once adapter has to answer to decide between retrying and
// dropping.
var (
	// ErrRejected is the sentinel every permanent event rejection wraps.
	ErrRejected = errors.New("stream: event rejected")

	// ErrNoEventID means the producer assigned no identifier. Deduplication is
	// keyed on it, so an event without one cannot be counted exactly once.
	ErrNoEventID = fmt.Errorf("%w: no producer-assigned event identifier", ErrRejected)
	// ErrNoProducedAt means the producer stamped no time. Ingestion lag is
	// measured from it, so an event without one cannot be judged for freshness.
	ErrNoProducedAt = fmt.Errorf("%w: no producer timestamp", ErrRejected)
	// ErrNoCaller means the event is not attributed to an authenticated caller.
	// The caller namespaces the dedup key; without it an identifier is squattable.
	ErrNoCaller = fmt.Errorf("%w: no caller identifier", ErrRejected)
	// ErrNoMetric means the event names no metric.
	ErrNoMetric = fmt.Errorf("%w: no metric", ErrRejected)
	// ErrNoSubject means the event names no subject to aggregate against.
	ErrNoSubject = fmt.Errorf("%w: no subject identifier", ErrRejected)
	// ErrValueNotFinite means the value is NaN or an infinity.
	ErrValueNotFinite = fmt.Errorf("%w: value is not a finite number", ErrRejected)

	// ErrUnknownMetric means no configured source aggregates that metric.
	ErrUnknownMetric = fmt.Errorf("%w: no configured source aggregates this metric", ErrRejected)
	// ErrDeductionNotAllowed means a negative delta arrived for a metric whose
	// source did not declare deductions.
	ErrDeductionNotAllowed = fmt.Errorf("%w: the source did not declare deduction deltas", ErrRejected)
	// ErrTooOld means the producer timestamp falls outside every declarable
	// window, so the event can no longer affect an answer.
	ErrTooOld = fmt.Errorf("%w: producer timestamp is older than the widest declarable window", ErrRejected)
	// ErrTooFarAhead means the producer timestamp is further into the future
	// than the tolerated clock skew.
	ErrTooFarAhead = fmt.Errorf("%w: producer timestamp is further ahead than the tolerated clock skew", ErrRejected)
	// ErrOutOfScope means the credential is not bound to that (source, metric).
	ErrOutOfScope = fmt.Errorf("%w: the credential is not scoped to this source and metric", ErrRejected)
	// ErrRateLimited means the caller or subject exceeded its ingest rate.
	ErrRateLimited = errors.New("stream: ingest rate limit exceeded")
)

// MaxClockSkew is how far ahead of this deployment's clock a producer
// timestamp may be and still be accepted.
//
// The bound exists because the timestamp is attacker-supplied on both of the
// things it drives. Stamping an event far in the future would park its value
// in a bucket no trailing window reaches — hiding a withdrawal from the limit
// that was supposed to see it — and would simultaneously pin reported lag at
// zero, so a genuinely stalled ingestion path would keep passing its freshness
// limit. Clamping the lag at zero handles an honest clock a little ahead;
// refusing the event handles a dishonest one a long way ahead.
const MaxClockSkew = 5 * time.Minute

// Event is one aggregation event as it crosses the ingestion port.
//
// Everything on it comes from the producer or from the authenticated caller.
// Nothing on it comes from a broker, which is what makes the same struct
// serviceable for a Kafka record and for a line in an HTTP request body.
type Event struct {
	// CallerID is the authenticated caller that delivered the event. It is the
	// namespace half of the dedup key.
	CallerID string
	// EventID is the producer-assigned unique identifier. The producer assigns
	// it, not the broker: a broker-assigned identifier would be a broker
	// concept crossing the port, and it would not survive a replay through a
	// different adapter.
	EventID string
	// Metric names the aggregate the event contributes to.
	Metric string
	// SubjectID names whose aggregate it contributes to.
	SubjectID string
	// Value is the delta. Negative values are deductions and are admitted only
	// where both the source declaration and the credential permit them.
	Value float64
	// ProducedAt is the producer's timestamp. Ingestion lag is measured from
	// it, and it decides which bucket the event lands in.
	ProducedAt time.Time
}

// Validate checks what the port itself requires of every event, whatever
// adapter delivered it.
//
// The producer identifier and the producer timestamp are checked here rather
// than in each adapter, because both are load-bearing for guarantees the core
// makes: an event without an identifier cannot be deduplicated and an event
// without a timestamp cannot be judged for freshness. An adapter that could
// wave either through would be an adapter that can switch off idempotency or
// the freshness limit by delivering a malformed record.
func (e Event) Validate() error {
	switch {
	case e.CallerID == "":
		return ErrNoCaller
	case e.EventID == "":
		return ErrNoEventID
	case e.Metric == "":
		return ErrNoMetric
	case e.SubjectID == "":
		return ErrNoSubject
	case e.ProducedAt.IsZero():
		return ErrNoProducedAt
	case math.IsNaN(e.Value) || math.IsInf(e.Value, 0):
		return ErrValueNotFinite
	}
	return nil
}

// Result reports what one confirmed batch did.
//
// It says how the core disposed of the events and nothing about where they
// came from. An adapter reads it to answer its caller — the HTTP ingest
// adapter puts the counts in its response body — and for nothing else.
type Result struct {
	// Applied is how many events were new and were folded into a bucket.
	Applied int
	// Duplicates is how many were already recorded and were therefore ignored.
	// A non-zero count is normal: at-least-once is what the port asks of an
	// adapter, so redelivery is the expected case rather than an incident.
	Duplicates int
}

// Sink is the core side of the ingestion port.
//
// Accept is the whole boundary. A nil error means processing is confirmed up
// to and including the last event of the batch, and that is the only thing an
// adapter learns — not which rows were written, not what a downstream position
// is, because either would be a concept only some brokers have.
//
// A batch is all-or-nothing. A non-nil error means nothing in it was applied,
// so an adapter may redeliver the whole batch without double counting.
type Sink interface {
	Accept(ctx context.Context, events []Event) (Result, error)
}

// Adapter is one ingestion transport behind the port.
//
// Both v1 adapters implement this and neither shape is privileged: Kafka pulls
// and blocks in Run, HTTP ingest is pushed into from a request handler and its
// Run only waits for shutdown. A port that could not accommodate both would be
// a port describing a consumer loop, which is a broker concept wearing a
// neutral name.
type Adapter interface {
	// Name is the adapter's configured name. A velocity source declaration
	// names the adapter feeding its metric, so this is what the two are joined
	// on.
	Name() string

	// ReportsLag declares, before any event has arrived, whether this adapter
	// can report ingestion lag at all.
	//
	// It is a static property because it is a load-time gate: a policy that
	// declares a freshness limit against a source fed by an adapter that
	// answers false is refused at load, rather than accepted and then
	// evaluated against an unknown at the worst possible moment.
	ReportsLag() bool

	// Lag reports now minus the producer timestamp of the most recently
	// confirmed event, clamped at zero.
	//
	// The second return is false when there is no answer — either because this
	// adapter cannot report lag, or because it has confirmed nothing yet. The
	// two are distinguished by ReportsLag, and both deny a freshness-limited
	// lookup: an unknown lag is not a small lag.
	Lag(now time.Time) (time.Duration, bool)

	// Run delivers events into sink until ctx is cancelled.
	Run(ctx context.Context, sink Sink) error
}

// LagTracker is the shared implementation of the port's lag contract.
//
// Both adapters embed one rather than each keeping its own high-water mark,
// because the definition of lag is a property of the port and not of a
// transport: two adapters that measured it differently would make the same
// freshness limit mean two things depending on how the events happened to
// arrive.
type LagTracker struct {
	mu     sync.Mutex
	newest time.Time
}

// Observe records a confirmed batch.
//
// The mark moves to the newest producer timestamp in the batch and never
// backwards. Out-of-order delivery is normal — a partitioned broker gives no
// global order and a replay is deliberately old — and letting an old replay
// push the mark back would report a freshness incident that is not happening.
func (t *LagTracker) Observe(events []Event) {
	var newest time.Time
	for _, ev := range events {
		if ev.ProducedAt.After(newest) {
			newest = ev.ProducedAt
		}
	}
	if newest.IsZero() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if newest.After(t.newest) {
		t.newest = newest
	}
}

// Lag reports the current ingestion lag, or false when nothing has been
// confirmed yet.
//
// The clamp at zero is the whole reason this is one function rather than a
// subtraction at each call site. A producer whose clock runs ahead of ours
// yields a negative difference, and a negative lag compares as smaller than
// every freshness limit — so an unclamped subtraction would let a clock skew,
// accidental or pushed, satisfy a freshness limit that ingestion was in fact
// failing.
func (t *LagTracker) Lag(now time.Time) (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.newest.IsZero() {
		return 0, false
	}
	lag := now.Sub(t.newest)
	if lag < 0 {
		return 0, true
	}
	return lag, true
}
