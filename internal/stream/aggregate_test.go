package stream_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/store"
	"github.com/d0lim/stamp/internal/stream"
)

// Every test in this file drives aggregation through an in-memory
// implementation of the ingestion port. No broker is started, imported or
// reachable from here — that is the unit's verification gate, and it holds
// only because the port carries no broker concept an in-memory adapter would
// have to fake.

const (
	metricWithdrawal = "withdrawal_amount"
	bucketWidth      = time.Hour
	dayWindow        = 24 * time.Hour
)

func newAggregator(t *testing.T, c *clock, specs ...stream.MetricSpec) *stream.Aggregator {
	t.Helper()
	if len(specs) == 0 {
		specs = []stream.MetricSpec{{Metric: metricWithdrawal, BucketWidth: bucketWidth}}
	}
	agg, err := stream.NewAggregator(stream.AggregatorConfig{
		Store:   openStore(t, c.Now),
		Metrics: specs,
		Now:     c.Now,
	})
	if err != nil {
		t.Fatalf("new aggregator: %v", err)
	}
	return agg
}

func ev(caller, id, subject string, value float64, at time.Time) stream.Event {
	return stream.Event{
		CallerID:   caller,
		EventID:    id,
		Metric:     metricWithdrawal,
		SubjectID:  subject,
		Value:      value,
		ProducedAt: at,
	}
}

func windowSum(t *testing.T, agg *stream.Aggregator, subject string, at time.Time) float64 {
	t.Helper()
	w, err := agg.Window(t.Context(), metricWithdrawal, subject, dayWindow, at)
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	return w.Sum
}

// The trailing sum answers from local state. A limit that the running total is
// just under is not exceeded, and the request that would exceed it is visible
// as such — with the aggregate read out of Postgres and no call leaving the
// process.
func TestWindowSumServesTheLimitCheckLocally(t *testing.T) {
	c := newClock()
	agg := newAggregator(t, c)
	adapter := stream.NewMemoryAdapter("test")

	adapter.Publish(
		ev("caller-a", "e1", "user-1", 400, c.Now().Add(-3*time.Hour)),
		ev("caller-a", "e2", "user-1", 500, c.Now().Add(-90*time.Minute)),
	)
	drain(t, adapter, agg)

	const limit = 1000.0
	if got := windowSum(t, agg, "user-1", c.Now()); got != 900 {
		t.Fatalf("24h sum = %v, want 900", got)
	}
	if sum := windowSum(t, agg, "user-1", c.Now()); sum+200 <= limit {
		t.Errorf("a 200 request on top of %v did not exceed the limit of %v", sum, limit)
	}
	// Another subject's aggregate is untouched.
	if got := windowSum(t, agg, "user-2", c.Now()); got != 0 {
		t.Errorf("unrelated subject sum = %v, want 0", got)
	}
}

// The same event delivered twice is counted once. At-least-once is all the
// port asks of an adapter, so this is the ordinary case rather than an
// anomaly, and the second delivery is reported as a duplicate rather than
// refused.
func TestRedeliveryIsCountedOnce(t *testing.T) {
	c := newClock()
	agg := newAggregator(t, c)

	first, err := agg.Accept(t.Context(), []stream.Event{ev("caller-a", "e1", "user-1", 250, c.Now())})
	if err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if first.Applied != 1 || first.Duplicates != 0 {
		t.Fatalf("first delivery = %+v, want 1 applied", first)
	}

	second, err := agg.Accept(t.Context(), []stream.Event{ev("caller-a", "e1", "user-1", 250, c.Now())})
	if err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if second.Applied != 0 || second.Duplicates != 1 {
		t.Fatalf("redelivery = %+v, want 1 duplicate", second)
	}
	if got := windowSum(t, agg, "user-1", c.Now()); got != 250 {
		t.Errorf("sum after redelivery = %v, want 250", got)
	}
}

// The dedup key is namespaced by caller. One caller claiming another's event
// identifier neither suppresses the other caller's event nor merges the two:
// both are counted, and the squatter's own redelivery is still deduplicated
// within its own namespace.
func TestEventIDSquattingDoesNotSwallowAnotherCallersEvent(t *testing.T) {
	c := newClock()
	agg := newAggregator(t, c)

	// The squatter gets there first with the identifier the honest producer
	// is about to use.
	if _, err := agg.Accept(t.Context(), []stream.Event{ev("caller-evil", "shared-id", "user-1", 10, c.Now())}); err != nil {
		t.Fatalf("squatter event: %v", err)
	}
	res, err := agg.Accept(t.Context(), []stream.Event{ev("caller-honest", "shared-id", "user-1", 700, c.Now())})
	if err != nil {
		t.Fatalf("honest event: %v", err)
	}
	if res.Applied != 1 {
		t.Fatalf("the honest caller's event was swallowed by a squatted identifier: %+v", res)
	}
	if got := windowSum(t, agg, "user-1", c.Now()); got != 710 {
		t.Errorf("sum = %v, want 710 (both callers counted)", got)
	}

	// And the namespace still deduplicates inside itself.
	again, err := agg.Accept(t.Context(), []stream.Event{ev("caller-honest", "shared-id", "user-1", 700, c.Now())})
	if err != nil {
		t.Fatalf("honest redelivery: %v", err)
	}
	if again.Duplicates != 1 {
		t.Errorf("the honest caller's redelivery = %+v, want 1 duplicate", again)
	}
}

// A restart before the adapter confirmed its position replays events that were
// already applied. The final sum is the same as if they had been delivered
// once, which is what makes at-least-once a sufficient adapter promise.
func TestReplayAfterRestartDoesNotDistortTheSum(t *testing.T) {
	c := newClock()
	agg := newAggregator(t, c)
	adapter := stream.NewMemoryAdapter("test")

	adapter.Publish(
		ev("caller-a", "e1", "user-1", 100, c.Now().Add(-2*time.Hour)),
		ev("caller-a", "e2", "user-1", 200, c.Now().Add(-time.Hour)),
		ev("caller-a", "e3", "user-1", 300, c.Now()),
	)
	drain(t, adapter, agg)
	if got := windowSum(t, agg, "user-1", c.Now()); got != 600 {
		t.Fatalf("sum after first pass = %v, want 600", got)
	}

	// The consumer restarts having confirmed nothing, so the broker hands the
	// whole uncommitted range over again.
	adapter.Rewind(3)
	drain(t, adapter, agg)
	if got := windowSum(t, agg, "user-1", c.Now()); got != 600 {
		t.Errorf("sum after replay = %v, want 600", got)
	}
}

// Concurrent ingests each below the limit cannot land a total above it. The
// bucket upsert is an atomic read-modify-write in the database rather than a
// read followed by a write in the process, so there is no window in which two
// senders both see room.
func TestConcurrentIngestSumsExactly(t *testing.T) {
	c := newClock()
	agg := newAggregator(t, c)

	const senders = 16
	var wg sync.WaitGroup
	errs := make(chan error, senders)
	for i := range senders {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "e" + string(rune('a'+i))
			if _, err := agg.Accept(t.Context(), []stream.Event{ev("caller-a", id, "user-1", 100, c.Now())}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent ingest: %v", err)
	}

	if got := windowSum(t, agg, "user-1", c.Now()); got != senders*100 {
		t.Errorf("sum = %v, want %v — concurrent deltas were lost or doubled", got, senders*100)
	}
}

// A negative delta is refused unless the source declared deductions. The
// permission is per metric because a deduction is the one event shape that can
// erase evidence of an earlier one.
func TestDeductionRequiresDeclaration(t *testing.T) {
	c := newClock()
	agg := newAggregator(t, c)

	_, err := agg.Accept(t.Context(), []stream.Event{ev("caller-a", "e1", "user-1", -100, c.Now())})
	if !errors.Is(err, stream.ErrDeductionNotAllowed) {
		t.Fatalf("negative delta on a source without deductions = %v, want ErrDeductionNotAllowed", err)
	}
	if got := windowSum(t, agg, "user-1", c.Now()); got != 0 {
		t.Errorf("sum = %v, want 0 — a refused batch must apply nothing", got)
	}

	allowed := newAggregator(t, c, stream.MetricSpec{
		Metric: metricWithdrawal, BucketWidth: bucketWidth, AllowDeduction: true,
	})
	if _, err := allowed.Accept(t.Context(), []stream.Event{
		ev("caller-a", "e1", "user-1", 500, c.Now()),
		ev("caller-a", "e2", "user-1", -100, c.Now()),
	}); err != nil {
		t.Fatalf("declared deduction: %v", err)
	}
	if got := windowSum(t, allowed, "user-1", c.Now()); got != 400 {
		t.Errorf("sum with a declared deduction = %v, want 400", got)
	}
}

// A window sum that straddles bucket boundaries is exact, and the window's
// precision is the bucket width: the bucket the window's start instant falls
// in is included whole.
func TestWindowSumAcrossBucketBoundaries(t *testing.T) {
	c := newClock()
	agg := newAggregator(t, c)

	// One event per hour for 30 hours, ending now.
	events := make([]stream.Event, 0, 30)
	for i := range 30 {
		events = append(events, ev("caller-a", "e"+time.Duration(i).String(), "user-1", 1,
			c.Now().Add(-time.Duration(i)*time.Hour)))
	}
	if _, err := agg.Accept(t.Context(), events); err != nil {
		t.Fatalf("accept: %v", err)
	}

	// A 24h trailing window over hourly buckets covers the 24 buckets before
	// now plus the whole bucket the start instant falls in: 25.
	w, err := agg.Window(t.Context(), metricWithdrawal, "user-1", dayWindow, c.Now())
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	if w.Sum != 25 || w.Count != 25 {
		t.Errorf("24h window = sum %v count %d, want 25 and 25", w.Sum, w.Count)
	}

	// Shifting the clock by half a bucket does not change which buckets are
	// covered, because bucket width is the declared precision.
	c.Advance(30 * time.Minute)
	shifted, err := agg.Window(t.Context(), metricWithdrawal, "user-1", dayWindow, c.Now())
	if err != nil {
		t.Fatalf("shifted window: %v", err)
	}
	if shifted.Sum != 25 {
		t.Errorf("window after half a bucket = %v, want 25", shifted.Sum)
	}
}

// An event older than the widest declarable window is refused rather than
// counted. Deduplication rows are kept for that window plus slack, so an event
// admitted past the horizon could outlive its own dedup row and be added a
// second time on a later replay.
func TestEventsBeyondTheDedupHorizonAreRefused(t *testing.T) {
	c := newClock()
	agg := newAggregator(t, c)

	old := c.Now().Add(-store.MaxDeclarableWindow - time.Hour)
	_, err := agg.Accept(t.Context(), []stream.Event{ev("caller-a", "e1", "user-1", 100, old)})
	if !errors.Is(err, stream.ErrTooOld) {
		t.Fatalf("event beyond the retention horizon = %v, want ErrTooOld", err)
	}

	// And a producer timestamp far in the future is refused too: it would park
	// the value where no trailing window reaches while pinning reported lag at
	// zero.
	ahead := c.Now().Add(stream.MaxClockSkew + time.Minute)
	if _, err := agg.Accept(t.Context(), []stream.Event{ev("caller-a", "e2", "user-1", 100, ahead)}); !errors.Is(err, stream.ErrTooFarAhead) {
		t.Fatalf("event past the tolerated skew = %v, want ErrTooFarAhead", err)
	}
}

// An event naming a metric no source aggregates is refused. Accepting it would
// write a bucket row nothing ever reads, at a width nothing declared.
func TestUnknownMetricIsRefused(t *testing.T) {
	c := newClock()
	agg := newAggregator(t, c)

	e := ev("caller-a", "e1", "user-1", 100, c.Now())
	e.Metric = "not_declared"
	if _, err := agg.Accept(t.Context(), []stream.Event{e}); !errors.Is(err, stream.ErrUnknownMetric) {
		t.Fatalf("unknown metric = %v, want ErrUnknownMetric", err)
	}
}

// A batch containing one unacceptable event applies none of it. An adapter
// that redelivers the batch must not find half of it already counted.
func TestBatchIsAllOrNothing(t *testing.T) {
	c := newClock()
	agg := newAggregator(t, c)

	bad := ev("caller-a", "", "user-1", 100, c.Now())
	_, err := agg.Accept(t.Context(), []stream.Event{
		ev("caller-a", "e1", "user-1", 100, c.Now()),
		bad,
		ev("caller-a", "e2", "user-1", 100, c.Now()),
	})
	if !errors.Is(err, stream.ErrNoEventID) {
		t.Fatalf("batch with a malformed event = %v, want ErrNoEventID", err)
	}
	if got := windowSum(t, agg, "user-1", c.Now()); got != 0 {
		t.Errorf("sum = %v, want 0 — a refused batch must apply nothing", got)
	}
}

// drain pumps everything the adapter holds into the sink, the way the adapter's
// own Run loop would, and fails the test if the sink refuses.
func drain(t *testing.T, a *stream.MemoryAdapter, sink stream.Sink) {
	t.Helper()
	if err := a.Drain(t.Context(), sink); err != nil {
		t.Fatalf("drain adapter %q: %v", a.Name(), err)
	}
}
