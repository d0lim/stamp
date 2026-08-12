package stream_test

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/stream"
)

const (
	producer = "workload:https://idp.example#producer-1"
	intruder = "workload:https://idp.example#producer-2"
)

// ingestHarness is the whole brokerless path: an HTTP ingest adapter in front
// of the aggregator, with the velocity source reading the buckets behind it.
type ingestHarness struct {
	*sourcesHarness
	ingest *stream.Ingest
}

// newIngestHarness wires the brokerless path in the order a composition root
// does it: declarations, aggregator, adapter, sources. The velocity source is
// declared against the ingest adapter itself, so the freshness limit it can
// carry is judged from the lag that adapter reports.
func newIngestHarness(t *testing.T, creds ...stream.IngestCredential) *ingestHarness {
	t.Helper()
	return newIngestHarnessWith(t, baseDecl(), creds...)
}

func newIngestHarnessWith(t *testing.T, decl stream.Declaration, creds ...stream.IngestCredential) *ingestHarness {
	t.Helper()
	decl.Adapter = "ingest"
	decls := []stream.Declaration{decl}
	c := newClock()

	agg, err := stream.NewAggregator(stream.AggregatorConfig{
		Store: openStore(t, c.Now), Metrics: stream.MetricSpecsFor(decls), Now: c.Now,
	})
	if err != nil {
		t.Fatalf("new aggregator: %v", err)
	}
	if len(creds) == 0 {
		creds = []stream.IngestCredential{{
			CallerID: producer,
			Scope:    []stream.ScopeEntry{{Source: decl.Name, Metric: decl.Metric}},
		}}
	}
	ingest, err := stream.NewIngest(stream.IngestConfig{
		Name:         "ingest",
		Declarations: decls,
		Sink:         agg,
		Now:          c.Now,
		Credentials:  creds,
	})
	if err != nil {
		t.Fatalf("new ingest: %v", err)
	}
	sources, err := stream.NewSources(decls, stream.SourcesConfig{
		Aggregator: agg, Adapters: []stream.Adapter{ingest}, Now: c.Now,
	})
	if err != nil {
		t.Fatalf("new sources: %v", err)
	}
	return &ingestHarness{
		sourcesHarness: &sourcesHarness{sources: sources, agg: agg, clock: c},
		ingest:         ingest,
	}
}

func batch(source string, events ...stream.IngestEvent) stream.IngestBatch {
	return stream.IngestBatch{Source: source, Events: events}
}

// The same aggregate is reachable through the HTTP ingest adapter as through
// any other implementation of the port, and the source reads it the same way.
// This is the brokerless configuration the demo bundle runs.
func TestIngestFeedsTheSameAggregate(t *testing.T) {
	h := newIngestHarness(t)

	res, err := h.ingest.Submit(t.Context(), producer, batch(sourceName,
		stream.IngestEvent{EventID: "e1", Subject: "user-1", Value: 400, ProducedAt: h.clock.Now()},
		stream.IngestEvent{EventID: "e2", Subject: "user-1", Value: 350, ProducedAt: h.clock.Now()},
	))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.Applied != 2 {
		t.Fatalf("submit = %+v, want 2 applied", res)
	}

	v, err := h.sources.Lookup(t.Context(), sourceName, fact.String("user-1"))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if v.Data != 750.0 {
		t.Errorf("lookup = %#v, want 750.0", v.Data)
	}
}

// The two v1 adapters produce the same aggregate from the same events. The
// port is what makes that a property rather than a coincidence: the aggregator
// is not told which adapter delivered a batch, and there is nowhere in [Event]
// for it to find out.
func TestBothAdaptersProduceTheSameAggregate(t *testing.T) {
	h := newIngestHarness(t)
	events := []stream.IngestEvent{
		{EventID: "e1", Subject: "user-1", Value: 120, ProducedAt: h.clock.Now().Add(-3 * time.Hour)},
		{EventID: "e2", Subject: "user-1", Value: 380, ProducedAt: h.clock.Now().Add(-time.Hour)},
		{EventID: "e3", Subject: "user-1", Value: 55, ProducedAt: h.clock.Now()},
	}

	// Through the HTTP ingest adapter.
	if _, err := h.ingest.Submit(t.Context(), producer, batch(sourceName, events...)); err != nil {
		t.Fatalf("submit: %v", err)
	}
	viaIngest, err := h.sources.Lookup(t.Context(), sourceName, fact.String("user-1"))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	// The same events through a different adapter, for a different subject so
	// the two aggregates are independent.
	other := newSources(t, baseDecl(), stream.NewMemoryAdapter("ingest"))
	for _, in := range events {
		other.adapter.Publish(ev(producer, in.EventID, "user-2", in.Value, in.ProducedAt))
	}
	drain(t, other.adapter, other.agg)
	viaPort, err := other.sources.Lookup(t.Context(), sourceName, fact.String("user-2"))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if viaIngest.Data != viaPort.Data {
		t.Errorf("the two adapters disagree: ingest %#v, port fake %#v", viaIngest.Data, viaPort.Data)
	}
	if viaIngest.Data != 555.0 {
		t.Errorf("aggregate = %#v, want 555.0", viaIngest.Data)
	}
}

// A resent ingest batch is counted once, exactly as a broker redelivery is.
func TestIngestRedeliveryIsCountedOnce(t *testing.T) {
	h := newIngestHarness(t)
	b := batch(sourceName, stream.IngestEvent{
		EventID: "e1", Subject: "user-1", Value: 900, ProducedAt: h.clock.Now(),
	})

	if _, err := h.ingest.Submit(t.Context(), producer, b); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	res, err := h.ingest.Submit(t.Context(), producer, b)
	if err != nil {
		t.Fatalf("resubmit: %v", err)
	}
	if res.Duplicates != 1 || res.Applied != 0 {
		t.Fatalf("resubmit = %+v, want 1 duplicate", res)
	}
	v, _ := h.sources.Lookup(t.Context(), sourceName, fact.String("user-1"))
	if v.Data != 900.0 {
		t.Errorf("aggregate after redelivery = %#v, want 900.0", v.Data)
	}
}

// One caller claiming another caller's event identifier does not suppress that
// caller's event. Both are ingested and both are counted.
func TestSquattedEventIDAcrossCredentialsIsNotSwallowed(t *testing.T) {
	scope := []stream.ScopeEntry{{Source: sourceName, Metric: metricWithdrawal}}
	h := newIngestHarness(t,
		stream.IngestCredential{CallerID: producer, Scope: scope},
		stream.IngestCredential{CallerID: intruder, Scope: scope},
	)

	if _, err := h.ingest.Submit(t.Context(), intruder, batch(sourceName, stream.IngestEvent{
		EventID: "settlement-42", Subject: "user-1", Value: 1, ProducedAt: h.clock.Now(),
	})); err != nil {
		t.Fatalf("intruder submit: %v", err)
	}
	res, err := h.ingest.Submit(t.Context(), producer, batch(sourceName, stream.IngestEvent{
		EventID: "settlement-42", Subject: "user-1", Value: 800, ProducedAt: h.clock.Now(),
	}))
	if err != nil {
		t.Fatalf("producer submit: %v", err)
	}
	if res.Applied != 1 {
		t.Fatalf("the producer's event was swallowed by a squatted identifier: %+v", res)
	}
	v, _ := h.sources.Lookup(t.Context(), sourceName, fact.String("user-1"))
	if v.Data != 801.0 {
		t.Errorf("aggregate = %#v, want 801.0 (both callers counted)", v.Data)
	}
}

// A credential may write only the (source, metric) pairs it is bound to, and a
// caller with no grant at all writes nothing.
func TestIngestScopeIsEnforced(t *testing.T) {
	h := newIngestHarness(t)

	_, err := h.ingest.Submit(t.Context(), intruder, batch(sourceName, stream.IngestEvent{
		EventID: "e1", Subject: "user-1", Value: 100, ProducedAt: h.clock.Now(),
	}))
	if !errors.Is(err, stream.ErrNoIngestGrant) {
		t.Errorf("submit by an ungranted caller = %v, want ErrNoIngestGrant", err)
	}

	_, err = h.ingest.Submit(t.Context(), producer, batch("some_other_source", stream.IngestEvent{
		EventID: "e1", Subject: "user-1", Value: 100, ProducedAt: h.clock.Now(),
	}))
	if !errors.Is(err, stream.ErrUnknownSource) {
		t.Errorf("submit to an unknown source = %v, want ErrUnknownSource", err)
	}

	// A credential scoped to a source it may not write is refused at the pair,
	// not at the caller.
	narrow := newIngestHarness(t, stream.IngestCredential{
		CallerID: producer,
		Scope:    []stream.ScopeEntry{{Source: sourceName, Metric: metricWithdrawal}},
	})
	if _, err := narrow.ingest.Submit(t.Context(), producer, batch(sourceName, stream.IngestEvent{
		EventID: "e1", Subject: "user-1", Value: 100, ProducedAt: narrow.clock.Now(),
	})); err != nil {
		t.Fatalf("in-scope submit: %v", err)
	}
	if got := len(h.ingest.Scopes(producer)); got != 1 {
		t.Errorf("Scopes(producer) has %d entries, want 1", got)
	}
	if got := h.ingest.Scopes(intruder); got != nil {
		t.Errorf("Scopes(intruder) = %v, want nil", got)
	}
}

// A scope entry naming a source this deployment does not serve, or naming the
// wrong metric for one it does, is refused when the adapter is built.
func TestIngestScopeIsCheckedAtLoad(t *testing.T) {
	h := newSources(t, baseDecl(), stream.NewMemoryAdapter("ingest"))

	for _, tc := range []struct {
		name  string
		scope []stream.ScopeEntry
	}{
		{"unknown source", []stream.ScopeEntry{{Source: "nowhere", Metric: metricWithdrawal}}},
		{"wrong metric", []stream.ScopeEntry{{Source: sourceName, Metric: "other_metric"}}},
		{"empty scope", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := stream.NewIngest(stream.IngestConfig{
				Name: "ingest", Declarations: []stream.Declaration{baseDecl()}, Sink: h.agg,
				Credentials: []stream.IngestCredential{{CallerID: producer, Scope: tc.scope}},
			})
			if err == nil {
				t.Fatal("a misconfigured credential scope was accepted")
			}
		})
	}
}

// Permission to send a deduction is granted per credential and separately from
// permission to write the metric.
func TestDeductionNeedsBothTheSourceAndTheCredential(t *testing.T) {
	// The source declares deductions; the credential does not.
	decl := baseDecl()
	decl.AllowDeduction = true
	scope := []stream.ScopeEntry{{Source: sourceName, Metric: metricWithdrawal}}

	refuser := newIngestHarnessWith(t, decl, stream.IngestCredential{
		CallerID: producer, Scope: scope, AllowDeduction: false,
	})
	if _, err := refuser.ingest.Submit(t.Context(), producer, batch(sourceName, stream.IngestEvent{
		EventID: "d1", Subject: "user-1", Value: -50, ProducedAt: refuser.clock.Now(),
	})); !errors.Is(err, stream.ErrDeductionNotPermitted) {
		t.Fatalf("deduction without the credential permission = %v, want ErrDeductionNotPermitted", err)
	}

	permitted := newIngestHarnessWith(t, decl, stream.IngestCredential{
		CallerID: producer, Scope: scope, AllowDeduction: true,
	})
	if _, err := permitted.ingest.Submit(t.Context(), producer, batch(sourceName,
		stream.IngestEvent{EventID: "a1", Subject: "user-1", Value: 300, ProducedAt: permitted.clock.Now()},
		stream.IngestEvent{EventID: "d1", Subject: "user-1", Value: -50, ProducedAt: permitted.clock.Now()},
	)); err != nil {
		t.Fatalf("permitted deduction: %v", err)
	}
	v, err := permitted.sources.Lookup(t.Context(), sourceName, fact.String("user-1"))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if v.Data != 250.0 {
		t.Errorf("aggregate = %#v, want 250.0", v.Data)
	}
}

// AE27: a velocity source fed by HTTP ingest denies once the producer
// timestamp of the last ingested event falls outside its freshness limit. The
// judgement is the Kafka path's judgement — the source reads a lag, not an
// adapter.
func TestIngestStalenessDeniesTheLookup(t *testing.T) {
	decl := baseDecl()
	decl.Freshness = 30 * time.Minute
	h := newIngestHarnessWith(t, decl)

	if _, err := h.ingest.Submit(t.Context(), producer, batch(sourceName, stream.IngestEvent{
		EventID: "e1", Subject: "user-1", Value: 700, ProducedAt: h.clock.Now().Add(-5 * time.Minute),
	})); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if _, err := h.sources.Lookup(t.Context(), sourceName, fact.String("user-1")); err != nil {
		t.Fatalf("lookup inside the freshness limit: %v", err)
	}

	// Ingestion stops. The last producer timestamp ages past the limit and the
	// lookup denies rather than answering with the total it happens to hold.
	h.clock.Advance(time.Hour)
	_, err := h.sources.Lookup(t.Context(), sourceName, fact.String("user-1"))
	var failure *fact.Failure
	if !errors.As(err, &failure) || failure.Reason != stream.ReasonStale {
		t.Fatalf("lookup after ingestion stalled = %v, want a %s failure", err, stream.ReasonStale)
	}
	if !failure.FailsClosed() {
		t.Error("a stale velocity source must fail closed")
	}
}

// The subject rate limit bites before the caller's overall budget is spent, so
// a credential with a generous allowance still cannot pour it all into one
// subject.
func TestIngestRateLimits(t *testing.T) {
	h := newIngestHarness(t, stream.IngestCredential{
		CallerID:    producer,
		Scope:       []stream.ScopeEntry{{Source: sourceName, Metric: metricWithdrawal}},
		Rate:        stream.RateLimit{PerSecond: 100, Burst: 100},
		SubjectRate: stream.RateLimit{PerSecond: 2, Burst: 2},
	})

	send := func(id, subject string) error {
		_, err := h.ingest.Submit(t.Context(), producer, batch(sourceName, stream.IngestEvent{
			EventID: id, Subject: subject, Value: 1, ProducedAt: h.clock.Now(),
		}))
		return err
	}

	if err := send("e1", "user-1"); err != nil {
		t.Fatalf("first event: %v", err)
	}
	if err := send("e2", "user-1"); err != nil {
		t.Fatalf("second event: %v", err)
	}
	if err := send("e3", "user-1"); !errors.Is(err, stream.ErrRateLimited) {
		t.Fatalf("third event for the same subject = %v, want ErrRateLimited", err)
	}
	// Another subject has its own budget.
	if err := send("e4", "user-2"); err != nil {
		t.Errorf("first event for a second subject: %v", err)
	}
	// And the budget refills.
	h.clock.Advance(time.Second)
	if err := send("e5", "user-1"); err != nil {
		t.Errorf("event after the bucket refilled: %v", err)
	}

	// The refused events were never applied.
	v, _ := h.sources.Lookup(t.Context(), sourceName, fact.String("user-1"))
	if v.Data != 3.0 {
		t.Errorf("aggregate = %#v, want 3.0 — a rate-limited event must not be applied", v.Data)
	}
}

// A caller-level flood is refused too, and one caller's budget is not another
// caller's.
func TestIngestCallerRateLimitIsPerCredential(t *testing.T) {
	scope := []stream.ScopeEntry{{Source: sourceName, Metric: metricWithdrawal}}
	rate := stream.RateLimit{PerSecond: 2, Burst: 2}
	h := newIngestHarness(t,
		stream.IngestCredential{CallerID: producer, Scope: scope, Rate: rate},
		stream.IngestCredential{CallerID: intruder, Scope: scope, Rate: rate},
	)

	send := func(caller, id string) error {
		_, err := h.ingest.Submit(t.Context(), caller, batch(sourceName, stream.IngestEvent{
			EventID: id, Subject: "user-1", Value: 1, ProducedAt: h.clock.Now(),
		}))
		return err
	}
	if err := send(producer, "e1"); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := send(producer, "e2"); err != nil {
		t.Fatalf("second: %v", err)
	}
	if err := send(producer, "e3"); !errors.Is(err, stream.ErrRateLimited) {
		t.Fatalf("third = %v, want ErrRateLimited", err)
	}
	if err := send(intruder, "e1"); err != nil {
		t.Errorf("a second caller was charged the first caller's budget: %v", err)
	}
}

// The rate limiter's table is bounded and refuses rather than growing. Its
// keys include the subject identifier, which is request-derived, so an
// unbounded table would let an authenticated caller grow the process's memory
// by inventing subjects — and a limiter that cannot record a charge has not
// applied a limit, so the safe answer when it is full is no.
func TestIngestRateLimiterTableIsBounded(t *testing.T) {
	decl := baseDecl()
	decl.Adapter = "ingest"
	decls := []stream.Declaration{decl}
	c := newClock()
	agg, err := stream.NewAggregator(stream.AggregatorConfig{
		Store: openStore(t, c.Now), Metrics: stream.MetricSpecsFor(decls), Now: c.Now,
	})
	if err != nil {
		t.Fatalf("new aggregator: %v", err)
	}
	ingest, err := stream.NewIngest(stream.IngestConfig{
		Name: "ingest", Declarations: decls, Sink: agg, Now: c.Now,
		MaxRateEntries: 2,
		Credentials: []stream.IngestCredential{{
			CallerID:    producer,
			Scope:       []stream.ScopeEntry{{Source: sourceName, Metric: metricWithdrawal}},
			Rate:        stream.RateLimit{PerSecond: 1000, Burst: 1000},
			SubjectRate: stream.RateLimit{PerSecond: 1000, Burst: 1000},
		}},
	})
	if err != nil {
		t.Fatalf("new ingest: %v", err)
	}

	// The first event fills the table: one bucket for the caller, one for the
	// subject. A second subject has nowhere to be recorded, and no bucket has
	// refilled, so it is refused rather than admitted unmetered.
	if _, err := ingest.Submit(t.Context(), producer, batch(sourceName, stream.IngestEvent{
		EventID: "e1", Subject: "user-1", Value: 1, ProducedAt: c.Now(),
	})); err != nil {
		t.Fatalf("first subject: %v", err)
	}
	if _, err := ingest.Submit(t.Context(), producer, batch(sourceName, stream.IngestEvent{
		EventID: "e2", Subject: "user-2", Value: 1, ProducedAt: c.Now(),
	})); !errors.Is(err, stream.ErrRateLimited) {
		t.Fatalf("a second subject with the table full = %v, want ErrRateLimited", err)
	}

	// Once the buckets have refilled, the sweep frees one and the new subject
	// is admitted again.
	c.Advance(2 * time.Second)
	if _, err := ingest.Submit(t.Context(), producer, batch(sourceName, stream.IngestEvent{
		EventID: "e3", Subject: "user-2", Value: 1, ProducedAt: c.Now(),
	})); err != nil {
		t.Errorf("a second subject after the buckets refilled: %v", err)
	}
}

// The port's own refusals reach an ingest caller unchanged: an event with no
// producer identifier or no producer timestamp is refused whichever adapter
// carries it.
func TestIngestRefusesEventsMissingProducerFields(t *testing.T) {
	h := newIngestHarness(t)

	_, err := h.ingest.Submit(t.Context(), producer, batch(sourceName, stream.IngestEvent{
		Subject: "user-1", Value: 100, ProducedAt: h.clock.Now(),
	}))
	if !errors.Is(err, stream.ErrNoEventID) {
		t.Errorf("event with no identifier = %v, want ErrNoEventID", err)
	}

	_, err = h.ingest.Submit(t.Context(), producer, batch(sourceName, stream.IngestEvent{
		EventID: "e1", Subject: "user-1", Value: 100,
	}))
	if !errors.Is(err, stream.ErrNoProducedAt) {
		t.Errorf("event with no producer timestamp = %v, want ErrNoProducedAt", err)
	}
}

// A batch larger than the cap is refused whole. The batch is one transaction,
// so the cap bounds how long one request can hold a connection.
func TestIngestBatchCap(t *testing.T) {
	h := newIngestHarness(t)
	events := make([]stream.IngestEvent, stream.DefaultMaxBatchEvents+1)
	for i := range events {
		events[i] = stream.IngestEvent{
			EventID: "e" + time.Duration(i).String(), Subject: "user-1", Value: 1, ProducedAt: h.clock.Now(),
		}
	}
	if _, err := h.ingest.Submit(t.Context(), producer, batch(sourceName, events...)); !errors.Is(err, stream.ErrBatchTooLarge) {
		t.Fatalf("oversized batch = %v, want ErrBatchTooLarge", err)
	}
}

// The ingest adapter reports lag from the producer timestamps it accepted, so
// a freshness limit judges the HTTP path exactly as it judges the Kafka one.
func TestIngestReportsLagFromProducerTimestamps(t *testing.T) {
	h := newIngestHarness(t)
	if !h.ingest.ReportsLag() {
		t.Fatal("the ingest adapter declares it cannot report lag")
	}
	if _, ok := h.ingest.Lag(h.clock.Now()); ok {
		t.Error("lag was reported before anything was ingested")
	}

	if _, err := h.ingest.Submit(t.Context(), producer, batch(sourceName, stream.IngestEvent{
		EventID: "e1", Subject: "user-1", Value: 100, ProducedAt: h.clock.Now().Add(-4 * time.Minute),
	})); err != nil {
		t.Fatalf("submit: %v", err)
	}
	lag, ok := h.ingest.Lag(h.clock.Now())
	if !ok || lag != 4*time.Minute {
		t.Errorf("lag = %s (reported %v), want 4m", lag, ok)
	}
}

// TestIngestRateLimitHoldsWhenSubmitsArriveTogether is R43 at the ingest
// adapter, asserted where the budget's exactness stops being about a counter.
//
// The limiter's own concurrency is pinned in ratelimit_test.go. What this adds
// is the consequence: an event the budget refused must not reach the aggregate.
// A limit that leaks by one under contention leaks one event into a velocity
// metric, and a velocity metric is what a policy then judges on — so the failure
// does not stay inside the limiter, it becomes a decision made on a number that
// was supposed to be bounded.
//
// The clock does not move for the length of the storm, so nothing here can be
// explained by refill. Both key namespaces of the one table are charged by every
// submit — the caller's, deliberately generous, and the subject's, which is the
// one that binds — so the table is being written under contention on two keys
// at once, which is the shape the ingest path actually runs in.
func TestIngestRateLimitHoldsWhenSubmitsArriveTogether(t *testing.T) {
	const (
		burst    = 8
		inFlight = 96
	)
	h := newIngestHarness(t, stream.IngestCredential{
		CallerID:    producer,
		Scope:       []stream.ScopeEntry{{Source: sourceName, Metric: metricWithdrawal}},
		Rate:        stream.RateLimit{PerSecond: 1e6, Burst: 1e6},
		SubjectRate: stream.RateLimit{PerSecond: 1000, Burst: burst},
	})

	var refused atomic.Int64
	accepted, peak := storm(inFlight, func(i int) bool {
		_, err := h.ingest.Submit(t.Context(), producer, batch(sourceName, stream.IngestEvent{
			EventID:    fmt.Sprintf("e%d", i),
			Subject:    "user-1",
			Value:      1,
			ProducedAt: h.clock.Now(),
		}))
		switch {
		case err == nil:
			return true
		case errors.Is(err, stream.ErrRateLimited):
			refused.Add(1)
			return false
		default:
			t.Errorf("submit %d = %v, want either acceptance or ErrRateLimited", i, err)
			return false
		}
	})
	assertContended(t, peak, inFlight)

	if accepted != burst {
		t.Fatalf("%d of %d simultaneous submits were accepted against a burst of %d, want exactly %d",
			accepted, inFlight, burst, burst)
	}
	if got := int(refused.Load()); got != inFlight-burst {
		t.Errorf("%d submits were refused, want %d", got, inFlight-burst)
	}

	// And the aggregate is the accepted count and nothing else. This is the
	// assertion the whole test exists for: the budget is not a number the
	// adapter reports, it is a bound on what a policy will later read.
	v, err := h.sources.Lookup(t.Context(), sourceName, fact.String("user-1"))
	if err != nil {
		t.Fatalf("look the aggregate up: %v", err)
	}
	if v.Data != float64(burst) {
		t.Errorf("the aggregate is %#v after %d simultaneous submits against a burst of %d, want %d: "+
			"an event the limit refused was applied anyway", v.Data, inFlight, burst, burst)
	}
}
