package stream

// aggregate.go is the core side of the ingestion port: the thing that turns
// "an event arrived" into a fixed-width bucket in Postgres, and that owns
// idempotency on behalf of every adapter.
//
// Three things here are load-bearing.
//
// The dedup insert and the bucket upsert are one transaction. Split them and a
// replay finds one of the two already written, which is a double count in one
// direction and a lost event in the other — and a replay is not an edge case,
// it is what at-least-once means.
//
// Validation happens before anything is written and covers the whole batch. A
// batch is all-or-nothing so that an adapter which did not get its
// confirmation can redeliver the whole thing; a partially applied batch would
// make redelivery unsafe and would put the burden of exactly-once back on the
// adapter, which is precisely what the port refuses to ask for.
//
// Events outside the answerable time range are refused rather than counted.
// Too old, and the event could outlive its own dedup row and be added again by
// a later replay. Too far ahead, and its value sits in a bucket no trailing
// window reaches while its timestamp pins reported lag at zero — a producer
// timestamp is attacker-supplied, and both of those are ways to spend money
// the limit was supposed to see.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/d0lim/stamp/internal/store"
)

// MetricSpec is how one metric is aggregated.
//
// It is derived from the velocity source declarations rather than configured
// separately: the bucket width is the precision a policy declared its window
// at, and the deduction permission is the one the source declared. Two
// declarations naming the same metric must agree on both, which
// [NewAggregator] and [NewSources] each check.
type MetricSpec struct {
	// Metric is the aggregate's name.
	Metric string
	// BucketWidth is the fixed bucket width, and therefore the precision of
	// every window declared over this metric.
	BucketWidth time.Duration
	// AllowDeduction admits negative deltas. Without it a negative event is
	// refused at the port.
	AllowDeduction bool
}

// AggregatorConfig configures an [Aggregator].
type AggregatorConfig struct {
	// Store is the bucket substrate. Required.
	Store *store.Store
	// Metrics are the metrics this deployment aggregates. An event naming any
	// other metric is refused.
	Metrics []MetricSpec
	// Now overrides the clock. Nil means time.Now.
	Now func() time.Time
}

// Aggregator folds events into fixed-width buckets and answers trailing-window
// sums over them.
//
// It implements [Sink], which is the whole of what an adapter sees.
type Aggregator struct {
	store   *store.Store
	metrics map[string]MetricSpec
	now     func() time.Time
}

var _ Sink = (*Aggregator)(nil)

// NewAggregator builds an aggregator over the given metrics.
func NewAggregator(cfg AggregatorConfig) (*Aggregator, error) {
	if cfg.Store == nil {
		return nil, errors.New("stream: the aggregator requires a store")
	}
	if len(cfg.Metrics) == 0 {
		return nil, errors.New("stream: the aggregator was configured with no metrics")
	}
	a := &Aggregator{
		store:   cfg.Store,
		metrics: make(map[string]MetricSpec, len(cfg.Metrics)),
		now:     cfg.Now,
	}
	if a.now == nil {
		a.now = time.Now
	}
	for _, spec := range cfg.Metrics {
		if spec.Metric == "" {
			return nil, errors.New("stream: a metric spec has no metric name")
		}
		if spec.BucketWidth <= 0 {
			return nil, fmt.Errorf("stream: metric %q has bucket width %s, which must be positive",
				spec.Metric, spec.BucketWidth)
		}
		if spec.BucketWidth > store.MaxDeclarableWindow {
			return nil, fmt.Errorf("stream: metric %q has bucket width %s, wider than the maximum declarable window %s",
				spec.Metric, spec.BucketWidth, store.MaxDeclarableWindow)
		}
		// Two specs for one metric must agree. They write the same bucket rows,
		// so disagreeing widths would silently split the metric in two and
		// disagreeing deduction permissions would make the stricter one
		// decorative.
		if existing, dup := a.metrics[spec.Metric]; dup {
			if existing != spec {
				return nil, fmt.Errorf("stream: metric %q is configured twice with different settings (%+v and %+v)",
					spec.Metric, existing, spec)
			}
			continue
		}
		a.metrics[spec.Metric] = spec
	}
	return a, nil
}

// Metrics returns the configured specs, sorted by metric name.
func (a *Aggregator) Metrics() []MetricSpec {
	out := make([]MetricSpec, 0, len(a.metrics))
	for _, spec := range a.metrics {
		out = append(out, spec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Metric < out[j].Metric })
	return out
}

// Spec returns the spec for one metric.
func (a *Aggregator) Spec(metric string) (MetricSpec, bool) {
	spec, ok := a.metrics[metric]
	return spec, ok
}

// Accept implements [Sink].
//
// Every event is checked before any of them is written, and the writes then
// happen in one transaction. A non-nil error therefore means nothing was
// applied and the whole batch may be redelivered.
func (a *Aggregator) Accept(ctx context.Context, events []Event) (Result, error) {
	if len(events) == 0 {
		return Result{}, nil
	}
	now := a.now()
	buckets := make([]store.BucketEvent, len(events))
	for i, e := range events {
		spec, err := a.check(e, now)
		if err != nil {
			return Result{}, fmt.Errorf("stream: event %d (%s/%s): %w", i, e.CallerID, e.EventID, err)
		}
		buckets[i] = store.BucketEvent{
			CallerID:  e.CallerID,
			EventID:   e.EventID,
			Metric:    e.Metric,
			SubjectID: e.SubjectID,
			Value:     e.Value,
			At:        e.ProducedAt,
			Width:     spec.BucketWidth,
		}
	}

	var res Result
	err := a.store.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// Counters are reset inside the closure because pgx retries nothing but
		// a caller might; a partially incremented Result from an aborted
		// attempt would over-report.
		res = Result{}
		for _, b := range buckets {
			applied, err := store.RecordEventTx(ctx, tx, b)
			if err != nil {
				return err
			}
			if applied {
				res.Applied++
			} else {
				res.Duplicates++
			}
		}
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("stream: apply batch: %w", err)
	}
	return res, nil
}

// check validates one event against the port's rules and this deployment's
// metric configuration.
func (a *Aggregator) check(e Event, now time.Time) (MetricSpec, error) {
	if err := e.Validate(); err != nil {
		return MetricSpec{}, err
	}
	spec, ok := a.metrics[e.Metric]
	if !ok {
		return MetricSpec{}, fmt.Errorf("%w: %q", ErrUnknownMetric, e.Metric)
	}
	if e.Value < 0 && !spec.AllowDeduction {
		return MetricSpec{}, fmt.Errorf("%w: metric %q", ErrDeductionNotAllowed, e.Metric)
	}
	// The horizon is the widest declarable window, not the dedup retention,
	// and the difference is the point. Retention is that window plus slack, so
	// refusing here guarantees no accepted event can outlive the dedup row
	// that keeps its replay from being counted twice.
	if e.ProducedAt.Before(now.Add(-store.MaxDeclarableWindow)) {
		return MetricSpec{}, fmt.Errorf("%w: produced at %s, horizon is %s",
			ErrTooOld, e.ProducedAt.UTC().Format(time.RFC3339), now.Add(-store.MaxDeclarableWindow).UTC().Format(time.RFC3339))
	}
	if e.ProducedAt.After(now.Add(MaxClockSkew)) {
		return MetricSpec{}, fmt.Errorf("%w: produced at %s, tolerance is %s",
			ErrTooFarAhead, e.ProducedAt.UTC().Format(time.RFC3339), MaxClockSkew)
	}
	return spec, nil
}

// Window sums the trailing window ending at now.
//
// The window is [now-window, now+MaxClockSkew), snapped down to the bucket the
// start instant falls in. Two things about those bounds are deliberate. The
// start is snapped because the bucket width *is* the declared precision — the
// alternative would be to pretend to a resolution the storage does not have.
// The end reaches over the tolerated clock skew because an event admitted a
// little ahead of our clock must still be counted; excluding it would let a
// producer stamp one second into the future to hide a withdrawal from the very
// window it belongs to.
func (a *Aggregator) Window(ctx context.Context, metric, subject string, window time.Duration, now time.Time) (store.BucketWindow, error) {
	spec, ok := a.metrics[metric]
	if !ok {
		return store.BucketWindow{}, fmt.Errorf("%w: %q", ErrUnknownMetric, metric)
	}
	if window <= 0 {
		return store.BucketWindow{}, fmt.Errorf("stream: window %s must be positive", window)
	}
	if window > store.MaxDeclarableWindow {
		return store.BucketWindow{}, fmt.Errorf("stream: window %s exceeds the maximum declarable window %s",
			window, store.MaxDeclarableWindow)
	}
	return a.store.Window(ctx, subject, metric, spec.BucketWidth,
		now.Add(-window), now.Add(MaxClockSkew))
}
