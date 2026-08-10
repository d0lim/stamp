package stream_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
	"github.com/d0lim/stamp/internal/stream"
)

const sourceName = "daily_withdrawal_total"

func baseDecl() stream.Declaration {
	return stream.Declaration{
		Name:        sourceName,
		Metric:      metricWithdrawal,
		Adapter:     "ingest",
		Window:      dayWindow,
		BucketWidth: bucketWidth,
		Params:      []policy.Param{{Name: "subject", Type: policy.TypeString}},
		Returns:     policy.TypeDouble,
	}
}

type sourcesHarness struct {
	sources *stream.Sources
	agg     *stream.Aggregator
	adapter *stream.MemoryAdapter
	clock   *clock
}

func newSources(t *testing.T, decl stream.Declaration, adapter *stream.MemoryAdapter) *sourcesHarness {
	t.Helper()
	c := newClock()
	specs := []stream.MetricSpec{{
		Metric: decl.Metric, BucketWidth: decl.BucketWidth, AllowDeduction: decl.AllowDeduction,
	}}
	agg, err := stream.NewAggregator(stream.AggregatorConfig{
		Store: openStore(t, c.Now), Metrics: specs, Now: c.Now,
	})
	if err != nil {
		t.Fatalf("new aggregator: %v", err)
	}
	sources, err := stream.NewSources([]stream.Declaration{decl}, stream.SourcesConfig{
		Aggregator: agg,
		Adapters:   []stream.Adapter{adapter},
		Now:        c.Now,
	})
	if err != nil {
		t.Fatalf("new sources: %v", err)
	}
	return &sourcesHarness{sources: sources, agg: agg, adapter: adapter, clock: c}
}

// A policy that declares a freshness limit against a source whose adapter
// cannot report ingestion lag is refused at load. The alternative is a limit
// that is evaluated against an unknown, which reads as "fresh" exactly when
// ingestion is broken.
func TestFreshnessLimitAgainstALagBlindAdapterIsRefusedAtLoad(t *testing.T) {
	blind := stream.NewMemoryAdapter("bridge", stream.WithoutLagReporting())
	agg := newAggregator(t, newClock())

	decl := baseDecl()
	decl.Adapter = "bridge"
	decl.Freshness = 10 * time.Minute

	_, err := stream.NewSources([]stream.Declaration{decl}, stream.SourcesConfig{
		Aggregator: agg, Adapters: []stream.Adapter{blind},
	})
	if err == nil {
		t.Fatal("a freshness limit against a lag-blind adapter loaded successfully")
	}
	if !errors.Is(err, fact.ErrLoad) {
		t.Errorf("load error = %v, want it to wrap fact.ErrLoad", err)
	}

	// Without the freshness limit the same source loads: the refusal is about
	// the limit, not about the adapter.
	decl.Freshness = 0
	if _, err := stream.NewSources([]stream.Declaration{decl}, stream.SourcesConfig{
		Aggregator: agg, Adapters: []stream.Adapter{blind},
	}); err != nil {
		t.Errorf("a lag-blind adapter with no freshness limit was refused: %v", err)
	}
}

// A window wider than the dedup retention can cover is refused at load. Past
// that horizon the dedup row is gone, so a replay would be added a second time
// inside a window that still reaches it.
func TestWindowBeyondDedupRetentionIsRefusedAtLoad(t *testing.T) {
	agg := newAggregator(t, newClock())
	decl := baseDecl()
	decl.Window = store.MaxDeclarableWindow + time.Hour

	_, err := stream.NewSources([]stream.Declaration{decl}, stream.SourcesConfig{
		Aggregator: agg, Adapters: []stream.Adapter{stream.NewMemoryAdapter("ingest")},
	})
	if !errors.Is(err, fact.ErrLoad) {
		t.Fatalf("window wider than retention loaded with error %v, want a load rejection", err)
	}
}

// The other load-time refusals, each of which would otherwise become a
// runtime surprise.
func TestSourceLoadRefusals(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*stream.Declaration)
	}{
		{"unknown adapter", func(d *stream.Declaration) { d.Adapter = "nowhere" }},
		{"no adapter", func(d *stream.Declaration) { d.Adapter = "" }},
		{"no metric", func(d *stream.Declaration) { d.Metric = "" }},
		{"metric the aggregator does not fold", func(d *stream.Declaration) { d.Metric = "other" }},
		{"zero window", func(d *stream.Declaration) { d.Window = 0 }},
		{"window narrower than a bucket", func(d *stream.Declaration) { d.Window = time.Minute }},
		{"window not a multiple of the bucket width", func(d *stream.Declaration) { d.Window = 90 * time.Minute }},
		{"bucket width disagreeing with the aggregator", func(d *stream.Declaration) { d.BucketWidth = 2 * time.Hour }},
		{"fail-open", func(d *stream.Declaration) { d.OnError = policy.OnErrorAllow }},
		{"no parameters", func(d *stream.Declaration) { d.Params = nil }},
		{"non-string subject parameter", func(d *stream.Declaration) {
			d.Params = []policy.Param{{Name: "subject", Type: policy.TypeInt}}
		}},
		{"return type that is not a number", func(d *stream.Declaration) { d.Returns = policy.TypeString }},
	}
	agg := newAggregator(t, newClock())
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decl := baseDecl()
			tc.mut(&decl)
			_, err := stream.NewSources([]stream.Declaration{decl}, stream.SourcesConfig{
				Aggregator: agg, Adapters: []stream.Adapter{stream.NewMemoryAdapter("ingest")},
			})
			if !errors.Is(err, fact.ErrLoad) {
				t.Fatalf("load error = %v, want a rejection wrapping fact.ErrLoad", err)
			}
		})
	}
}

// A lookup answers from the local buckets, and the answer is the trailing
// window sum.
func TestLookupAnswersFromLocalBuckets(t *testing.T) {
	h := newSources(t, baseDecl(), stream.NewMemoryAdapter("ingest"))

	h.adapter.Publish(
		ev("caller-a", "e1", "user-1", 400, h.clock.Now().Add(-2*time.Hour)),
		ev("caller-a", "e2", "user-1", 350, h.clock.Now()),
	)
	drain(t, h.adapter, h.agg)

	v, err := h.sources.Lookup(t.Context(), sourceName, fact.String("user-1"))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got, ok := v.Data.(float64); !ok || got != 750 {
		t.Errorf("lookup = %#v, want the float64 750", v.Data)
	}
}

// A source declared to return an int answers with the event count rather than
// the value sum.
func TestLookupCanReturnTheEventCount(t *testing.T) {
	decl := baseDecl()
	decl.Returns = policy.TypeInt
	h := newSources(t, decl, stream.NewMemoryAdapter("ingest"))

	h.adapter.Publish(
		ev("caller-a", "e1", "user-1", 400, h.clock.Now()),
		ev("caller-a", "e2", "user-1", 350, h.clock.Now()),
	)
	drain(t, h.adapter, h.agg)

	v, err := h.sources.Lookup(t.Context(), sourceName, fact.String("user-1"))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got, ok := v.Data.(int64); !ok || got != 2 {
		t.Errorf("lookup = %#v, want the int64 2", v.Data)
	}
}

// Ingestion lag past the declared freshness limit denies the lookup, and the
// lag is measured from the producer timestamp of the last processed event
// rather than from when it happened to be stored.
func TestStaleIngestionDeniesTheLookup(t *testing.T) {
	decl := baseDecl()
	decl.Freshness = 30 * time.Minute
	h := newSources(t, decl, stream.NewMemoryAdapter("ingest"))

	// Nothing has been ingested at all: the lag is unknown, which is not the
	// same as small.
	_, err := h.sources.Lookup(t.Context(), sourceName, fact.String("user-1"))
	var failure *fact.Failure
	if !errors.As(err, &failure) || failure.Reason != stream.ReasonLagUnknown {
		t.Fatalf("lookup with no ingestion yet = %v, want a %s failure", err, stream.ReasonLagUnknown)
	}
	if !failure.FailsClosed() {
		t.Error("a freshness failure must fail closed")
	}

	// An event produced 10 minutes ago leaves the source inside its limit.
	h.adapter.Publish(ev("caller-a", "e1", "user-1", 100, h.clock.Now().Add(-10*time.Minute)))
	drain(t, h.adapter, h.agg)
	if _, err := h.sources.Lookup(t.Context(), sourceName, fact.String("user-1")); err != nil {
		t.Fatalf("lookup within the freshness limit: %v", err)
	}

	// Time passes with nothing arriving. The last producer timestamp is now
	// well past the limit.
	h.clock.Advance(time.Hour)
	_, err = h.sources.Lookup(t.Context(), sourceName, fact.String("user-1"))
	if !errors.As(err, &failure) || failure.Reason != stream.ReasonStale {
		t.Fatalf("lookup with stale ingestion = %v, want a %s failure", err, stream.ReasonStale)
	}
}

// A producer clock running ahead of ours does not manufacture freshness: the
// lag clamps at zero, so the source is judged fresh rather than negatively
// stale, and the clamp is what stops a pushed clock from being usable to
// pretend a stalled path is healthy for longer than the tolerated skew.
func TestFreshnessUsesTheClampedProducerLag(t *testing.T) {
	decl := baseDecl()
	decl.Freshness = 30 * time.Minute
	h := newSources(t, decl, stream.NewMemoryAdapter("ingest"))

	h.adapter.Publish(ev("caller-a", "e1", "user-1", 100, h.clock.Now().Add(stream.MaxClockSkew)))
	drain(t, h.adapter, h.agg)

	lag, ok := h.sources.Lag(sourceName, h.clock.Now())
	if !ok {
		t.Fatal("the source reported no lag after an event was ingested")
	}
	if lag != 0 {
		t.Errorf("lag = %s for a producer timestamp ahead of us, want it clamped to 0", lag)
	}
	if _, err := h.sources.Lookup(t.Context(), sourceName, fact.String("user-1")); err != nil {
		t.Errorf("lookup with a clamped lag: %v", err)
	}
}

// The resolver answers the batch the evaluator hands it, and passes calls it
// does not own to the synchronous fact plane behind it.
func TestResolveSourcesDelegatesUnknownCalls(t *testing.T) {
	h := newSources(t, baseDecl(), stream.NewMemoryAdapter("ingest"))
	h.adapter.Publish(ev("caller-a", "e1", "user-1", 120, h.clock.Now()))
	drain(t, h.adapter, h.agg)

	fallback := &recordingResolver{answers: map[string]any{"allowlist": []any{"a"}}}
	sources, err := stream.NewSources([]stream.Declaration{baseDecl()}, stream.SourcesConfig{
		Aggregator: h.agg, Adapters: []stream.Adapter{h.adapter}, Now: h.clock.Now, Fallback: fallback,
	})
	if err != nil {
		t.Fatalf("new sources: %v", err)
	}

	velocity := engine.SourceCall{Name: sourceName, Args: []any{"user-1"}}
	other := engine.SourceCall{Name: "allowlist", Args: nil}
	facts, err := sources.ResolveSources(t.Context(), []engine.SourceCall{velocity, other})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got, _ := facts.Value(velocity); got != 120.0 {
		t.Errorf("velocity fact = %#v, want 120.0", got)
	}
	if _, ok := facts.Value(other); !ok {
		t.Error("the delegated call is missing from the merged fact table")
	}
	if len(fallback.seen) != 1 || fallback.seen[0].Name != "allowlist" {
		t.Errorf("the fallback saw %+v, want only the call this resolver does not own", fallback.seen)
	}
}

// A schema declaring an event source this deployment does not configure is
// refused, and one whose signature disagrees with the configured source is
// refused too.
func TestVerifySchema(t *testing.T) {
	h := newSources(t, baseDecl(), stream.NewMemoryAdapter("ingest"))

	good := &policy.Schema{Sources: []policy.SourceDecl{{
		Name: sourceName, Kind: policy.SourceEvent,
		Params:  []policy.Param{{Name: "subject", Type: policy.TypeString}},
		Returns: policy.TypeDouble, OnError: policy.OnErrorDeny,
	}}}
	if err := h.sources.VerifySchema(good); err != nil {
		t.Fatalf("a matching schema was refused: %v", err)
	}

	missing := &policy.Schema{Sources: []policy.SourceDecl{{
		Name: "not_configured", Kind: policy.SourceEvent,
		Params:  []policy.Param{{Name: "subject", Type: policy.TypeString}},
		Returns: policy.TypeDouble, OnError: policy.OnErrorDeny,
	}}}
	if err := h.sources.VerifySchema(missing); !errors.Is(err, fact.ErrLoad) {
		t.Errorf("an unconfigured event source verified with error %v, want a load rejection", err)
	}

	mismatched := &policy.Schema{Sources: []policy.SourceDecl{{
		Name: sourceName, Kind: policy.SourceEvent,
		Params:  []policy.Param{{Name: "subject", Type: policy.TypeString}},
		Returns: policy.TypeInt, OnError: policy.OnErrorDeny,
	}}}
	if err := h.sources.VerifySchema(mismatched); !errors.Is(err, fact.ErrLoad) {
		t.Errorf("a signature mismatch verified with error %v, want a load rejection", err)
	}
}

// recordingResolver stands in for the synchronous fact plane behind the
// velocity sources.
type recordingResolver struct {
	answers map[string]any
	seen    []engine.SourceCall
}

func (r *recordingResolver) ResolveSources(_ context.Context, calls []engine.SourceCall) (*engine.Facts, error) {
	r.seen = append(r.seen, calls...)
	facts := engine.NewFacts()
	for _, call := range calls {
		v, ok := r.answers[call.Name]
		if !ok {
			return nil, errors.New("recordingResolver: no answer for " + call.Name)
		}
		facts.Set(call, v)
	}
	return facts, nil
}
