package stream_test

import (
	"errors"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/stream"
)

var epoch = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

func validEvent() stream.Event {
	return stream.Event{
		CallerID:   "workload:https://idp.example#pep-1",
		EventID:    "e-1",
		Metric:     "withdrawal_amount",
		SubjectID:  "user-1",
		Value:      100,
		ProducedAt: epoch,
	}
}

// The port refuses an event that carries no producer-assigned identifier and
// one that carries no producer timestamp. Both are the port's business rather
// than an adapter's: deduplication is keyed on the identifier and lag is
// measured from the timestamp, so an adapter that could deliver an event
// without them would be an adapter that can disable both.
func TestEventValidateRefusesMissingProducerFields(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*stream.Event)
		want error
	}{
		{"no event id", func(e *stream.Event) { e.EventID = "" }, stream.ErrNoEventID},
		{"no producer timestamp", func(e *stream.Event) { e.ProducedAt = time.Time{} }, stream.ErrNoProducedAt},
		{"no caller", func(e *stream.Event) { e.CallerID = "" }, stream.ErrNoCaller},
		{"no metric", func(e *stream.Event) { e.Metric = "" }, stream.ErrNoMetric},
		{"no subject", func(e *stream.Event) { e.SubjectID = "" }, stream.ErrNoSubject},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := validEvent()
			tc.mut(&ev)
			err := ev.Validate()
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate() = %v, want %v", err, tc.want)
			}
			if !errors.Is(err, stream.ErrRejected) {
				t.Errorf("Validate() = %v, want it to wrap ErrRejected", err)
			}
		})
	}

	if err := validEvent().Validate(); err != nil {
		t.Fatalf("a complete event was refused: %v", err)
	}
}

// A value that is not a finite number is refused. NaN in a bucket sum poisons
// every later comparison against a limit, and a comparison against NaN is
// false — which turns a velocity limit off rather than tripping it.
func TestEventValidateRefusesNonFiniteValue(t *testing.T) {
	for _, v := range []float64{nan(), inf(1), inf(-1)} {
		ev := validEvent()
		ev.Value = v
		if err := ev.Validate(); !errors.Is(err, stream.ErrValueNotFinite) {
			t.Errorf("Validate() with value %v = %v, want ErrValueNotFinite", v, err)
		}
	}
}

// Lag is now minus the producer timestamp of the most recently confirmed
// event, and it clamps at zero when the producer's clock runs ahead. A
// negative lag would read as "fresher than fresh" and would pass any freshness
// limit no matter how far the clock had been pushed.
func TestLagTrackerMeasuresFromProducerTimestamp(t *testing.T) {
	var tr stream.LagTracker

	if _, ok := tr.Lag(epoch); ok {
		t.Fatal("Lag reported a value before any event was confirmed")
	}

	tr.Observe([]stream.Event{
		{ProducedAt: epoch.Add(-90 * time.Second)},
		{ProducedAt: epoch.Add(-30 * time.Second)},
		{ProducedAt: epoch.Add(-60 * time.Second)},
	})
	lag, ok := tr.Lag(epoch)
	if !ok {
		t.Fatal("Lag reported nothing after a confirmed batch")
	}
	if want := 30 * time.Second; lag != want {
		t.Errorf("Lag = %s, want %s — it must measure from the newest producer timestamp in the batch", lag, want)
	}

	// An older batch arriving later does not move the mark backwards.
	tr.Observe([]stream.Event{{ProducedAt: epoch.Add(-10 * time.Minute)}})
	if lag, _ := tr.Lag(epoch); lag != 30*time.Second {
		t.Errorf("Lag = %s after an older batch, want it unchanged at 30s", lag)
	}

	// A producer clock running ahead of ours clamps at zero rather than
	// reporting a negative lag.
	tr.Observe([]stream.Event{{ProducedAt: epoch.Add(5 * time.Minute)}})
	if lag, _ := tr.Lag(epoch); lag != 0 {
		t.Errorf("Lag = %s for a producer timestamp in the future, want it clamped to 0", lag)
	}
}

func nan() float64 { var z float64; return z / z } //nolint:revive // deliberate NaN
func inf(sign int) float64 {
	var z float64
	if sign < 0 {
		return -1 / z
	}
	return 1 / z
}
