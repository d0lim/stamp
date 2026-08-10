package stream

// memory.go is an in-memory adapter for the ingestion port.
//
// It is not test scaffolding that happens to live in the package. The unit's
// verification gate is that the entire aggregation suite runs with no broker,
// and that gate is only meaningful if the thing standing in for the broker
// implements the same port the Kafka adapter does — the same Run, the same
// Sink, the same lag contract. If the port ever grew an offset or a partition,
// this file would stop compiling, which is the cheapest possible alarm for the
// abstraction leaking.
//
// It models the two broker behaviours the port's guarantees actually depend
// on, and no others. Events sit in an append-only log, and a cursor advances
// only when the sink confirms — so a batch the sink refused is redelivered,
// and [MemoryAdapter.Rewind] replays a range whose confirmation was lost to a
// restart. The cursor is deliberately private: it is the adapter's own
// bookkeeping and never crosses the port.

import (
	"context"
	"errors"
	"sync"
	"time"
)

// DefaultMemoryBatch is how many events a memory adapter hands over at once.
const DefaultMemoryBatch = 64

// DefaultMemoryPoll is how often its Run loop looks for new events.
const DefaultMemoryPoll = 5 * time.Millisecond

// MemoryAdapterOption configures a [MemoryAdapter].
type MemoryAdapterOption func(*MemoryAdapter)

// WithoutLagReporting builds an adapter that declares it cannot report
// ingestion lag.
//
// A real transport in this position exists — a bridge that receives events
// with no usable producer clock — and the load gate that refuses a freshness
// limit against such a source has to be exercised against something. This is
// that something.
func WithoutLagReporting() MemoryAdapterOption {
	return func(m *MemoryAdapter) { m.reportsLag = false }
}

// WithMemoryBatch sets how many events are handed over at once.
func WithMemoryBatch(n int) MemoryAdapterOption {
	return func(m *MemoryAdapter) {
		if n > 0 {
			m.batch = n
		}
	}
}

// MemoryAdapter is an [Adapter] whose transport is a slice.
type MemoryAdapter struct {
	name       string
	reportsLag bool
	batch      int
	poll       time.Duration
	lag        LagTracker

	mu     sync.Mutex
	log    []Event
	cursor int
}

var _ Adapter = (*MemoryAdapter)(nil)

// NewMemoryAdapter builds an in-memory adapter.
func NewMemoryAdapter(name string, opts ...MemoryAdapterOption) *MemoryAdapter {
	m := &MemoryAdapter{
		name:       name,
		reportsLag: true,
		batch:      DefaultMemoryBatch,
		poll:       DefaultMemoryPoll,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Name implements [Adapter].
func (m *MemoryAdapter) Name() string { return m.name }

// ReportsLag implements [Adapter].
func (m *MemoryAdapter) ReportsLag() bool { return m.reportsLag }

// Lag implements [Adapter].
func (m *MemoryAdapter) Lag(now time.Time) (time.Duration, bool) {
	if !m.reportsLag {
		return 0, false
	}
	return m.lag.Lag(now)
}

// Publish appends events to the adapter's log, the way a producer would.
func (m *MemoryAdapter) Publish(events ...Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.log = append(m.log, events...)
}

// Rewind moves the cursor back by n events, modelling a consumer that
// restarted before its position was confirmed.
//
// The replayed range has already been applied, so what it exercises is exactly
// the guarantee the port makes: at-least-once from the adapter, exactly-once
// in the aggregate.
func (m *MemoryAdapter) Rewind(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cursor -= n
	if m.cursor < 0 {
		m.cursor = 0
	}
}

// Pending reports how many events have not been confirmed yet.
func (m *MemoryAdapter) Pending() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.log) - m.cursor
}

// Drain hands everything pending to the sink and returns when the log is
// exhausted. It is the deterministic form of [MemoryAdapter.Run].
func (m *MemoryAdapter) Drain(ctx context.Context, sink Sink) error {
	for {
		delivered, err := m.deliverOnce(ctx, sink)
		if err != nil {
			return err
		}
		if delivered == 0 {
			return nil
		}
	}
}

// Run implements [Adapter]. It polls its own log until the context ends.
func (m *MemoryAdapter) Run(ctx context.Context, sink Sink) error {
	ticker := time.NewTicker(m.poll)
	defer ticker.Stop()
	for {
		if _, err := m.deliverOnce(ctx, sink); err != nil {
			if errors.Is(err, ctx.Err()) {
				return nil
			}
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// deliverOnce hands over at most one batch and advances the cursor only if the
// sink confirmed it.
func (m *MemoryAdapter) deliverOnce(ctx context.Context, sink Sink) (int, error) {
	m.mu.Lock()
	if m.cursor >= len(m.log) {
		m.mu.Unlock()
		return 0, nil
	}
	end := min(m.cursor+m.batch, len(m.log))
	batch := append([]Event(nil), m.log[m.cursor:end]...)
	m.mu.Unlock()

	if _, err := sink.Accept(ctx, batch); err != nil {
		// The cursor does not move. A refused batch is redelivered, which is
		// the whole of what an at-least-once adapter promises — and a
		// permanently unacceptable event would stall this adapter, which is
		// the honest behaviour for a transport that cannot dead-letter.
		return 0, err
	}
	m.lag.Observe(batch)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cursor = end
	return len(batch), nil
}
