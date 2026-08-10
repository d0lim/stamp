package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// MaxDeclarableWindow is the widest velocity window a policy may declare. It
// bounds how far back an aggregate query can reach, and therefore how long the
// dedup index has to remember an event.
const MaxDeclarableWindow = 30 * 24 * time.Hour

// DedupRetentionSlack is the margin added to the maximum declarable window when
// deciding how long a processed-event row is kept.
//
// The slack is not decoration. Retention exactly equal to the window would let
// a redelivery that arrives during the cleanup pass be counted twice, and an
// at-least-once ingestion adapter is precisely the thing that redelivers at the
// least convenient moment.
const DedupRetentionSlack = 24 * time.Hour

// DefaultDedupRetention is how long a processed-event row is kept.
func DefaultDedupRetention() time.Duration { return MaxDeclarableWindow + DedupRetentionSlack }

// BucketEvent is one aggregation event as an ingestion adapter delivers it.
//
// CallerID is part of the dedup key and not decoration: keying the index on
// event_id alone would let any caller suppress another caller's events by
// claiming their identifiers first.
type BucketEvent struct {
	CallerID  string
	EventID   string
	Metric    string
	SubjectID string
	Value     float64
	At        time.Time
	Width     time.Duration
}

// BucketWindow is an aggregate over a time range.
type BucketWindow struct {
	SubjectID string
	Metric    string
	Width     time.Duration
	From      time.Time
	To        time.Time
	Count     int64
	Sum       float64
}

// widthSeconds converts a bucket width to the column's unit, refusing widths
// outside the range a policy may declare. The bound is what keeps the
// conversion total rather than wrapping.
func widthSeconds(width time.Duration) (int32, error) {
	if width <= 0 {
		return 0, fmt.Errorf("store: bucket width must be positive, got %s", width)
	}
	if width > MaxDeclarableWindow {
		return 0, fmt.Errorf("store: bucket width %s exceeds the maximum declarable window %s",
			width, MaxDeclarableWindow)
	}
	return int32(width / time.Second), nil
}

// BucketStart returns the start of the fixed-width bucket an instant falls in.
func BucketStart(at time.Time, width time.Duration) time.Time {
	return at.UTC().Truncate(width)
}

// RecordEvent deduplicates an event and folds it into its bucket.
//
// The return value reports whether the event was new. Deduplication and the
// bucket update happen in one transaction, so an event can never be marked as
// seen without having been counted, or counted without having been marked.
func (s *Store) RecordEvent(ctx context.Context, ev BucketEvent) (bool, error) {
	var applied bool
	err := s.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		applied, err = RecordEventTx(ctx, tx, ev)
		return err
	})
	return applied, err
}

// RecordEventTx is RecordEvent inside a caller's transaction.
func RecordEventTx(ctx context.Context, q Querier, ev BucketEvent) (bool, error) {
	seconds, err := widthSeconds(ev.Width)
	if err != nil {
		return false, err
	}
	if ev.CallerID == "" || ev.EventID == "" || ev.Metric == "" {
		return false, fmt.Errorf("store: dedup key needs caller_id, event_id and metric (got %q, %q, %q)",
			ev.CallerID, ev.EventID, ev.Metric)
	}

	at := ev.At
	if at.IsZero() {
		at = time.Now()
	}
	tag, err := q.Exec(ctx, `
		INSERT INTO processed_events (caller_id, event_id, metric, seen_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (caller_id, event_id, metric) DO NOTHING`,
		ev.CallerID, ev.EventID, ev.Metric, at.UTC())
	if err != nil {
		return false, fmt.Errorf("store: mark event processed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}

	_, err = q.Exec(ctx, `
		INSERT INTO velocity_buckets
			(subject_id, metric, width_seconds, bucket_start, event_count, value_sum, updated_at)
		VALUES ($1, $2, $3, $4, 1, $5, now())
		ON CONFLICT (subject_id, metric, width_seconds, bucket_start) DO UPDATE
		SET event_count = velocity_buckets.event_count + 1,
		    value_sum = velocity_buckets.value_sum + EXCLUDED.value_sum,
		    updated_at = now()`,
		ev.SubjectID, ev.Metric, seconds,
		BucketStart(at, ev.Width), ev.Value)
	if err != nil {
		return false, fmt.Errorf("store: upsert velocity bucket: %w", err)
	}
	return true, nil
}

// Window sums the buckets covering [from, to).
func (s *Store) Window(ctx context.Context, subjectID, metric string, width time.Duration, from, to time.Time) (BucketWindow, error) {
	return WindowTx(ctx, s.pool, subjectID, metric, width, from, to)
}

// WindowTx is Window inside a caller's transaction.
func WindowTx(ctx context.Context, q Querier, subjectID, metric string, width time.Duration, from, to time.Time) (BucketWindow, error) {
	seconds, err := widthSeconds(width)
	if err != nil {
		return BucketWindow{}, err
	}
	out := BucketWindow{
		SubjectID: subjectID, Metric: metric, Width: width,
		From: from.UTC(), To: to.UTC(),
	}
	err = q.QueryRow(ctx, `
		SELECT coalesce(sum(event_count), 0), coalesce(sum(value_sum), 0)
		FROM velocity_buckets
		WHERE subject_id = $1 AND metric = $2 AND width_seconds = $3
		  AND bucket_start >= $4 AND bucket_start < $5`,
		subjectID, metric, seconds,
		BucketStart(from, width), out.To).Scan(&out.Count, &out.Sum)
	if err != nil {
		return BucketWindow{}, fmt.Errorf("store: read velocity window: %w", err)
	}
	return out, nil
}

// PruneProcessedEvents removes dedup rows older than the retention period.
//
// Retention is the widest declarable window plus slack, which is the shortest
// span that still makes deduplication correct for every window a policy can
// ask for.
func (s *Store) PruneProcessedEvents(ctx context.Context, retention time.Duration, now time.Time) (int64, error) {
	if retention < DefaultDedupRetention() {
		return 0, fmt.Errorf("store: dedup retention %s is shorter than the maximum declarable window plus slack (%s)",
			retention, DefaultDedupRetention())
	}
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM processed_events WHERE seen_at < $1`, now.UTC().Add(-retention))
	if err != nil {
		return 0, fmt.Errorf("store: prune processed events: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PruneBuckets removes buckets that start before the retention horizon.
func (s *Store) PruneBuckets(ctx context.Context, retention time.Duration, now time.Time) (int64, error) {
	if retention < MaxDeclarableWindow {
		return 0, fmt.Errorf("store: bucket retention %s is shorter than the maximum declarable window %s",
			retention, MaxDeclarableWindow)
	}
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM velocity_buckets WHERE bucket_start < $1`, now.UTC().Add(-retention))
	if err != nil {
		return 0, fmt.Errorf("store: prune velocity buckets: %w", err)
	}
	return tag.RowsAffected(), nil
}
