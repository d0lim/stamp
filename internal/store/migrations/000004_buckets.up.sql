-- Velocity aggregation and the dedup index that makes ingestion idempotent.

CREATE TABLE velocity_buckets (
    subject_id    text             NOT NULL,
    metric        text             NOT NULL,
    width_seconds integer          NOT NULL,
    bucket_start  timestamptz      NOT NULL,
    event_count   bigint           NOT NULL DEFAULT 0,
    value_sum     double precision NOT NULL DEFAULT 0,
    updated_at    timestamptz      NOT NULL DEFAULT now(),
    CONSTRAINT velocity_buckets_pkey PRIMARY KEY (subject_id, metric, width_seconds, bucket_start),
    CONSTRAINT velocity_buckets_width_check CHECK (width_seconds > 0),
    CONSTRAINT velocity_buckets_count_check CHECK (event_count >= 0)
);

CREATE INDEX velocity_buckets_prune_idx ON velocity_buckets (bucket_start);

-- The caller is part of the key. Keying on event_id alone would let any caller
-- burn another caller's identifier by claiming it first, which turns a dedup
-- index into a suppression channel.
CREATE TABLE processed_events (
    caller_id text        NOT NULL,
    event_id  text        NOT NULL,
    metric    text        NOT NULL,
    seen_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT processed_events_pkey PRIMARY KEY (caller_id, event_id, metric)
);

-- Retention is the widest declarable window plus slack, so the sweep is a
-- range scan on this index rather than a full table scan.
CREATE INDEX processed_events_seen_at_idx ON processed_events (seen_at);
