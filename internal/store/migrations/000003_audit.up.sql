-- The segmented audit chain.
--
-- One row per audited event, chained per writer rather than globally: a global
-- chain has to serialize every append behind one lock, and U0 measured that
-- difference at more than an order of magnitude. The cost of the split is that
-- a writer_id must be owned by exactly one process at a time, which
-- audit_writers enforces.

CREATE TABLE audit_writers (
    writer_id   text        NOT NULL,
    lock_key    bigint      NOT NULL,
    instance    text        NOT NULL,
    claimed_at  timestamptz NOT NULL DEFAULT now(),
    released_at timestamptz,
    CONSTRAINT audit_writers_pkey PRIMARY KEY (writer_id),
    -- The advisory lock key is derived from the writer id. Two writer ids that
    -- collided on a key would let one process silently claim the other's
    -- segment, so the mapping is unique by constraint and not by hope.
    CONSTRAINT audit_writers_lock_key_unique UNIQUE (lock_key)
);

CREATE TABLE audit_log (
    writer_id   text        NOT NULL,
    seq         bigint      NOT NULL,
    prev_hash   bytea       NOT NULL,
    hash        bytea       NOT NULL,
    kind        text        NOT NULL,
    subject     text        NOT NULL DEFAULT '',
    payload     jsonb       NOT NULL,
    recorded_at timestamptz NOT NULL,
    -- The primary key is the chain. A second process writing the same segment
    -- collides here rather than forking the chain silently.
    CONSTRAINT audit_log_pkey PRIMARY KEY (writer_id, seq),
    CONSTRAINT audit_log_seq_check CHECK (seq > 0),
    CONSTRAINT audit_log_hash_check CHECK (octet_length(hash) = 32),
    CONSTRAINT audit_log_prev_hash_check CHECK (octet_length(prev_hash) = 32)
);

CREATE INDEX audit_log_recorded_idx ON audit_log (recorded_at);
CREATE INDEX audit_log_subject_idx ON audit_log (kind, subject);

-- Checkpoints cross-link the segments: each one names every writer's head at a
-- moment and is signed with a key the database does not hold, so DB write
-- access alone cannot forge one. The row here is a convenience copy — the
-- authority is the copy in the external sink.
CREATE TABLE audit_checkpoints (
    seq        bigint      NOT NULL,
    created_at timestamptz NOT NULL,
    heads      jsonb       NOT NULL,
    heads_hash bytea       NOT NULL,
    -- Checkpoints are themselves chained, which is what turns a deleted
    -- checkpoint into a detectable gap rather than a shorter history.
    prev_hash  bytea       NOT NULL,
    key_id     text        NOT NULL,
    signature  bytea       NOT NULL,
    CONSTRAINT audit_checkpoints_pkey PRIMARY KEY (seq),
    CONSTRAINT audit_checkpoints_seq_check CHECK (seq > 0),
    CONSTRAINT audit_checkpoints_heads_hash_check CHECK (octet_length(heads_hash) = 32),
    CONSTRAINT audit_checkpoints_prev_hash_check CHECK (octet_length(prev_hash) = 32)
);
