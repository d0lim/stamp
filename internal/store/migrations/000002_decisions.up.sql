-- Decision lifecycle: the decision itself, the per-challenge progress rows, and
-- the approvals collected against them.

CREATE TABLE decisions (
    id                 uuid        NOT NULL,
    caller_id          text        NOT NULL,
    policy_id          text        NOT NULL,
    policy_version     bigint      NOT NULL,
    subject_id         text        NOT NULL,
    resource_id        text        NOT NULL,
    action             text        NOT NULL,
    request            jsonb       NOT NULL,
    -- Facts are frozen onto the row rather than re-read at resolution time. A
    -- decision that was created because a fact said one thing must not become
    -- allowable because the fact later says another.
    fact_snapshot      jsonb       NOT NULL,
    obligations        jsonb       NOT NULL DEFAULT '[]'::jsonb,
    state              text        NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    -- expires_at is the decision's own deadline and the only column an
    -- entry-time deadline check reads.
    expires_at         timestamptz NOT NULL,
    -- next_deadline is the scheduler's column: min(expires_at, unmet challenge
    -- timers). It exists separately precisely so a delay timer landing in it
    -- does not make the decision read as expired.
    next_deadline      timestamptz,
    next_deadline_kind text,
    resolved_at        timestamptz,
    CONSTRAINT decisions_pkey PRIMARY KEY (id),
    CONSTRAINT decisions_policy_fk FOREIGN KEY (policy_id, policy_version)
        REFERENCES policies (id, version),
    CONSTRAINT decisions_state_check
        CHECK (state IN ('pending', 'allowed', 'denied', 'expired', 'cancelled')),
    CONSTRAINT decisions_deadline_kind_check
        CHECK (next_deadline_kind IS NULL OR next_deadline_kind IN ('expiry', 'challenge')),
    CONSTRAINT decisions_deadline_pair_check
        CHECK ((next_deadline IS NULL) = (next_deadline_kind IS NULL)),
    -- next_deadline is a minimum that includes expires_at, so it can never sit
    -- past it. A row that violated this would make the sweeper wake up after
    -- the decision was already due to expire.
    CONSTRAINT decisions_deadline_bound_check
        CHECK (next_deadline IS NULL OR next_deadline <= expires_at)
);

-- The sweeper's claim query drives off next_deadline; entry-time checks drive
-- off expires_at. Two columns, two indexes, two questions.
CREATE INDEX decisions_due_idx ON decisions (next_deadline) WHERE state = 'pending';
CREATE INDEX decisions_expiry_idx ON decisions (expires_at) WHERE state = 'pending';
CREATE INDEX decisions_caller_idx ON decisions (caller_id, created_at DESC);

CREATE TABLE challenge_progress (
    decision_id  uuid        NOT NULL,
    ordinal      integer     NOT NULL,
    kind         text        NOT NULL,
    state        text        NOT NULL,
    deadline     timestamptz,
    satisfied_at timestamptz,
    detail       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT challenge_progress_pkey PRIMARY KEY (decision_id, ordinal),
    CONSTRAINT challenge_progress_decision_fk FOREIGN KEY (decision_id)
        REFERENCES decisions (id) ON DELETE CASCADE,
    CONSTRAINT challenge_progress_kind_check
        CHECK (kind IN ('quorum', 'mfa', 'delay', 'external')),
    CONSTRAINT challenge_progress_state_check
        CHECK (state IN ('pending', 'satisfied', 'failed', 'cancelled')),
    CONSTRAINT challenge_progress_ordinal_check CHECK (ordinal >= 0)
);

CREATE TABLE approvals (
    id                uuid        NOT NULL,
    decision_id       uuid        NOT NULL,
    challenge_ordinal integer     NOT NULL,
    approver_id       text        NOT NULL,
    verdict           text        NOT NULL,
    -- The binding hash is server-issued. It is what ties an approval to the
    -- exact decision content the approver was shown.
    binding_hash      bytea       NOT NULL,
    detail            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    submitted_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT approvals_pkey PRIMARY KEY (id),
    CONSTRAINT approvals_challenge_fk FOREIGN KEY (decision_id, challenge_ordinal)
        REFERENCES challenge_progress (decision_id, ordinal) ON DELETE CASCADE,
    CONSTRAINT approvals_verdict_check CHECK (verdict IN ('approve', 'reject')),
    -- "Distinct approvals" is a database constraint, not a read-then-write
    -- check in the quorum path: two concurrent submissions from one approver
    -- must not both count toward a threshold.
    CONSTRAINT approvals_unique_approver UNIQUE (decision_id, challenge_ordinal, approver_id),
    CONSTRAINT approvals_binding_hash_check CHECK (octet_length(binding_hash) = 32)
);

CREATE INDEX approvals_decision_idx ON approvals (decision_id, challenge_ordinal);
