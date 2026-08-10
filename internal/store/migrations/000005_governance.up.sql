-- Self-referential governance: the proposal a policy change becomes, and the
-- one-time token that gates governance before the lock.

CREATE TABLE policy_revisions (
    id               uuid        NOT NULL,
    -- The governance decision gating this revision. It is null only in
    -- solo-admin mode before the lock, where the bootstrap token is the control
    -- and no quorum exists to open a decision against.
    decision_id      uuid,
    proposer_id      text        NOT NULL,
    -- The delta, stored with each side of every policy as its exchange-format
    -- document. The document is what a person reads in a diff and what the
    -- weakening classification was computed over.
    delta            jsonb       NOT NULL,
    delta_digest     bytea       NOT NULL,
    application_mode text        NOT NULL,
    state            text        NOT NULL,
    weakening        boolean     NOT NULL,
    findings         jsonb       NOT NULL DEFAULT '[]'::jsonb,
    threshold        integer     NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now(),
    resolved_at      timestamptz,
    CONSTRAINT policy_revisions_pkey PRIMARY KEY (id),
    CONSTRAINT policy_revisions_decision_fk FOREIGN KEY (decision_id)
        REFERENCES decisions (id),
    CONSTRAINT policy_revisions_state_check
        CHECK (state IN ('pending', 'applied', 'withdrawn', 'rejected')),
    CONSTRAINT policy_revisions_mode_check
        CHECK (application_mode IN ('revaluate', 'grandfather')),
    CONSTRAINT policy_revisions_digest_check CHECK (octet_length(delta_digest) = 32)
);

-- One pending revision at a time (D24). Serializing proposals is what lets an
-- approver review a single diff against the state currently in force instead of
-- against a base that another proposal is about to move. The constraint is an
-- index rather than an agreement between writers, because two proposals racing
-- is exactly the case an agreement would lose.
CREATE UNIQUE INDEX policy_revisions_pending_idx
    ON policy_revisions (state) WHERE state = 'pending';

CREATE INDEX policy_revisions_decision_idx ON policy_revisions (decision_id);

-- The bootstrap token, as a digest. The plaintext is printed once at first
-- start and never stored: a token readable out of the database would be a
-- second admin credential sitting in the same place as everything it protects.
CREATE TABLE governance_bootstrap (
    singleton      boolean     NOT NULL DEFAULT true,
    token_hash     bytea       NOT NULL,
    issued_at      timestamptz NOT NULL DEFAULT now(),
    -- Set when the lock succeeds. A consumed token is dead: R34 gives it one
    -- use, and the recovery path afterwards is the offline break-glass
    -- procedure rather than a second token.
    consumed_at    timestamptz,
    last_warned_at timestamptz,
    CONSTRAINT governance_bootstrap_pkey PRIMARY KEY (singleton),
    CONSTRAINT governance_bootstrap_singleton_check CHECK (singleton),
    CONSTRAINT governance_bootstrap_hash_check CHECK (octet_length(token_hash) = 32)
);
