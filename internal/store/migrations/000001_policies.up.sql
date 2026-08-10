-- Policy storage. A policy's identity is its id; a policy's history is the
-- (id, version) pair. Versions are never rewritten, because a decision row
-- points at the exact version that was evaluated and that pointer has to stay
-- resolvable for as long as the audit log does.

CREATE TABLE policy_schemas (
    version      bigint      NOT NULL,
    document     text        NOT NULL,
    content_hash bytea       NOT NULL,
    origin       text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   text        NOT NULL,
    CONSTRAINT policy_schemas_pkey PRIMARY KEY (version),
    CONSTRAINT policy_schemas_version_check CHECK (version > 0),
    CONSTRAINT policy_schemas_origin_check CHECK (origin IN ('form', 'file'))
);

CREATE TABLE policies (
    id                text        NOT NULL,
    version           bigint      NOT NULL,
    schema_version    bigint      NOT NULL,
    origin            text        NOT NULL,
    document          text        NOT NULL,
    content_hash      bytea       NOT NULL,
    requires_decision boolean     NOT NULL,
    deleted           boolean     NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now(),
    created_by        text        NOT NULL,
    superseded_at     timestamptz,
    CONSTRAINT policies_pkey PRIMARY KEY (id, version),
    CONSTRAINT policies_schema_fk FOREIGN KEY (schema_version)
        REFERENCES policy_schemas (version),
    CONSTRAINT policies_version_check CHECK (version > 0),
    -- The authoring origin decides which path owns the policy. Without it the
    -- next file apply computes every console-authored policy as a delete.
    CONSTRAINT policies_origin_check CHECK (origin IN ('form', 'file'))
);

-- At most one live version per policy. This is the constraint that makes
-- "the effective set" a query rather than an agreement between writers.
CREATE UNIQUE INDEX policies_effective_idx ON policies (id) WHERE superseded_at IS NULL;

CREATE INDEX policies_origin_idx ON policies (origin)
    WHERE superseded_at IS NULL AND NOT deleted;
