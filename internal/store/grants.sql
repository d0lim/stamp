-- Per-role database privileges (R39).
--
-- This ships with the migrations and Migrate applies it as the last step, but
-- it is not itself a numbered migration. Roles are cluster-global objects while
-- migrations are per-database, and the role names have to be settable per
-- deployment — a cluster that already has a role called stamp_check must not be
-- silently co-opted. golang-migrate files are static text, so the names are
-- templated here and validated as SQL identifiers before substitution.
--
-- No passwords and no LOGIN attribute are set here. These are privilege
-- templates; a deployment grants them to whatever login roles it already
-- manages, and credentials never live in a file that ships with the binary.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{{.Check}}') THEN
        CREATE ROLE {{.Check}} NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{{.Decide}}') THEN
        CREATE ROLE {{.Decide}} NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{{.Consumer}}') THEN
        CREATE ROLE {{.Consumer}} NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{{.Admin}}') THEN
        CREATE ROLE {{.Admin}} NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO {{.Check}}, {{.Decide}}, {{.Consumer}}, {{.Admin}};

-- Start from nothing on every apply so that a privilege removed from this file
-- is actually removed from the database.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {{.Check}}, {{.Decide}}, {{.Consumer}}, {{.Admin}};
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {{.Check}}, {{.Decide}}, {{.Consumer}}, {{.Admin}};

-- Every role reads the applied schema version, because every role answers a
-- readiness probe with it. Only one tier migrates, so the others have to be able
-- to see whether the schema they were built against has arrived before they take
-- traffic — a tier that cannot read this table cannot tell "the migration has not
-- landed yet" from "I am ready", and answers requests with 42703 instead of
-- staying out of its Service.
--
-- SELECT only, and it stays that way: reading which version is applied is not
-- permission to claim one. A role that could write this table could tell the
-- whole fleet the schema had arrived.
GRANT SELECT ON schema_migrations TO {{.Check}}, {{.Decide}}, {{.Consumer}}, {{.Admin}};

-- check: reads what it evaluates against and appends audit rows. It never
-- writes a policy — a compromised check tier must not be able to author the
-- rules it is judged by.
GRANT SELECT ON
    policy_schemas, policies, decisions, challenge_progress, approvals,
    velocity_buckets, audit_log, audit_checkpoints
    TO {{.Check}};
GRANT INSERT ON audit_log TO {{.Check}};
GRANT SELECT, INSERT, UPDATE ON audit_writers TO {{.Check}};

-- decide: owns the decision lifecycle and appends the audit rows that go in the
-- same transaction as each state transition. Still read-only on policies.
GRANT SELECT ON policy_schemas, policies, velocity_buckets TO {{.Decide}};
GRANT SELECT, INSERT, UPDATE ON decisions, challenge_progress, approvals TO {{.Decide}};
GRANT SELECT, INSERT ON audit_log, audit_checkpoints TO {{.Decide}};
GRANT SELECT, INSERT, UPDATE ON audit_writers TO {{.Decide}};

-- consumer: bucket upsert and the dedup index that makes the upsert idempotent.
-- Nothing else. An ingestion adapter reachable from a broker is the least
-- trusted writer in the system.
GRANT SELECT, INSERT, UPDATE ON velocity_buckets TO {{.Consumer}};
GRANT SELECT, INSERT, DELETE ON processed_events TO {{.Consumer}};

-- admin: the governance and authoring path. It writes policies; it does not get
-- UPDATE or DELETE on the audit log, because append-only is a grant and not a
-- convention.
GRANT SELECT, INSERT, UPDATE ON policy_schemas, policies TO {{.Admin}};
GRANT SELECT, INSERT, UPDATE ON decisions, challenge_progress, approvals TO {{.Admin}};
-- The revision effect hook invalidates approvals whose binding hash no longer
-- matches, and rebuilds a decision's challenge rows when the revision changed
-- which challenges it carries (R5, R31). Both are deletes, and both are on the
-- governance path alone — the decide role never gets them, so a compromised
-- decide tier cannot erase the evidence a quorum was collected on.
GRANT DELETE ON approvals, challenge_progress TO {{.Admin}};
GRANT SELECT, INSERT, UPDATE ON policy_revisions, governance_bootstrap TO {{.Admin}};
-- The decide tier reads the pending revision so a console can show what is in
-- flight; it never writes one.
GRANT SELECT ON policy_revisions TO {{.Decide}};
GRANT SELECT, INSERT ON audit_log, audit_checkpoints TO {{.Admin}};
GRANT SELECT, INSERT, UPDATE ON audit_writers TO {{.Admin}};
GRANT SELECT, INSERT, UPDATE, DELETE ON velocity_buckets, processed_events TO {{.Admin}};
