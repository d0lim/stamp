-- The caller's name for a decide attempt, so a retry can find what the attempt
-- created instead of creating a second one (#47(a)).
--
-- A PEP that times out mid-decide has no identifier: the response carrying it is
-- the thing that was lost. Without a name for the attempt the only safe move it
-- has is to retry, and every retry opened another decision — another outstanding
-- slot against the subject's cap, another challenge, another prompt at a person
-- for an authorization they were already asked about. Those decisions are
-- orphans in the exact sense the issue names: nothing the caller holds refers to
-- them, and they sit open until they expire.
ALTER TABLE decisions ADD COLUMN idempotency_key text;

-- The key is scoped to the caller and never global. Two workloads that number
-- their retries the same way are two callers; collapsing them would hand one
-- workload a decision identifier the other created, which R40 then lets it read.
--
-- **This index is the backstop and not the mechanism.** The lookup that makes a
-- retry cheap lives in the decide path ahead of the evaluation, because a
-- decision issues its challenges before its row is written — so a key enforced
-- only here would still reach the IdP once per retry and refuse afterwards,
-- which is the failure this column exists to prevent rather than a fix for it.
-- What the index is for is the case the lookup structurally cannot cover: two
-- concurrent attempts that both read no row. One of them lands, the other gets
-- 23505 and reads the winner's decision, and the callers converge.
--
-- Partial, so that the decisions nobody named — every decision written before
-- this migration and every keyless decide after it — do not collide with each
-- other on a NULL. Postgres would not collide them anyway, since NULLs are
-- distinct in a unique index; the predicate says so out loud and keeps the index
-- to the rows that can actually conflict.
CREATE UNIQUE INDEX decisions_unique_idempotency_key
    ON decisions (caller_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- A bound on what a caller can make the engine store and index. The surface
-- refuses an over-long key before it reaches here; this is the same rule stated
-- where it cannot be bypassed by a second write path.
ALTER TABLE decisions ADD CONSTRAINT decisions_idempotency_key_length
    CHECK (idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 1 AND 255);
