-- The authoring path a revision proposal arrived through, and the state a
-- proposal ends in when another from the same path replaces it.
--
-- The serialization gate admits one pending revision at a time, and the fourth
-- way out of it is same-origin supersession: a new proposal from the path that
-- already holds the gate replaces the one it holds, while one from the other
-- path is refused. Telling those two cases apart is what the column is for.
-- Without it a CI that applies on every merge deadlocks against its own last
-- proposal, and the only alternative — letting either path replace either
-- proposal — would be a way to discard a revision under review without a
-- withdrawal anybody can see.
ALTER TABLE policy_revisions
    ADD COLUMN origin text NOT NULL DEFAULT 'form';

ALTER TABLE policy_revisions
    ADD CONSTRAINT policy_revisions_origin_check CHECK (origin IN ('form', 'file'));

-- 'superseded' is that path's terminal state. It is distinct from 'withdrawn'
-- because nobody withdrew: an operator reading the history has to be able to
-- tell a proposal somebody took back from one the next merge replaced.
ALTER TABLE policy_revisions DROP CONSTRAINT policy_revisions_state_check;

ALTER TABLE policy_revisions
    ADD CONSTRAINT policy_revisions_state_check
        CHECK (state IN ('pending', 'applied', 'withdrawn', 'rejected', 'superseded'));

-- The rate limit on the release paths reads one origin's recent proposals.
CREATE INDEX policy_revisions_origin_created_idx
    ON policy_revisions (origin, created_at DESC);
