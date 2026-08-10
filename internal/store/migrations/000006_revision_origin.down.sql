DROP INDEX IF EXISTS policy_revisions_origin_created_idx;

ALTER TABLE policy_revisions DROP CONSTRAINT IF EXISTS policy_revisions_state_check;

-- A superseded proposal has no representation in the older schema. It is a
-- resolved proposal either way, so it rolls back as a rejection rather than
-- blocking the migration on rows the old constraint would refuse.
UPDATE policy_revisions SET state = 'rejected' WHERE state = 'superseded';

ALTER TABLE policy_revisions
    ADD CONSTRAINT policy_revisions_state_check
        CHECK (state IN ('pending', 'applied', 'withdrawn', 'rejected'));

ALTER TABLE policy_revisions DROP CONSTRAINT IF EXISTS policy_revisions_origin_check;

ALTER TABLE policy_revisions DROP COLUMN IF EXISTS origin;
