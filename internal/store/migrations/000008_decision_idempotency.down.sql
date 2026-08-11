-- Rolling this back takes the column and the check, and leaves every decision
-- row where it was. Dropping the column drops the check with it; the check is
-- named here anyway, so that a database where one was created by hand and the
-- other was not still ends up clean.
--
-- The unique index is 000009's and is dropped by 000009's down. It is not named
-- here: golang-migrate runs downs newest-first, so by the time this file runs
-- the index is already gone, and naming it here would be a second claim on an
-- object this migration does not own. If someone rolls back to 7 by hand without
-- running 000009's down, DROP COLUMN takes the index along with the column
-- anyway — there is no path that leaves it behind.
ALTER TABLE decisions DROP CONSTRAINT IF EXISTS decisions_idempotency_key_length;
ALTER TABLE decisions DROP COLUMN IF EXISTS idempotency_key;
