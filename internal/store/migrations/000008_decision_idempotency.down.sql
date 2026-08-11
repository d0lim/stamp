-- Rolling this back takes the column and everything hanging off it, and leaves
-- every decision row where it was. Dropping the column drops the index and the
-- check with it; both are named here anyway, so that a database where one was
-- created by hand and the other was not still ends up clean.
DROP INDEX IF EXISTS decisions_unique_idempotency_key;
ALTER TABLE decisions DROP CONSTRAINT IF EXISTS decisions_idempotency_key_length;
ALTER TABLE decisions DROP COLUMN IF EXISTS idempotency_key;
