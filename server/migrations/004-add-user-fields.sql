-- add optional fields to users
ALTER TABLE users ADD COLUMN phone TEXT;
ALTER TABLE users ADD COLUMN address TEXT;
-- PRAGMA and transaction wrappers removed to avoid nested transaction errors
