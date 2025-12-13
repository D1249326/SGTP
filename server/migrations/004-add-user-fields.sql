-- add optional fields to users
PRAGMA foreign_keys=off;
BEGIN TRANSACTION;
ALTER TABLE users ADD COLUMN phone TEXT;
ALTER TABLE users ADD COLUMN address TEXT;
COMMIT;
PRAGMA foreign_keys=on;
