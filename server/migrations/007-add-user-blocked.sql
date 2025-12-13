-- add is_blocked flag to users for admin blocking
-- single statement to avoid nested transaction errors in sqlite3 exec
ALTER TABLE users ADD COLUMN is_blocked INTEGER DEFAULT 0;
