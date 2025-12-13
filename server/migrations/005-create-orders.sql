-- 005-create-orders.sql
-- Orders table for storing buyer orders
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  buyer_id INTEGER,
  buyer_email TEXT,
  items TEXT,
  total_amount REAL DEFAULT 0,
  status TEXT DEFAULT 'pending',
  cancel_status TEXT,
  cancel_reason TEXT,
  ship_name TEXT,
  ship_phone TEXT,
  ship_address TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  canceled_by INTEGER,
  canceled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders(created_at);
