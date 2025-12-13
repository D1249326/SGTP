-- 006-create-cart.sql
-- Cart items per user
CREATE TABLE IF NOT EXISTS cart_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  product_id TEXT NOT NULL,
  title TEXT,
  price REAL DEFAULT 0,
  qty INTEGER DEFAULT 1,
  image TEXT,
  seller_id TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cart_user ON cart_items(user_id);
