CREATE TABLE IF NOT EXISTS chat_rooms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  buyer_id INTEGER NOT NULL,
  seller_id INTEGER NOT NULL,
  product_id INTEGER,  -- 如果允許「純閒聊」(不針對特定商品)，這裡可以不設 NOT NULL
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (buyer_id) REFERENCES users(id),
  FOREIGN KEY (seller_id) REFERENCES users(id),
  FOREIGN KEY (product_id) REFERENCES products(id),

  -- 【關鍵修改】設定唯一索引
  -- 確保這組組合永遠只有一筆紀錄
  UNIQUE(buyer_id, seller_id, product_id)
);

CREATE TABLE IF NOT EXISTS chat_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id INTEGER NOT NULL,  -- 這裡連結上面的 chat_rooms.id
  sender_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  -- 當聊天室被刪除時，連帶刪除訊息
  FOREIGN KEY (room_id) REFERENCES chat_rooms(id) ON DELETE CASCADE,
  FOREIGN KEY (sender_id) REFERENCES users(id)
);