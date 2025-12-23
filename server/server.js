const express = require('express');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { db, runMigration } = require('./db');

const path = require('path');
const multer = require('multer');

const http = require('http');
const { Server } = require("socket.io");

const app = express();
app.use(cors());
app.use(express.json());

const crypto = require('crypto');

// ✅ [新增] 建立 HTTP Server 並綁定 Socket.io
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" } // 允許跨域連線
});

// Serve project static files
const publicRoot = path.join(__dirname, '..');
app.use(express.static(publicRoot));

// Serve uploaded files
const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!require('fs').existsSync(uploadsDir)) require('fs').mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir));

const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, uploadsDir); },
  filename: function (req, file, cb) { const ts = Date.now(); const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_'); cb(null, ts + '_' + safe); }
});
const upload = multer({ storage });

app.get('/', (req, res, next) => {
  const indexPath = path.join(publicRoot, 'index.html');
  if (require('fs').existsSync(indexPath)) return next();
  res.send('<h2>SGTP API Server</h2><p>API is available under /api/*</p>');
});

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';

/* =========================================
   ✅ [新增] Socket.io 聊天邏輯
   ========================================= */
/* server.js 的 Socket 部分 */

io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  socket.on('join', (userId) => {
    socket.join(String(userId));
  });

  // ✅ [修改] 讀取歷史：加入 order_id 篩選
  socket.on('loadHistory', ({ user1, user2, productId, orderId }) => {
    const pid = productId ? parseInt(productId) : 0;
    const oid = orderId ? parseInt(orderId) : 0; // 新增 orderId

    const sql = `
      SELECT * FROM chat_messages 
      WHERE ((sender_id = ? AND receiver_id = ?) 
         OR (sender_id = ? AND receiver_id = ?))
      AND product_id = ? 
      AND order_id = ?   -- ✅ 關鍵：只撈出該訂單的對話
      ORDER BY created_at ASC
    `;
    
    db.all(sql, [user1, user2, user2, user1, pid, oid], (err, rows) => {
      if (err) console.error(err);
      else socket.emit('history', rows || []);
    });
  });

  // ✅ [修改] 發送訊息：儲存 order_id
  socket.on('sendMessage', ({ sender, receiver, content, product_id, order_id }) => {
    if (!sender || !receiver || !content) return;

    const pid = product_id ? parseInt(product_id) : 0;
    const oid = order_id ? parseInt(order_id) : 0; // 新增 orderId

    const sql = `INSERT INTO chat_messages (room_id, sender_id, receiver_id, content, product_id, order_id, created_at) VALUES (0, ?, ?, ?, ?, ?, datetime('now', '+8 hours'))`;
    
    db.run(sql, [sender, receiver, content, pid, oid], function(err) {
      if (err) return console.error('Save msg error:', err);
      
      const msgData = {
        id: this.lastID,
        sender_id: sender,
        receiver_id: receiver,
        content: content,
        product_id: pid,
        order_id: oid,    // ✅ 回傳給前端
        created_at: new Date().toISOString()
      };

      io.to(String(receiver)).emit('receiveMessage', msgData);
      socket.emit('receiveMessage', msgData);
    });
  });
});

async function initServer(){
  try{
    await runMigration();
    const userCount = await new Promise((resolve, reject) => {
      db.get('SELECT COUNT(*) AS cnt FROM users', [], (err, row) => {
        if (err) return reject(err);
        resolve(row && row.cnt ? row.cnt : 0);
      });
    });

    if (!userCount) {
      console.log('No users found in DB — running seed...');
      const seedModule = require('./seed');
      await seedModule.seed();
      console.log('Auto-seed completed');
    }
  }catch(err){
    console.error('Error during migration/seed:', err);
  }
}

// Auth Middleware
function getTokenFromHeader(req) {
  const h = req.headers && req.headers.authorization;
  if (!h) return null;
  const parts = h.split(' ');
  if (parts.length === 2 && parts[0] === 'Bearer') return parts[1];
  return null;
}

function adminAuth(req, res, next) {
  const token = getTokenFromHeader(req);
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'admin') return res.status(403).json({ error: 'Requires admin role' });
    req.user = payload;
    next();
  } catch (e) { return res.status(401).json({ error: 'Invalid token' }); }
}

function userAuth(req, res, next) {
  const token = getTokenFromHeader(req);
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    db.get('SELECT COALESCE(is_blocked,0) AS is_blocked FROM users WHERE id = ?', [payload.id], (err, row) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      if (row && row.is_blocked) return res.status(403).json({ error: 'User is blocked' });
      req.user = payload;
      next();
    });
  } catch (e) { return res.status(401).json({ error: 'Invalid token' }); }
}

function sellerAuth(req, res, next) {
  const token = getTokenFromHeader(req);
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'seller') return res.status(403).json({ error: 'Requires seller role' });
    db.get('SELECT COALESCE(is_blocked,0) AS is_blocked FROM users WHERE id = ?', [payload.id], (err, row) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      if (row && row.is_blocked) return res.status(403).json({ error: 'User is blocked' });
      req.user = payload;
      next();
    });
  } catch (e) { return res.status(401).json({ error: 'Invalid token' }); }
}

function logAdminAction(adminId, action, targetType = null, targetId = null, details = null) {
  try {
    db.run('INSERT INTO admin_logs (admin_id, action, target_type, target_id, details, created_at) VALUES (?, ?, ?, ?, ?, datetime("now", "+8 hours"))', 
      [adminId, action, targetType, targetId, details], function(err) {
      if (err) console.error('Failed to write admin log:', err);
    });
  } catch (e) { console.error('Error in logAdminAction:', e); }
}

function dbRun(sql, params) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this); // 回傳 this 以便取得 lastID
    });
  });
}

// Create user
app.post('/api/users/register', (req, res) => {
  const { name, email, password, role, phone, address } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });

  db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (row) return res.status(409).json({ error: 'Email exists' });

    try {
      const hash = await bcrypt.hash(password, 10);
      const r = role || 'buyer';
      db.run('INSERT INTO users (name, email, password_hash, role, phone, address, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime("now", "+8 hours"))', 
        [name, email, hash, r, phone || null, address || null], function(insertErr) {
        if (insertErr) return res.status(500).json({ error: 'Insert error' });
        const id = this.lastID;
        db.get('SELECT id, name, email, role, phone, address, created_at FROM users WHERE id = ?', [id], (getErr, user) => {
          res.status(201).json(user);
        });
      });
    } catch (e) { res.status(500).json({ error: 'Server error' }); }
  });
});

// ✅ [新增] 管理者註冊 API
app.post('/api/admin/register', (req, res) => {
  const { name, email, password } = req.body;
  
  // 1. 基本檢查
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });

  // 2. 檢查 Email 是否重複
  db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (row) return res.status(409).json({ error: 'Email exists' });

    try {
      // 3. 加密密碼
      const hash = await bcrypt.hash(password, 10);
      
      // 4. 寫入資料庫 (強制 role = 'admin')
      // 注意：管理者不需要電話地址，所以填 null
      db.run('INSERT INTO users (name, email, password_hash, role, phone, address, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime("now", "+8 hours"))', 
        [name, email, hash, 'admin', null, null], function(insertErr) {
        if (insertErr) return res.status(500).json({ error: 'Insert error' });
        
        // 回傳成功
        res.status(201).json({ success: true, message: 'Admin created' });
      });
    } catch (e) { res.status(500).json({ error: 'Server error' }); }
  });
});

app.post('/api/uploads', userAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({ url: '/uploads/' + req.file.filename });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT id, name, email, role, password_hash, COALESCE(is_blocked,0) AS is_blocked FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.is_blocked) return res.status(403).json({ error: 'User is blocked' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const payload = { id: user.id, email: user.email, name: user.name, role: user.role };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, user: payload });
  });
});

app.get('/api/auth/me', (req, res) => {
  const token = getTokenFromHeader(req);
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    
    // ✅ [修改] 加入子查詢來計算 avg_rating 和 review_count
    const sql = `
      SELECT u.id, u.name, u.email, u.role, u.phone, u.address, u.created_at,
      (SELECT AVG(rating) FROM reviews WHERE seller_id = u.id) as avg_rating,
      (SELECT COUNT(*) FROM reviews WHERE seller_id = u.id) as review_count
      FROM users u
      WHERE u.id = ?
    `;

    db.get(sql, [payload.id], (err, row) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      if (!row) return res.status(404).json({ error: 'User not found' });
      res.json(row);
    });
  } catch (e) { return res.status(401).json({ error: 'Invalid token' }); }
});

// Update user profile
// Update user profile
app.put('/api/users/me', userAuth, (req, res) => {
  const uid = req.user.id;
  const { name, email, phone, address, currentPassword } = req.body;

  // 1. 先從資料庫查出目前的使用者資料 (比對用)
  db.get('SELECT * FROM users WHERE id = ?', [uid], async (err, currentUser) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!currentUser) return res.status(404).json({ error: 'User not found' });

    // 2. 判斷 Email 是否真的有變更
    // (如果前端傳來的 email 跟資料庫裡的一樣，就算沒變)
    const isEmailChanged = email && (email !== currentUser.email);

    // 定義執行更新的函式
    const doUpdate = () => {
      // 使用新值，若前端沒傳該欄位則維持原值 (避免 undefined 變成 null)
      const newName = name !== undefined ? name : currentUser.name;
      const newEmail = email !== undefined ? email : currentUser.email;
      const newPhone = phone !== undefined ? phone : currentUser.phone;
      const newAddress = address !== undefined ? address : currentUser.address;

      const sql = 'UPDATE users SET name = ?, email = ?, phone = ?, address = ? WHERE id = ?';
      db.run(sql, [newName, newEmail, newPhone, newAddress, uid], function(err) {
        if (err) return res.status(500).json({ error: 'Update DB error' });
        
        // 更新成功，回傳最新的資料給前端
        db.get('SELECT id, name, email, role, phone, address, created_at FROM users WHERE id = ?', [uid], (e, row) => {
          res.json(row);
        });
      });
    };

    // 3. 驗證邏輯
    if (isEmailChanged) {
      // --- 情況 A：Email 有變，需要嚴格檢查 ---
      
      // 檢查 Email 是否被其他人佔用
      db.get('SELECT id FROM users WHERE email = ? AND id != ?', [email, uid], async (err, row) => {
        if (row) return res.status(409).json({ error: '此 Email 已被註冊' });

        // 檢查密碼 (改 Email 必須提供密碼)
        if (!currentPassword) return res.status(400).json({ error: '更改 Email 需輸入目前密碼' });

        // 驗證密碼是否正確
        const match = await bcrypt.compare(currentPassword, currentUser.password_hash);
        if (!match) return res.status(401).json({ error: '密碼錯誤' });

        // 通過驗證，執行更新
        doUpdate();
      });
    } else {
      // --- 情況 B：Email 沒變 (只是改名字或電話) ---
      // 不需要檢查密碼，直接更新
      doUpdate();
    }
  });
});

// Admin: users
app.get('/api/admin/users', adminAuth, (req, res) => {
  const q = req.query.q || '';
  const role = req.query.role;
  let sql = 'SELECT id, name, email, role, phone, address, created_at, COALESCE(is_blocked, 0) AS is_blocked FROM users';
  const params = []; const where = [];
  if (role && role !== 'all') { where.push('role = ?'); params.push(role); }
  if (q) { where.push('(name LIKE ? OR email LIKE ?)'); params.push('%'+q+'%', '%'+q+'%'); }
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY created_at DESC';
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

app.delete('/api/admin/users/:id', adminAuth, (req, res) => {
  const id = req.params.id; const adminId = req.user.id;
  db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
    logAdminAction(adminId, 'delete_user', 'user', id, JSON.stringify({ deletedId: id }));
    res.json({ success: true });
  });
});

app.put('/api/admin/users/:id', adminAuth, (req, res) => {
  const id = req.params.id; const { name, email, role, is_blocked } = req.body; const adminId = req.user.id;
  db.run('UPDATE users SET name = ?, email = ?, role = ?, is_blocked = COALESCE(?, is_blocked) WHERE id = ?', 
    [name, email, role, (is_blocked != null ? (is_blocked?1:0):null), id], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    db.get('SELECT * FROM users WHERE id = ?', [id], (e, row) => {
      if (adminId && (is_blocked !== undefined)) {
        logAdminAction(adminId, is_blocked ? 'block_user' : 'unblock_user', 'user', id);
      }
      res.json(row);
    });
  });
});

// ✅ [新增] 管理者儀表板 API (Dashboard)
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  try {
    // 使用 Promise.all 平行執行多個 SQL 查詢，提升效能
    const [users, products, orders, sales, pending, blocked] = await Promise.all([
      // 1. 使用者總數
      new Promise((resolve, reject) => {
        db.get("SELECT COUNT(*) as count FROM users", (err, row) => err ? reject(err) : resolve(row.count));
      }),
      // 2. 商品總數
      new Promise((resolve, reject) => {
        db.get("SELECT COUNT(*) as count FROM products", (err, row) => err ? reject(err) : resolve(row.count));
      }),
      // 3. 訂單總數
      new Promise((resolve, reject) => {
        db.get("SELECT COUNT(*) as count FROM orders", (err, row) => err ? reject(err) : resolve(row.count));
      }),
      // 4. 總營業額 (加總 total_amount)
      new Promise((resolve, reject) => {
        db.get("SELECT SUM(total_amount) as total FROM orders", (err, row) => err ? reject(err) : resolve(row.total || 0));
      }),
      // 5. 待處理訂單數 (status = 'pending')
      new Promise((resolve, reject) => {
        // 注意：這裡假設你的狀態是用 'pending' (小寫)，如果資料庫存的是 'Pending' 請自行調整
        db.get("SELECT COUNT(*) as count FROM orders WHERE status = 'pending'", (err, row) => err ? reject(err) : resolve(row.count));
      }),
      // 6. 已封鎖使用者數
      new Promise((resolve, reject) => {
        db.get("SELECT COUNT(*) as count FROM users WHERE is_blocked = 1", (err, row) => err ? reject(err) : resolve(row.count));
      })
    ]);

    // 回傳 JSON 給前端
    res.json({
      users_count: users,
      products_count: products,
      orders_count: orders,
      total_sales: sales,
      pending_orders: pending,
      blocked_users: blocked
    });

  } catch (err) {
    console.error("Dashboard Error:", err);
    res.status(500).json({ error: 'Database error' });
  }
});

// ✅ [新增] 管理者取得所有商品 (包含賣家資訊)
app.get('/api/admin/products', adminAuth, (req, res) => {
  // 關聯查詢：取得商品資訊 + 賣家名字/Email
  const sql = `
    SELECT p.*, u.name as seller_name, u.email as seller_email 
    FROM products p 
    LEFT JOIN users u ON p.seller_id = u.id 
    ORDER BY p.created_at DESC
  `;
  
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

// ✅ [新增] 管理者刪除商品 API
// 注意：前端呼叫的是 /api/products/:id，我們這裡要補上對應的 Admin 路由
app.delete('/api/products/:id', adminAuth, (req, res) => {
  const id = req.params.id;
  const adminId = req.user.id;

  // 1. 先查出商品標題 (為了寫日誌)
  db.get('SELECT title FROM products WHERE id = ?', [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'Product not found' });

    const title = row.title;

    // 2. 執行刪除
    db.run('DELETE FROM products WHERE id = ?', [id], function(err) {
      if (err) return res.status(500).json({ error: 'Delete failed' });
      
      // 3. 寫入操作日誌
      logAdminAction(adminId, 'delete_product', 'product', id, JSON.stringify({ title: title }));
      
      res.json({ success: true });
    });
  });
});

// ✅ [新增] 管理者取得所有訂單 (含搜尋、篩選與格式轉換)
app.get('/api/orders', adminAuth, (req, res) => {
  const { q, status } = req.query;
  let sql = 'SELECT * FROM orders';
  const where = [];
  const params = [];

  // 1. 篩選狀態
  if (status) {
    where.push('status = ?');
    params.push(status);
  }

  // 2. 搜尋 (訂單號 或 買家Email)
  if (q) {
    where.push('(id LIKE ? OR buyer_email LIKE ?)');
    params.push(`%${q}%`, `%${q}%`);
  }

  if (where.length > 0) {
    sql += ' WHERE ' + where.join(' AND ');
  }

  sql += ' ORDER BY created_at DESC';

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });

    // 3. 資料格式處理
    const results = rows.map(row => {
      // 解析商品 JSON
      try { row.items = JSON.parse(row.items); } catch (e) { row.items = []; }
      
      // 轉換欄位名稱 (snake_case -> camelCase) 以配合前端 admin_orders.html
      row.buyerEmail = row.buyer_email;
      row.totalAmount = row.total_amount;
      row.shipName = row.ship_name;
      row.shipPhone = row.ship_phone;
      row.shipAddress = row.ship_address;
      row.cancelStatus = row.cancel_status;
      row.cancelReason = row.cancel_reason;
      
      return row;
    });

    res.json(results);
  });
});

// ✅ [新增] 管理者修改訂單狀態 (含取消)
app.put('/api/orders/:id', adminAuth, (req, res) => {
  const id = req.params.id;
  const { status, cancelStatus } = req.body; // 前端傳來的欄位
  const adminId = req.user.id;

  // 動態組裝 SQL
  let sql = 'UPDATE orders SET status = ?';
  const params = [status];

  if (cancelStatus) {
    sql += ', cancel_status = ?';
    params.push(cancelStatus);
  }
  
  // 如果狀態改成 canceled，記錄取消時間
  if (status === 'canceled') {
    sql += ', canceled_at = datetime("now", "+8 hours")';
  }

  sql += ' WHERE id = ?';
  params.push(id);

  db.run(sql, params, function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Order not found' });
    
    // 寫入日誌
    logAdminAction(adminId, 'update_order', 'order', id, `Status changed to: ${status}`);
    res.json({ success: true });
  });
});

// ✅ [新增] 管理者刪除訂單
app.delete('/api/orders/:id', adminAuth, (req, res) => {
  const id = req.params.id;
  const adminId = req.user.id;

  db.run('DELETE FROM orders WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Order not found' });

    // 寫入日誌
    logAdminAction(adminId, 'delete_order', 'order', id);
    res.json({ success: true });
  });
});

// ✅ [新增] 管理者取得操作日誌 (含搜尋與篩選)
app.get('/api/admin/logs', adminAuth, (req, res) => {
  const { q, target_type } = req.query;
  
  // 關聯查詢：取得日誌 + 管理者名字/Email
  let sql = `
    SELECT l.*, u.name as admin_name, u.email as admin_email 
    FROM admin_logs l
    LEFT JOIN users u ON l.admin_id = u.id
  `;
  
  const where = [];
  const params = [];

  // 1. 篩選目標類型 (user, product, order)
  if (target_type) {
    where.push('l.target_type = ?');
    params.push(target_type);
  }

  // 2. 搜尋 (動作、詳情、管理者Email)
  if (q) {
    where.push('(l.action LIKE ? OR l.details LIKE ? OR u.email LIKE ?)');
    params.push(`%${q}%`, `%${q}%`, `%${q}%`);
  }

  if (where.length > 0) {
    sql += ' WHERE ' + where.join(' AND ');
  }

  sql += ' ORDER BY l.created_at DESC LIMIT 100'; // 限制最近 100 筆，避免資料過多

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

// Public user info
/* server.js */

// ✅ [修改] 取得使用者公開資料 (加入平均評分計算)
app.get('/api/users/:id', (req, res) => {
  const userId = req.params.id;
  
  // 使用 SQL 子查詢直接算出 avg_rating (平均分) 和 review_count (總筆數)
  const sql = `
    SELECT u.id, u.name, u.email,
    (SELECT AVG(rating) FROM reviews WHERE seller_id = u.id) as avg_rating,
    (SELECT COUNT(*) FROM reviews WHERE seller_id = u.id) as review_count
    FROM users u
    WHERE u.id = ?
  `;

  db.get(sql, [userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'Not found' });
    res.json(row);
  });
});

// Products
app.get('/api/products', (req, res) => {
  const seller = req.query.seller_id;
  let sql = 'SELECT * FROM products';
  const params = [];
  if (seller) { sql += ' WHERE seller_id = ?'; params.push(seller); }
  sql += ' ORDER BY created_at DESC';
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

app.get('/api/products/:id', (req, res) => {
  db.get('SELECT * FROM products WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'Not found' });
    try { row.images = row.images ? JSON.parse(row.images) : null; } catch(e) { row.images = null; }
    res.json(row);
  });
});

// Admin create product
app.post('/api/products', adminAuth, (req, res) => {
  const { title, description, price, quantity, seller_id, category, image, images } = req.body;
  const adminId = req.user.id;
  const imagesTxt = images ? JSON.stringify(images) : null;
  
  db.run('INSERT INTO products (title, description, price, quantity, seller_id, category, image, images, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime("now", "+8 hours"))', 
    [title, description || '', price || 0, quantity || 0, seller_id || null, category || null, image || null, imagesTxt], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    db.get('SELECT * FROM products WHERE id = ?', [this.lastID], (e, row) => {
      logAdminAction(adminId, 'create_product', 'product', row.id, JSON.stringify({ title: row.title }));
      res.status(201).json(row);
    });
  });
});

// Seller create product
app.post('/api/seller/products', userAuth, (req, res) => {
  const user = req.user;
  if (!user || user.role !== 'seller') return res.status(403).json({ error: 'Seller role required' });
  const seller_id = user.id;
  const { title, description, price, quantity, stock, category, image, images } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });

  const finalStock = (stock !== undefined && stock !== null) ? stock : (quantity || 0);
  const imagesTxt = images && Array.isArray(images) ? JSON.stringify(images) : (typeof images === 'string' ? images : null);
  const imageVal = image || (images && images.length ? images[0] : null);

  db.run(
    'INSERT INTO products (title, description, price, quantity, stock, seller_id, category, image, images, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime("now", "+8 hours"))',
    [title, description || '', price || 0, finalStock, finalStock, seller_id, category || null, imageVal || null, imagesTxt], 
    function(err) {
      if (err) return res.status(500).json({ error: 'DB error' });
      db.get('SELECT * FROM products WHERE id = ?', [this.lastID], (e, row) => {
        try { row.images = row.images ? JSON.parse(row.images) : null; } catch(_) { row.images = null; }
        res.status(201).json(row);
      });
    }
  );
});

// Update product
app.put('/api/seller/products/:id', sellerAuth, (req, res) => {
  const id = req.params.id; const { title, description, price, quantity, stock, category, image, images } = req.body;
  const sellerId = req.user.id;
  db.get('SELECT * FROM products WHERE id = ?', [id], (err, product) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!product) return res.status(404).json({ error: 'Not found' });
    if (product.seller_id !== sellerId) return res.status(403).json({ error: 'Forbidden' });

    const finalStock = (stock !== undefined && stock !== null) ? stock : (quantity || 0);
    const imagesTxt = images && Array.isArray(images) ? JSON.stringify(images) : null;

    db.run(
      'UPDATE products SET title=?, description=?, price=?, quantity=?, stock=?, category=COALESCE(?, category), image=COALESCE(?, image), images=COALESCE(?, images) WHERE id=?',
      [title, description, price, finalStock, finalStock, category||null, image||null, imagesTxt, id],
      function(uErr) {
        if (uErr) return res.status(500).json({ error: 'DB error' });
        db.get('SELECT * FROM products WHERE id = ?', [id], (e, row) => {
          try { row.images = row.images ? JSON.parse(row.images) : null; } catch(_) {}
          res.json(row);
        });
      }
    );
  });
});

app.delete('/api/seller/products/:id', sellerAuth, (req, res) => {
  const id = req.params.id; const sellerId = req.user.id;
  db.run('DELETE FROM products WHERE id = ? AND seller_id = ?', [id, sellerId], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  });
});

// Orders

function dbGet(sql, params) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

// Create Order (Checkout)
app.post('/api/orders', userAuth, async (req, res) => {
  const user = req.user;
  const { items, shipName, shipPhone, shipAddress } = req.body;
  // 注意：前端傳來的 totalAmount 是總金額，但因為我們要拆單，所以需要針對每個賣家重新計算子訂單金額。

  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Items required' });
  }

  try {
    // 1. 將商品依照 sellerId 分組
    const ordersBySeller = {};
    
    for (const item of items) {
      // 相容 sellerId 或 seller_id
      const sid = item.sellerId || item.seller_id;
      if (!sid) throw new Error(`商品 "${item.title}" 資料異常，缺少賣家資訊`);

      if (!ordersBySeller[sid]) {
        ordersBySeller[sid] = {
          items: [],
          total: 0
        };
      }
      ordersBySeller[sid].items.push(item);
    }

    const createdOrderIds = [];

    // 2. 針對每一組 (每一個賣家) 建立一筆訂單
    // 使用 for...of 迴圈搭配 await 確保依序執行，避免資料庫鎖定問題
    for (const sellerId of Object.keys(ordersBySeller)) {
      const group = ordersBySeller[sellerId];
      const groupItems = group.items;
      let groupTotal = 0;

      // 2-1. 檢查庫存並計算該張訂單的總金額
      for (const item of groupItems) {
        const productId = item.productId || item.id;
        const buyQty = Number(item.qty) || 1;
        
        // 查庫存
        const product = await dbGet('SELECT title, stock, price FROM products WHERE id = ?', [productId]);
        
        if (!product) throw new Error(`商品 ID ${productId} 不存在`);
        if (product.stock < buyQty) throw new Error(`商品 "${product.title}" 庫存不足 (剩餘: ${product.stock}, 欲購買: ${buyQty})`);
        
        // 累加金額 (使用前端傳來的價格或資料庫價格皆可，這裡沿用前端傳遞的 price 以保持一致性)
        groupTotal += (Number(item.price) * buyQty);
      }

      // 2-2. 寫入訂單 (Orders)
      const sqlOrder = `
        INSERT INTO orders (buyer_id, buyer_email, items, total_amount, status, ship_name, ship_phone, ship_address, cancellation_rejected, created_at) 
        VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, 0, datetime("now", "+8 hours"))
      `;
      const itemsJson = JSON.stringify(groupItems);
      
      const result = await dbRun(sqlOrder, [
        user.id, 
        user.email || '', 
        itemsJson, 
        groupTotal, 
        shipName, 
        shipPhone, 
        shipAddress
      ]);
      
      const newOrderId = result.lastID;
      createdOrderIds.push(newOrderId);

      // 2-3. 寫入訂單明細 (Order Items) 並扣除庫存
      for (const item of groupItems) {
        const productId = item.productId || item.id;
        const qty = Number(item.qty) || 1;

        await dbRun(
          'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)', 
          [newOrderId, productId, qty, item.price]
        );
        
        await dbRun('UPDATE products SET stock = stock - ? WHERE id = ?', [qty, productId]);
      }
    }

    // 全部成功
    res.status(201).json({ success: true, message: 'Orders created', orderIds: createdOrderIds });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Server error during checkout' });
  }
});

// ✅ [新增] 買家完成訂單 (Buy Complete Order)
app.put('/api/orders/:id/complete', userAuth, (req, res) => {
  const uid = req.user.id;
  const oid = req.params.id;
  
  // 確認訂單屬於該買家
  db.get('SELECT * FROM orders WHERE id = ? AND buyer_id = ?', [oid, uid], (err, order) => {
    if(err || !order) return res.status(404).json({error:'Order not found or access denied'});
    
    // 只有「已出貨」狀態才能改為「已完成」
    const currentStatus = (order.status || '').toLowerCase();
    if(currentStatus !== 'shipped') {
      return res.status(400).json({error:'只有已出貨的訂單才能標記為已完成'});
    }
    
    db.run('UPDATE orders SET status = ? WHERE id = ?', ['Completed', oid], (e)=>{
      if(e) return res.status(500).json({error:'DB Error'});
      res.json({success:true, message: '訂單已完成'});
    });
  });
});

app.get('/api/orders/my', userAuth, (req, res) => {
  const uid = req.user.id;
  db.all('SELECT * FROM orders WHERE buyer_id = ? ORDER BY created_at DESC', [uid], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    const out = rows.map(r => ({ ...r, items: r.items?JSON.parse(r.items):[] }));
    res.json(out);
  });
});

// Buyer Cancel Request
app.put('/api/orders/:id/cancel-request', userAuth, (req, res) => {
  const orderId = req.params.id; const { cancelReason } = req.body;
  db.get('SELECT cancellation_rejected, status FROM orders WHERE id = ?', [orderId], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Order not found' });
    if (row.cancellation_rejected == 1) return res.status(400).json({ error: "已拒絕過，無法再次申請" });
    
    db.run("UPDATE orders SET status='Cancellation Requested', cancel_status='Requested', cancel_reason=?, prev_status=? WHERE id=?", 
      [cancelReason, row.status, orderId], function(e){
      if(e) return res.status(500).json({error:e.message});
      res.json({ success: true });
    });
  });
});

// Seller Orders
function normId(v) { return v===null||v===undefined ? '' : String(v); }

app.get('/api/seller/orders/my', sellerAuth, (req, res) => {
  const sellerId = normId(req.user.id);
  db.all('SELECT * FROM orders ORDER BY created_at DESC', [], (err, orders) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    const out = orders.map(o => {
      let items = []; try { items = JSON.parse(o.items); } catch {}
      const myItems = items.filter(i => normId(i.sellerId || i.seller_id) === sellerId);
      if (myItems.length === 0) return null;
      const total = myItems.reduce((acc, cur) => acc + (Number(cur.price)*Number(cur.qty)||0), 0);
      return { ...o, items: myItems, totalAmount: total }; 
    }).filter(Boolean);
    res.json(out);
  });
});

// Seller Approve/Reject Cancel
app.put('/api/seller/orders/:id/cancel', sellerAuth, (req, res) => {
  const orderId = req.params.id;
  const { action } = req.body; // 'approve' or 'reject'
  const sellerId = req.user.id; // 取得賣家 ID (發送通知用)

  if (action === 'approve') {
    // ... (同意取消的部分保持不變) ...
    db.get('SELECT items FROM orders WHERE id = ?', [orderId], (err, row) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      if (!row) return res.status(404).json({ error: 'Order not found' });

      let items = [];
      try { items = JSON.parse(row.items); } catch(e) {}

      // 回補庫存
      items.forEach(item => {
        const pid = item.productId || item.id;
        const qty = Number(item.qty) || 0;
        if (pid && qty > 0) {
          db.run('UPDATE products SET stock = stock + ? WHERE id = ?', [qty, pid], (e) => {
            if (e) console.error(`[Stock Restore] Failed for pid=${pid}`, e);
          });
        }
      });

      const sql = `UPDATE orders SET status = 'Cancelled', cancel_status = 'Approved', canceled_at = datetime("now", "+8 hours") WHERE id = ?`;
      db.run(sql, [orderId], function(updErr) {
        if(updErr) return res.status(500).json({ error: updErr.message });
        res.json({ message: "已同意取消，庫存已回補" });
      });
    });

  } else if (action === 'reject') {
    // ✅ [修改] 這裡多選取 buyer_id，以便發送通知
    db.get('SELECT prev_status, buyer_id FROM orders WHERE id = ?', [orderId], (err, row) => {
      if(err) return res.status(500).json({ error: "DB Error" });
      if(!row) return res.status(404).json({ error: "Order not found" });
      
      // 狀態回復邏輯
      let originalStatus = (row && row.prev_status) ? row.prev_status : '已成立';
      if (originalStatus === '已付款') originalStatus = '已成立'; 

      const sql = `UPDATE orders SET status = ?, cancel_status = 'Rejected', cancellation_rejected = 1 WHERE id = ?`;
      db.run(sql, [originalStatus, orderId], function(updateErr) {
        if(updateErr) return res.status(500).json({ error: updateErr.message });

        // ✅ [新增] 自動發送聊天訊息通知買家
        const buyerId = row.buyer_id;
        const msgContent = `您的取消訂單申請（訂單 #${orderId}）已被賣家拒絕，訂單狀態已回復為原狀態。`;

        const msgSql = `INSERT INTO chat_messages (room_id, sender_id, receiver_id, content, product_id, order_id, created_at) VALUES (0, ?, ?, ?, 0, ?, datetime('now', '+8 hours'))`;
        
        db.run(msgSql, [sellerId, buyerId, msgContent, orderId], function(msgErr) {
            if (!msgErr) {
                // 透過 Socket.io 即時推播給買家
                const msgData = {
                    id: this.lastID,
                    sender_id: sellerId,
                    receiver_id: buyerId,
                    content: msgContent,
                    product_id: 0,
                    order_id: orderId,
                    created_at: new Date().toISOString()
                };
                io.to(String(buyerId)).emit('receiveMessage', msgData);
            }
        });

        res.json({ message: `已拒絕取消，訂單回復為 ${originalStatus}，並已通知買家。` });
      });
    });
  } else {
    res.status(400).json({ error: "Unknown action" });
  }
});

app.put('/api/seller/orders/:id/status', sellerAuth, (req, res) => {
  const orderId = req.params.id; const { newStatus } = req.body;
  db.run('UPDATE orders SET status = ? WHERE id = ?', [newStatus, orderId], function(err) {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json({ success: true, message: `狀態已更新為 ${newStatus}` });
  });
});

app.get('/api/cart', userAuth, (req, res) => {
  const uid = req.user.id;
  const sql = `
    SELECT c.*, p.stock 
    FROM cart_items c
    LEFT JOIN products p ON c.product_id = p.id
    WHERE c.user_id = ? 
    ORDER BY c.created_at DESC
  `;
  db.all(sql, [uid], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    const out = rows.map(r => ({ 
      id: r.id, 
      productId: r.product_id, 
      title: r.title, 
      price: r.price, 
      qty: r.qty, 
      stock: r.stock,
      image: r.image, 
      sellerId: r.seller_id 
    }));
    res.json(out);
  });
});

app.post('/api/cart/items', userAuth, (req, res) => {
  const uid = req.user.id;
  const { productId, title, price, qty, image, sellerId } = req.body;
  
  db.get('SELECT id, qty FROM cart_items WHERE user_id = ? AND product_id = ?', [uid, productId], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (row) {
      const incomingQty = Number(qty) || 1;
      const newQty = row.qty + incomingQty;
      db.run('UPDATE cart_items SET qty = ? WHERE id = ?', [newQty, row.id], function(e) {
        if (e) return res.status(500).json({ error: 'DB error' });
        res.json({ success: true });
      });
    } else {
      db.run('INSERT INTO cart_items (user_id, product_id, title, price, qty, image, seller_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, datetime("now", "+8 hours"))', 
        [uid, productId, title, price, qty||1, image, sellerId], function(e2) {
        if (e2) return res.status(500).json({ error: 'DB error' });
        res.status(201).json({ success: true, id: this.lastID });
      });
    }
  });
});

app.put('/api/cart/items/:productId', userAuth, (req, res) => {
  const uid = req.user.id; const pid = req.params.productId; const { qty } = req.body;
  db.run('UPDATE cart_items SET qty = ? WHERE user_id = ? AND product_id = ?', [qty, uid, pid], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ success: true });
  });
});

app.delete('/api/cart/items/:productId', userAuth, (req, res) => {
  const uid = req.user.id; const pid = req.params.productId;
  db.run('DELETE FROM cart_items WHERE user_id = ? AND product_id = ?', [uid, pid], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ success: true });
  });
});

app.delete('/api/cart/clear', userAuth, (req, res) => {
  db.run('DELETE FROM cart_items WHERE user_id = ?', [req.user.id], (err) => {
    res.json({ success: true });
  });
});

// ✅ [新增] 通用聊天室列表 API (買家/賣家通用)
app.get('/api/chats', userAuth, (req, res) => {
  const myId = req.user.id;

  const sql = `
    SELECT * FROM chat_messages 
    WHERE sender_id = ? OR receiver_id = ? 
    ORDER BY created_at DESC
  `;

  db.all(sql, [myId, myId], async (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });

    const chatMap = new Map();

    for (const row of rows) {
      const isMeSender = (row.sender_id === myId);
      const otherId = isMeSender ? row.receiver_id : row.sender_id;
      
      const pid = row.product_id || 0;
      const oid = row.order_id || 0; // ✅ 取得 order_id

      // 建立唯一鍵值：人 + 商品 + 訂單
      const uniqueKey = `${otherId}_${pid}_${oid}`;

      if (!chatMap.has(uniqueKey)) {
        chatMap.set(uniqueKey, {
          targetId: otherId,
          productId: pid,
          orderId: oid,    // ✅ 存入 Map
          lastMessage: row.content,
          timestamp: row.created_at,
          displayName: 'Loading...', 
          productTitle: '' 
        });
      }
    }

    const results = Array.from(chatMap.values());

    await Promise.all(results.map(async (chat) => {
      // A. 查對方名字
      const user = await new Promise(resolve => {
        db.get('SELECT name FROM users WHERE id = ?', [chat.targetId], (e, r) => resolve(r));
      });
      chat.displayName = user ? user.name : `用戶 #${chat.targetId}`;
      
      // B. 查商品標題 (如果有 product_id 且沒有 order_id)
      if (chat.productId > 0 && chat.orderId === 0) {
        const product = await new Promise(resolve => {
          db.get('SELECT title FROM products WHERE id = ?', [chat.productId], (e, r) => resolve(r));
        });
        chat.productTitle = product ? product.title : '未知商品';
      }
      // C. (可選) 如果需要查訂單詳情也可以在這裡查，但我們直接顯示 ID 即可
    }));

    res.json(results);
  });
});

// ✅ [新增] 提交評價 API
app.post('/api/reviews', userAuth, (req, res) => {
  const { orderId, sellerId, rating, comment } = req.body;
  const buyerId = req.user.id;

  if (!orderId || !sellerId || !rating) return res.status(400).json({ error: 'Missing fields' });
  if (rating < 1 || rating > 5) return res.status(400).json({ error: 'Rating must be 1-5' });

  // 1. 檢查訂單是否已完成且屬於該買家
  db.get('SELECT status FROM orders WHERE id = ? AND buyer_id = ?', [orderId, buyerId], (err, order) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    if (order.status !== 'Completed') return res.status(400).json({ error: '只有「已完成」的訂單才能評價' });

    // 2. 寫入評價
    const sql = `INSERT INTO reviews (order_id, buyer_id, seller_id, rating, comment, created_at) VALUES (?, ?, ?, ?, ?, datetime('now', '+8 hours'))`;
    db.run(sql, [orderId, buyerId, sellerId, rating, comment || ''], function(insertErr) {
      if (insertErr) {
        if (insertErr.message.includes('UNIQUE')) return res.status(409).json({ error: '此訂單已評價過' });
        return res.status(500).json({ error: 'Review failed' });
      }
      res.json({ success: true, message: '評價成功' });
    });
  });
});

// ✅ [修改] 取得使用者公開資料 (加入平均評分)
// 請找到原本的 app.get('/api/users/:id') 並替換成這個版本
app.get('/api/users/:id', (req, res) => {
  const userId = req.params.id;
  
  // 這裡用子查詢算出平均分 (avg_rating) 和 總評價數 (review_count)
  const sql = `
    SELECT u.id, u.name, u.email,
    (SELECT AVG(rating) FROM reviews WHERE seller_id = u.id) as avg_rating,
    (SELECT COUNT(*) FROM reviews WHERE seller_id = u.id) as review_count
    FROM users u
    WHERE u.id = ?
  `;

  db.get(sql, [userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'Not found' });
    res.json(row);
  });
});

// ✅ [修改] 買家取得我的訂單 (加入 is_reviewed 欄位，判斷是否評過了)
// 請找到 app.get('/api/orders/my') 並修改 SQL
app.get('/api/orders/my', userAuth, (req, res) => {
  const uid = req.user.id;
  // LEFT JOIN reviews 來檢查是否已經有評價紀錄
  const sql = `
    SELECT o.*, 
           (CASE WHEN r.id IS NOT NULL THEN 1 ELSE 0 END) as is_reviewed
    FROM orders o
    LEFT JOIN reviews r ON o.id = r.order_id
    WHERE o.buyer_id = ? 
    ORDER BY o.created_at DESC
  `;
  
  db.all(sql, [uid], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    const out = rows.map(r => ({ ...r, items: r.items ? JSON.parse(r.items) : [] }));
    res.json(out);
  });
});

// 1. 初始化時確保資料表有 reply 欄位 (請將這段放在 start() 或資料庫初始化的地方)
db.run("ALTER TABLE reviews ADD COLUMN reply TEXT", [], (err)=>{});
db.run("ALTER TABLE reviews ADD COLUMN reply_at DATETIME", [], (err)=>{});

// 2. ✅ [新增] 讀取某位賣家的所有評價 (公開，給買家看)
// ✅ [修改] 讀取某位賣家的所有評價 (加入商品名稱解析)
app.get('/api/users/:sellerId/reviews', (req, res) => {
  const sellerId = req.params.sellerId;
  
  // 關聯 orders 表來取得 items
  const sql = `
    SELECT r.*, u.name as buyer_name, u.email as buyer_email, o.items
    FROM reviews r
    LEFT JOIN users u ON r.buyer_id = u.id
    LEFT JOIN orders o ON r.order_id = o.id
    WHERE r.seller_id = ?
    ORDER BY r.created_at DESC
  `;
  
  db.all(sql, [sellerId], (err, rows) => {
    if(err) return res.status(500).json({error: 'DB error'});
    
    // 處理每一筆評價，解析 items JSON 取得商品標題
    const results = rows.map(row => {
        let productTitle = '未知商品';
        try {
            const items = JSON.parse(row.items);
            if (Array.isArray(items)) {
                // 只抓取屬於這位賣家的商品 (雖然通常訂單對應單一賣家，但做個保險)
                // 這裡假設 items 裡面的 sellerId 是字串或數字，統一轉字串比對
                const myItems = items.filter(i => String(i.sellerId || i.seller_id) === String(sellerId));
                
                // 如果有找到對應賣家的商品，就用那些商品的標題；否則顯示全部
                const targetItems = myItems.length > 0 ? myItems : items;
                
                // 組合標題 (例如: "商品A, 商品B")
                productTitle = targetItems.map(i => i.title).join(', ');
            }
        } catch (e) {
            // JSON 解析失敗或欄位為空，維持 '未知商品'
        }
        
        return {
            ...row,
            product_title: productTitle // 新增欄位回傳給前端
        };
    });

    res.json(results);
  });
});

// 3. ✅ [新增] 賣家讀取自己收到的評價 (私有，給賣家後台看)
app.get('/api/seller/reviews/my', sellerAuth, (req, res) => {
  const sellerId = req.user.id;
  const sql = `
    SELECT r.*, u.name as buyer_name 
    FROM reviews r
    LEFT JOIN users u ON r.buyer_id = u.id
    WHERE r.seller_id = ?
    ORDER BY r.created_at DESC
  `;
  db.all(sql, [sellerId], (err, rows) => {
    if(err) return res.status(500).json({error: 'DB error'});
    res.json(rows);
  });
});

// 4. ✅ [新增] 賣家回覆評價
app.put('/api/seller/reviews/:id/reply', sellerAuth, (req, res) => {
  const reviewId = req.params.id;
  const sellerId = req.user.id;
  const { replyContent } = req.body;

  if(!replyContent) return res.status(400).json({error: '回覆內容不能為空'});

  // 確保是評論自己的評價
  db.run(
    'UPDATE reviews SET reply = ?, reply_at = datetime("now", "+8 hours") WHERE id = ? AND seller_id = ?',
    [replyContent, reviewId, sellerId],
    function(err) {
      if(err) return res.status(500).json({error: 'DB error'});
      if(this.changes === 0) return res.status(404).json({error: 'Review not found or permission denied'});
      res.json({success: true});
    }
  );
});

app.post('/api/auth/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: '請輸入 Email' });

  db.get('SELECT id FROM users WHERE email = ?', [email], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: '找不到此 Email 註冊的帳號' });

    // 產生 Token (有效期限 1 小時)
    const token = crypto.randomBytes(20).toString('hex');
    const expires = Date.now() + 3600000; // 1 hour from now

    db.run('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?', [token, expires, row.id], (e) => {
      if (e) return res.status(500).json({ error: 'DB error' });
      
      // 因為沒有 Email Server，直接回傳連結給前端顯示
      const resetLink = `/reset_password_final.html?token=${token}`;
      res.json({ 
        success: true, 
        message: '重設信件已發送 (模擬)', 
        resetLink: resetLink 
      });
    });
  });
});

// ✅ [新增] 重設密碼 - 執行更新
app.post('/api/auth/reset-password', (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: '資料不完整' });
  if (newPassword.length < 6) return res.status(400).json({ error: '密碼長度需大於 6 碼' });

  db.get('SELECT id, reset_expires FROM users WHERE reset_token = ?', [token], async (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(400).json({ error: '連結無效或已過期' });
    
    if (Date.now() > row.reset_expires) {
      return res.status(400).json({ error: '連結已過期，請重新申請' });
    }

    try {
      const hash = await bcrypt.hash(newPassword, 10);
      db.run('UPDATE users SET password_hash = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?', [hash, row.id], (e) => {
        if (e) return res.status(500).json({ error: 'DB error' });
        res.json({ success: true, message: '密碼重設成功，請重新登入' });
      });
    } catch (e) {
      res.status(500).json({ error: 'Hashing error' });
    }
  });
});

const port = process.env.PORT || 3000;
async function start() {
  try {
    await runMigration();
    // 確保 chat_messages 有 receiver_id 欄位 (簡單修補)
    db.run("ALTER TABLE chat_messages ADD COLUMN receiver_id INTEGER", [], (err)=>{});
    db.run("ALTER TABLE users ADD COLUMN reset_token TEXT", [], ()=>{});
    db.run("ALTER TABLE users ADD COLUMN reset_expires INTEGER", [], ()=>{});
    server.listen(port, () => {
      console.log(`Server running on http://localhost:${port}`);
    });
  } catch (e) {
    console.error(e);
  }
}
start();
