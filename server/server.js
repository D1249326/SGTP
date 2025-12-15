const express = require('express');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { db, runMigration } = require('./db');

const path = require('path');
const multer = require('multer');
const app = express();
app.use(cors());
app.use(express.json());

// Serve project static files (so GET / will return index.html from project root)
const publicRoot = path.join(__dirname, '..');
app.use(express.static(publicRoot));

// Serve uploaded files from /uploads
const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!require('fs').existsSync(uploadsDir)) require('fs').mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir));

// configure multer for uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, uploadsDir); },
  filename: function (req, file, cb) { const ts = Date.now(); const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_'); cb(null, ts + '_' + safe); }
});
const upload = multer({ storage });

// optional: friendly root message if no index.html
app.get('/', (req, res, next) => {
  const indexPath = path.join(publicRoot, 'index.html');
  if (require('fs').existsSync(indexPath)) return next();
  res.send('<h2>SGTP API Server</h2><p>API is available under /api/*</p>');
});

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';

// Perform migrations and optional auto-seed before starting the server
// (runMigration now returns a Promise)

async function initServer(){
  try{
    await runMigration();

    // check whether users table has any rows; if none, run seed automatically
    const userCount = await new Promise((resolve, reject) => {
      db.get('SELECT COUNT(*) AS cnt FROM users', [], (err, row) => {
        if (err) return reject(err);
        resolve(row && row.cnt ? row.cnt : 0);
      });
    });

    if (!userCount) {
      console.log('No users found in DB — running seed to create default accounts and products');
      const seedModule = require('./seed');
      await seedModule.seed();
      console.log('Auto-seed completed');
    }
  }catch(err){
    console.error('Error during migration/seed:', err);
    // continue to start server so user can inspect logs; do not crash
  }
}

// auth middleware to protect admin routes
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
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// General authenticated user middleware (no role check)
function userAuth(req, res, next) {
  const token = getTokenFromHeader(req);
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // verify in DB whether user is blocked
    db.get('SELECT COALESCE(is_blocked,0) AS is_blocked FROM users WHERE id = ?', [payload.id], (err, row) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      if (row && row.is_blocked) return res.status(403).json({ error: 'User is blocked' });
      req.user = payload;
      next();
    });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Seller auth (require role === 'seller')
function sellerAuth(req, res, next) {
  const token = getTokenFromHeader(req);
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'seller') return res.status(403).json({ error: 'Requires seller role' });
    // check blocked
    db.get('SELECT COALESCE(is_blocked,0) AS is_blocked FROM users WHERE id = ?', [payload.id], (err, row) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      if (row && row.is_blocked) return res.status(403).json({ error: 'User is blocked' });
      req.user = payload;
      next();
    });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Helper: record admin actions for audit trail (non-blocking)
function logAdminAction(adminId, action, targetType = null, targetId = null, details = null) {
  try {
    console.log('logAdminAction called:', { adminId, action, targetType, targetId });
    db.run('INSERT INTO admin_logs (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)', [adminId, action, targetType, targetId, details], function(err) {
      if (err) console.error('Failed to write admin log:', err);
    });
  } catch (e) {
    console.error('Error in logAdminAction:', e);
  }
}

// Create user (general)
app.post('/api/users/register', (req, res) => {
  const { name, email, password, role, phone, address } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });

  db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'DB error' }); }
    if (row) return res.status(409).json({ error: 'Email exists' });

    try {
      const hash = await bcrypt.hash(password, 10);
      const r = role || 'buyer';
      db.run('INSERT INTO users (name, email, password_hash, role, phone, address) VALUES (?, ?, ?, ?, ?, ?)', [name, email, hash, r, phone || null, address || null], function(insertErr) {
        if (insertErr) { console.error(insertErr); return res.status(500).json({ error: 'Insert error' }); }
        const id = this.lastID;
        db.get('SELECT id, name, email, role, phone, address, created_at FROM users WHERE id = ?', [id], (getErr, user) => {
          if (getErr) { console.error(getErr); return res.status(500).json({ error: 'DB error' }); }
          res.status(201).json(user);
        });
      });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Server error' });
    }
  });
});

// Upload endpoint - authenticated users can upload images
app.post('/api/uploads', userAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const urlPath = '/uploads/' + req.file.filename;
    res.json({ url: urlPath });
  } catch (e) {
    console.error('Upload error', e);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Admin register convenience endpoint (keeps existing front-end)
app.post('/api/admin/register', (req, res) => {
  // forward to users/register with role=admin
  const body = Object.assign({}, req.body, { role: 'admin' });
  req.body = body;
  return app._router.handle(req, res, () => {});
});

// Login (returns JWT) - now checks users table
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  db.get('SELECT id, name, email, role, password_hash, COALESCE(is_blocked,0) AS is_blocked FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'DB error' }); }
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    // deny login for blocked users
    if (user.is_blocked) return res.status(403).json({ error: 'User is blocked' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const payload = { id: user.id, email: user.email, name: user.name, role: user.role };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, user: payload });
  });
});

// Return current user info from token
app.get('/api/auth/me', (req, res) => {
  const token = getTokenFromHeader(req);
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // fetch full user data from DB (including phone/address)
    db.get('SELECT id, name, email, role, phone, address, created_at FROM users WHERE id = ?', [payload.id], (err, row) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      if (!row) return res.status(404).json({ error: 'User not found' });
      res.json({ id: row.id, name: row.name, email: row.email, role: row.role, phone: row.phone, address: row.address, created_at: row.created_at });
    });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

// Update current user's profile (requires authentication)
app.put('/api/users/me', userAuth, (req, res) => {
  const uid = req.user.id;
  const { name, email, phone, address, currentPassword } = req.body;

  // If email change requested, verify currentPassword
  function doUpdate() {
    db.run('UPDATE users SET name = ?, email = ?, phone = ?, address = ? WHERE id = ?', [name || null, email || null, phone || null, address || null, uid], function(err) {
      if (err) return res.status(500).json({ error: 'DB error' });
      db.get('SELECT id, name, email, role, phone, address, created_at FROM users WHERE id = ?', [uid], (e, row) => {
        if (e) return res.status(500).json({ error: 'DB error' });
        res.json(row);
      });
    });
  }

  if (email) {
    // check if email already used by other user
    db.get('SELECT id, password_hash FROM users WHERE email = ? AND id != ?', [email, uid], (err, row) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      if (row) return res.status(409).json({ error: 'Email already in use' });
      // verify currentPassword
      if (!currentPassword) return res.status(400).json({ error: 'currentPassword required to change email' });
      db.get('SELECT password_hash FROM users WHERE id = ?', [uid], async (er, r2) => {
        if (er) return res.status(500).json({ error: 'DB error' });
        const match = await bcrypt.compare(currentPassword, r2.password_hash);
        if (!match) return res.status(401).json({ error: 'Invalid password' });
        doUpdate();
      });
    });
  } else {
    doUpdate();
  }
});

// Admin-only: list users (supports ?q=, ?role=)
app.get('/api/admin/users', adminAuth, (req, res) => {
  const q = req.query.q || '';
  const role = req.query.role;
  let sql = 'SELECT id, name, email, role, phone, address, created_at, COALESCE(is_blocked, 0) AS is_blocked FROM users';
  const params = [];
  const where = [];
  if (role && role !== 'all') { where.push('role = ?'); params.push(role); }
  if (q) { where.push('(name LIKE ? OR email LIKE ?)'); params.push('%' + q + '%', '%' + q + '%'); }
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY created_at DESC';
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    // parse images JSON if present
    const out = rows.map(r => {
      const copy = Object.assign({}, r);
      try { copy.images = copy.images ? JSON.parse(copy.images) : null; } catch(e) { copy.images = null; }
      return copy;
    });
    res.json(out);
  });
});

// Admin-only: delete user
app.delete('/api/admin/users/:id', adminAuth, (req, res) => {
  const id = req.params.id;
  const adminId = req.user && req.user.id;
  db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
    // record admin action
    if (adminId) logAdminAction(adminId, 'delete_user', 'user', id, JSON.stringify({ deletedId: id }));
    res.json({ success: true });
  });
});

// Admin-only: update user
app.put('/api/admin/users/:id', adminAuth, (req, res) => {
  const id = req.params.id;
  const { name, email, role, is_blocked } = req.body;
  const adminId = req.user && req.user.id;
  // allow updating is_blocked as 0/1 as well
  db.run('UPDATE users SET name = ?, email = ?, role = ?, is_blocked = COALESCE(?, is_blocked) WHERE id = ?', [name, email, role, (is_blocked != null ? (is_blocked ? 1 : 0) : null), id], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
    db.get('SELECT id, name, email, role, created_at FROM users WHERE id = ?', [id], (e, row) => {
      if (e) return res.status(500).json({ error: 'DB error' });
      // record block/unblock
      if (adminId && (is_blocked !== undefined && is_blocked !== null)) {
        const act = is_blocked ? 'block_user' : 'unblock_user';
        logAdminAction(adminId, act, 'user', id, JSON.stringify({ is_blocked: !!is_blocked }));
      }
      res.json(row);
    });
  });
});

// Public: get basic user info by id (name only)
app.get('/api/users/:id', (req, res) => {
  const id = req.params.id;
  db.get('SELECT id, name FROM users WHERE id = ?', [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'Not found' });
    res.json({ id: row.id, name: row.name });
  });
});

// Products CRUD
app.get('/api/products', (req, res) => {
  const seller = req.query.seller_id;
  let sql = 'SELECT * FROM products';
  const params = [];
  if (seller) {
    sql += ' WHERE seller_id = ?';
    params.push(seller);
  }
  sql += ' ORDER BY created_at DESC';
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

// Admin: products with seller info
app.get('/api/admin/products', adminAuth, (req, res) => {
  const seller = req.query.seller_id;
  let sql = `SELECT p.*, u.name AS seller_name, u.email AS seller_email FROM products p LEFT JOIN users u ON p.seller_id = u.id`;
  const params = [];
  if (seller) {
    sql += ' WHERE p.seller_id = ?';
    params.push(seller);
  }
  sql += ' ORDER BY p.created_at DESC';
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    const out = rows.map(r => { const copy = Object.assign({}, r); try { copy.images = copy.images ? JSON.parse(copy.images) : null; } catch(e) { copy.images = null; } return copy; });
    res.json(out);
  });
});

// Admin dashboard: aggregated stats
app.get('/api/admin/dashboard', adminAuth, (req, res) => {
  const sql = `SELECT 
    (SELECT COUNT(*) FROM users) AS users_count,
    (SELECT COUNT(*) FROM products) AS products_count,
    (SELECT COUNT(*) FROM orders) AS orders_count,
    (SELECT COALESCE(SUM(total_amount),0) FROM orders WHERE status IN ('paid','shipped','completed')) AS total_sales,
    (SELECT COUNT(*) FROM orders WHERE status = 'pending') AS pending_orders,
    (SELECT COUNT(*) FROM users WHERE COALESCE(is_blocked,0)=1) AS blocked_users
  `;
  db.get(sql, [], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(row);
  });
});

// Admin logs: list admin actions (supports ?q=&admin_id=&target_type=&limit=&offset=)
app.get('/api/admin/logs', adminAuth, (req, res) => {
  const q = req.query.q || '';
  const adminId = req.query.admin_id;
  const targetType = req.query.target_type;
  const limit = parseInt(req.query.limit) || 100;
  const offset = parseInt(req.query.offset) || 0;

  let sql = `SELECT l.*, u.name AS admin_name, u.email AS admin_email FROM admin_logs l LEFT JOIN users u ON l.admin_id = u.id WHERE 1=1`;
  const params = [];
  if (adminId) { sql += ' AND l.admin_id = ?'; params.push(adminId); }
  if (targetType) { sql += ' AND l.target_type = ?'; params.push(targetType); }
  if (q) { sql += ' AND (l.action LIKE ? OR l.details LIKE ?)'; params.push('%' + q + '%', '%' + q + '%'); }
  sql += ' ORDER BY l.created_at DESC LIMIT ? OFFSET ?'; params.push(limit, offset);

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

// File upload endpoint (authenticated users)
app.post('/api/uploads', userAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const url = '/uploads/' + req.file.filename;
  res.json({ url });
});

// Create product (admin)
app.post('/api/products', adminAuth, (req, res) => {
  const { title, description, price, quantity, seller_id, category, image, images } = req.body;
  const adminId = req.user && req.user.id;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const imagesTxt = images && Array.isArray(images) ? JSON.stringify(images) : (typeof images === 'string' ? images : null);
  db.run('INSERT INTO products (title, description, price, quantity, seller_id, category, image, images) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [title, description || '', price || 0, quantity || 0, seller_id || null, category || null, image || null, imagesTxt], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    db.get('SELECT * FROM products WHERE id = ?', [this.lastID], (e, row) => {
      if (e) return res.status(500).json({ error: 'DB error' });
      try { row.images = row.images ? JSON.parse(row.images) : null; } catch(_) { row.images = null; }
      // record create action
      if (adminId) logAdminAction(adminId, 'create_product', 'product', row.id, JSON.stringify({ title: row.title }));
      res.status(201).json(row);
    });
  });
});

// Create product (seller) - sellers can create their own products
app.post('/api/seller/products', sellerAuth, (req, res) => {
  const { title, description, price, quantity, category, image, images } = req.body;
  const seller_id = req.user && req.user.id;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const imagesTxt = images && Array.isArray(images) ? JSON.stringify(images) : (typeof images === 'string' ? images : null);
  const imageCover = image || (images && images[0]) || null;
  db.run('INSERT INTO products (title, description, price, quantity, seller_id, category, image, images) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [title, description || '', price || 0, quantity || 0, seller_id || null, category || null, imageCover, imagesTxt], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    db.get('SELECT * FROM products WHERE id = ?', [this.lastID], (e, row) => {
      if (e) return res.status(500).json({ error: 'DB error' });
      try { row.images = row.images ? JSON.parse(row.images) : null; } catch(_) { row.images = null; }
      res.status(201).json(row);
    });
  });
});

// Create product for sellers (authenticated sellers can use this)
app.post('/api/seller/products', userAuth, (req, res) => {
  const user = req.user;
  if (!user || user.role !== 'seller') return res.status(403).json({ error: 'Seller role required' });
  const seller_id = user.id;
  const { title, description, price, quantity, category, image, images } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const imagesTxt = images && Array.isArray(images) ? JSON.stringify(images) : (typeof images === 'string' ? images : null);
  const imageVal = image || (images && images.length ? images[0] : null);
  db.run('INSERT INTO products (title, description, price, quantity, seller_id, category, image, images) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [title, description || '', price || 0, quantity || 0, seller_id, category || null, imageVal || null, imagesTxt], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    db.get('SELECT * FROM products WHERE id = ?', [this.lastID], (e, row) => {
      if (e) return res.status(500).json({ error: 'DB error' });
      try { row.images = row.images ? JSON.parse(row.images) : null; } catch(_) { row.images = null; }
      res.status(201).json(row);
    });
  });
});

// Update product (admin)
app.put('/api/products/:id', adminAuth, (req, res) => {
  const id = req.params.id;
  const { title, description, price, quantity, category, image, images } = req.body;
  const adminId = req.user && req.user.id;
  const imagesTxt = images && Array.isArray(images) ? JSON.stringify(images) : (typeof images === 'string' ? images : null);
  db.run('UPDATE products SET title = ?, description = ?, price = ?, quantity = ?, category = COALESCE(?, category), image = COALESCE(?, image), images = COALESCE(?, images) WHERE id = ?', [title, description, price, quantity, category || null, image || null, imagesTxt, id], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
    db.get('SELECT * FROM products WHERE id = ?', [id], (e, row) => {
      if (e) return res.status(500).json({ error: 'DB error' });
      try { row.images = row.images ? JSON.parse(row.images) : null; } catch(_) { row.images = null; }
      if (adminId) logAdminAction(adminId, 'update_product', 'product', id, JSON.stringify({ title: row.title }));
      res.json(row);
    });
  });
});

// Delete product (admin)
app.delete('/api/products/:id', adminAuth, (req, res) => {
  const id = req.params.id;
  const adminId = req.user && req.user.id;
  db.run('DELETE FROM products WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
    if (adminId) logAdminAction(adminId, 'delete_product', 'product', id, JSON.stringify({ deletedId: id }));
    res.json({ success: true });
  });
});

// Orders endpoints (admin only)
// List all orders (admin) - supports ?q=&status=&limit=&offset=
app.get('/api/orders', adminAuth, (req, res) => {
  const q = req.query.q || '';
  const status = req.query.status || '';
  const limit = parseInt(req.query.limit) || 200;
  const offset = parseInt(req.query.offset) || 0;

  let sql = 'SELECT * FROM orders WHERE 1=1';
  const params = [];
  if (status) { sql += ' AND status = ?'; params.push(status); }
  if (q) { sql += ' AND (buyer_email LIKE ? OR id LIKE ?)'; params.push('%' + q + '%', '%' + q + '%'); }
  sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'; params.push(limit, offset);

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    const out = rows.map(r => {
      let items = [];
      try { items = r.items ? JSON.parse(r.items) : []; } catch(e) { items = []; }
      return {
        id: r.id,
        buyerId: r.buyer_id,
        buyerEmail: r.buyer_email,
        items,
        totalAmount: r.total_amount,
        status: r.status,
        cancelStatus: r.cancel_status,
        cancelReason: r.cancel_reason,
        shipName: r.ship_name,
        shipPhone: r.ship_phone,
        shipAddress: r.ship_address,
        created_at: r.created_at,
        canceledBy: r.canceled_by,
        canceledAt: r.canceled_at
      };
    });
    res.json(out);
  });
});

// Create order (authenticated buyer)
app.post('/api/orders', userAuth, (req, res) => {
  const user = req.user;
  const { items, totalAmount, shipName, shipPhone, shipAddress } = req.body;
  if (!Array.isArray(items) || items.length === 0) return res.status(400).json({ error: 'Items required' });

  const itemsJson = JSON.stringify(items);
  const sql = 'INSERT INTO orders (buyer_id, buyer_email, items, total_amount, status, ship_name, ship_phone, ship_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
  const params = [user.id, user.email || null, itemsJson, totalAmount || 0, 'pending', shipName || null, shipPhone || null, shipAddress || null];
  db.run(sql, params, function(err) {
    if (err) { console.error(err); return res.status(500).json({ error: 'DB error' }); }
    const id = this.lastID;
    db.get('SELECT * FROM orders WHERE id = ?', [id], (e, row) => {
      if (e) return res.status(500).json({ error: 'DB error' });
      try { row.items = row.items ? JSON.parse(row.items) : []; } catch(_) { row.items = []; }
      res.status(201).json({ id: row.id, buyerId: row.buyer_id, buyerEmail: row.buyer_email, items: row.items, totalAmount: row.total_amount, status: row.status, created_at: row.created_at });
    });
  });
});

// Get current user's orders
app.get('/api/orders/my', userAuth, (req, res) => {
  const uid = req.user.id;
  db.all('SELECT * FROM orders WHERE buyer_id = ? ORDER BY created_at DESC', [uid], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    const out = rows.map(r => { try { r.items = r.items ? JSON.parse(r.items) : []; } catch(e){ r.items = []; } return { id: r.id, buyerId: r.buyer_id, buyerEmail: r.buyer_email, items: r.items, totalAmount: r.total_amount, status: r.status, created_at: r.created_at }; });
    res.json(out);
  });
});

// Get order by id (owner or admin)
app.get('/api/orders/:id', userAuth, (req, res) => {
  const id = req.params.id;
  db.get('SELECT * FROM orders WHERE id = ?', [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'Not found' });
    // only owner or admin
    if (String(row.buyer_id) !== String(req.user.id) && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    try { row.items = row.items ? JSON.parse(row.items) : []; } catch(e) { row.items = []; }
    res.json({ id: row.id, buyerId: row.buyer_id, buyerEmail: row.buyer_email, items: row.items, totalAmount: row.total_amount, status: row.status, created_at: row.created_at });
  });
});

// Update order (admin) - supports marking as canceled and updating cancel reason/status
app.put('/api/orders/:id', adminAuth, (req, res) => {
  const id = req.params.id;
  const { status, cancelStatus, cancelReason, canceledBy } = req.body;
  const adminId = req.user && req.user.id;

  // fetch current order to compare status
  db.get('SELECT status, cancel_status FROM orders WHERE id = ?', [id], (err, before) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!before) return res.status(404).json({ error: 'Not found' });

    // When marking canceled, set canceled_at to now
    const sql = `UPDATE orders SET status = ?, cancel_status = ?, cancel_reason = ?, canceled_by = ?, canceled_at = CASE WHEN (? = 'canceled' OR ? = 'admin_canceled') THEN datetime('now') ELSE canceled_at END WHERE id = ?`;
    const params = [status || null, cancelStatus || null, cancelReason || null, canceledBy || null, status || null, cancelStatus || null, id];
    db.run(sql, params, function(upErr) {
      if (upErr) { console.error(upErr); return res.status(500).json({ error: 'DB error' }); }
      if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
      db.get('SELECT * FROM orders WHERE id = ?', [id], (e, row) => {
        if (e) return res.status(500).json({ error: 'DB error' });
        try { row.items = row.items ? JSON.parse(row.items) : []; } catch (_) { row.items = []; }
        // log status change if changed
        if (adminId) {
          const prevStatus = before.status;
          const prevCancel = before.cancel_status;
          if (status && status !== prevStatus) {
            logAdminAction(adminId, 'update_order_status', 'order', id, JSON.stringify({ from: prevStatus, to: status }));
          }
          if (cancelStatus && cancelStatus !== prevCancel) {
            logAdminAction(adminId, 'update_order_cancelStatus', 'order', id, JSON.stringify({ from: prevCancel, to: cancelStatus, reason: cancelReason }));
          }
        }
        res.json(row);
      });
    });
  });
});

// Delete order (admin)
app.delete('/api/orders/:id', adminAuth, (req, res) => {
  const id = req.params.id;
  const adminId = req.user && req.user.id;
  db.run('DELETE FROM orders WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
    if (adminId) logAdminAction(adminId, 'delete_order', 'order', id, JSON.stringify({ deletedId: id }));
    res.json({ success: true });
  });
});

// Cart endpoints (authenticated user)
// Get cart items
app.get('/api/cart', userAuth, (req, res) => {
  const uid = req.user.id;
  db.all('SELECT * FROM cart_items WHERE user_id = ? ORDER BY created_at DESC', [uid], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    const out = rows.map(r => ({ id: r.id, productId: r.product_id, title: r.title, price: r.price, qty: r.qty, image: r.image, sellerId: r.seller_id }));
    res.json(out);
  });
});

// Add or update cart item
app.post('/api/cart/items', userAuth, (req, res) => {
  const uid = req.user.id;
  const { productId, title, price, qty, image, sellerId } = req.body;
  if (!productId) return res.status(400).json({ error: 'productId required' });
  // If item exists for this user+productId, update qty, else insert
  db.get('SELECT id, qty FROM cart_items WHERE user_id = ? AND product_id = ?', [uid, productId], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (row) {
      const newQty = (qty != null) ? qty : row.qty + 1;
      db.run('UPDATE cart_items SET qty = ?, title = ?, price = ?, image = ?, seller_id = ? WHERE id = ?', [newQty, title || null, price || 0, image || null, sellerId || null, row.id], function(e) {
        if (e) return res.status(500).json({ error: 'DB error' });
        db.get('SELECT * FROM cart_items WHERE id = ?', [row.id], (er, item) => { if (er) return res.status(500).json({ error: 'DB error' }); res.json({ id: item.id, productId: item.product_id, title: item.title, price: item.price, qty: item.qty, image: item.image, sellerId: item.seller_id }); });
      });
    } else {
      db.run('INSERT INTO cart_items (user_id, product_id, title, price, qty, image, seller_id) VALUES (?, ?, ?, ?, ?, ?, ?)', [uid, productId, title || null, price || 0, qty || 1, image || null, sellerId || null], function(e2) {
        if (e2) return res.status(500).json({ error: 'DB error' });
        db.get('SELECT * FROM cart_items WHERE id = ?', [this.lastID], (er, item) => { if (er) return res.status(500).json({ error: 'DB error' }); res.status(201).json({ id: item.id, productId: item.product_id, title: item.title, price: item.price, qty: item.qty, image: item.image, sellerId: item.seller_id }); });
      });
    }
  });
});

// Update cart item qty
app.put('/api/cart/items/:productId', userAuth, (req, res) => {
  const uid = req.user.id;
  const pid = req.params.productId;
  const { qty } = req.body;
  if (qty == null) return res.status(400).json({ error: 'qty required' });
  db.run('UPDATE cart_items SET qty = ? WHERE user_id = ? AND product_id = ?', [qty, uid, pid], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  });
});

// Delete cart item
app.delete('/api/cart/items/:productId', userAuth, (req, res) => {
  const uid = req.user.id;
  const pid = req.params.productId;
  db.run('DELETE FROM cart_items WHERE user_id = ? AND product_id = ?', [uid, pid], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ success: true });
  });
});

// Clear cart
app.delete('/api/cart/clear', userAuth, (req, res) => {
  const uid = req.user.id;
  db.run('DELETE FROM cart_items WHERE user_id = ?', [uid], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ success: true });
  });
});

const port = process.env.PORT || 3000;

// initialize migrations/seed then start server
initServer().then(() => {
  app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
}).catch(err => {
  console.error('Init failed, starting server anyway:', err);
  app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
});
