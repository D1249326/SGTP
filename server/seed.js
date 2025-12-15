const bcrypt = require('bcryptjs');
const { db, runMigration } = require('./db');

// Promisify helper for sqlite3
function runSql(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function getSql(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function allSql(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

async function ensureUser({ name, email, password, role='buyer', phone=null, address=null }){
  const existing = await getSql('SELECT id FROM users WHERE email = ?', [email]);
  if (existing) return existing.id;
  const hash = await bcrypt.hash(password, 10);
  const r = await runSql('INSERT INTO users (name, email, password_hash, role, phone, address) VALUES (?, ?, ?, ?, ?, ?)', [name, email, hash, role, phone, address]);
  return r.lastID;
}

async function ensureProduct({ title, description='', price=0, quantity=0, seller_id=null, category=null, images=null }){
  // avoid duplicates by title+seller
  const existing = await getSql('SELECT id, category, image, images FROM products WHERE title = ? AND seller_id = ?', [title, seller_id]);
  const imagesTxt = images && Array.isArray(images) ? JSON.stringify(images) : (typeof images === 'string' ? images : null);
  const image = images && images[0] ? images[0] : null;
  if (existing) {
    // update missing fields if provided
    await runSql('UPDATE products SET category = COALESCE(?, category), image = COALESCE(?, image), images = COALESCE(?, images) WHERE id = ?', [category, image, imagesTxt, existing.id]);
    return existing.id;
  }
  const r = await runSql('INSERT INTO products (title, description, price, quantity, seller_id, category, image, images) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [title, description, price, quantity, seller_id, category, image, imagesTxt]);
  return r.lastID;
}

async function seed(){
  console.log('Running migrations (if needed)');
  await runMigration();

  try{
    console.log('Creating users...');
    const adminId = await ensureUser({ name: 'Admin User', email: 'admin@example.com', password: 'adminpass', role: 'admin' });
    const seller1 = await ensureUser({ name: 'Alice Seller', email: 'alice@sellers.com', password: 'sellerpass', role: 'seller', phone: '0911-111111', address: '台北市' });
    const seller2 = await ensureUser({ name: 'Bob Seller', email: 'bob@sellers.com', password: 'sellerpass', role: 'seller', phone: '0922-222222', address: '新北市' });
    const buyer1 = await ensureUser({ name: 'Charlie Buyer', email: 'charlie@buyers.com', password: 'buyerpass', role: 'buyer', phone: '0933-333333', address: '台中市' });
    const buyer2 = await ensureUser({ name: 'Dana Buyer', email: 'dana@buyers.com', password: 'buyerpass', role: 'buyer', phone: '0944-444444', address: '高雄市' });

    console.log('Users created: ', { adminId, seller1, seller2, buyer1, buyer2 });

    console.log('Creating products...');
    const p1 = await ensureProduct({ title: 'Vintage Lamp', description: '古董檯燈，狀況良好', price: 1200, quantity: 2, seller_id: seller1, category: '生活雜務', images: ['https://via.placeholder.com/400x300?text=Vintage+Lamp'] });
    const p2 = await ensureProduct({ title: 'Used Bicycle', description: '城市通勤用二手單車', price: 3000, quantity: 1, seller_id: seller1, category: '運動器材', images: ['https://via.placeholder.com/400x300?text=Used+Bicycle'] });
    const p3 = await ensureProduct({ title: 'Leather Jacket', description: '綁帶皮衣，幾乎全新', price: 2500, quantity: 1, seller_id: seller2, category: '衣服', images: ['https://via.placeholder.com/400x300?text=Leather+Jacket'] });
    const p4 = await ensureProduct({ title: 'Coffee Table', description: '木製咖啡桌，帶刮痕', price: 800, quantity: 3, seller_id: seller2, category: '生活雜務', images: ['https://via.placeholder.com/400x300?text=Coffee+Table'] });
    const p5 = await ensureProduct({ title: 'Set of Mugs', description: '四入陶瓷杯', price: 400, quantity: 5, seller_id: seller1, category: '生活雜務', images: ['https://via.placeholder.com/400x300?text=Set+of+Mugs'] });
    const p6 = await ensureProduct({ title: 'Wireless Headphones', description: '藍牙耳機，功能正常', price: 1500, quantity: 2, seller_id: seller2, category: '3C產品', images: ['https://via.placeholder.com/400x300?text=Wireless+Headphones'] });

    console.log('Products created: ', { p1, p2, p3, p4, p5, p6 });

    console.log('\nSeed completed. Test accounts:');
    console.log('Admin: admin@example.com / adminpass');
    console.log('Sellers: alice@sellers.com / sellerpass  ,  bob@sellers.com / sellerpass');
    console.log('Buyers: charlie@buyers.com / buyerpass  ,  dana@buyers.com / buyerpass');

    // Print some totals
    const users = await allSql('SELECT id, email, role FROM users');
    const products = await allSql('SELECT id, title, seller_id FROM products');
    console.log('\nUsers:'); console.table(users);
    console.log('Products:'); console.table(products);

    // do not call process.exit here so seed can be used programmatically
    return { users, products };
  }catch(err){
    console.error('Seed error:', err);
    throw err;
  }
}

// allow running seed.js directly for CLI
if (require.main === module) {
  seed().then(()=> process.exit(0)).catch(()=> process.exit(1));
}

module.exports = { seed };
