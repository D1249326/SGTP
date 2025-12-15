// smoke_orders_admin_logs.js
// Simple smoke test: create order as buyer, update status as admin, assert admin_logs entry exists

const base = 'http://localhost:3000';

async function req(path, opts={}){
  opts.headers = opts.headers || {};
  if (opts.body && typeof opts.body === 'object') { opts.body = JSON.stringify(opts.body); opts.headers['Content-Type'] = 'application/json'; }
  const res = await fetch(base + path, opts);
  const text = await res.text();
  let body = null; try { body = text ? JSON.parse(text) : null; } catch(e){ body = text; }
  return { status: res.status, body };
}

async function run(){
  console.log('1) Login as buyer...');
  let r = await req('/api/auth/login', { method: 'POST', body: { email: 'charlie@buyers.com', password: 'buyerpass' } });
  if (r.status !== 200 || !r.body || !r.body.token) throw new Error('Buyer login failed: ' + JSON.stringify(r));
  const buyerToken = r.body.token;

  console.log('2) Get products...');
  r = await req('/api/products');
  if (r.status !== 200 || !Array.isArray(r.body) || r.body.length === 0) throw new Error('No products found');
  const p = r.body[0];
  console.log('   using product', p.id, p.title);

  console.log('3) Create order as buyer...');
  const orderBody = { items: [{ productId: p.id, title: p.title, price: p.price || 0, qty: 1, sellerId: p.seller_id || p.sellerId }], totalAmount: p.price || 0, shipName: 'Smoke Tester', shipPhone: '0912-345678', shipAddress: 'Test City' };
  r = await req('/api/orders', { method: 'POST', headers: { Authorization: 'Bearer ' + buyerToken }, body: orderBody });
  if (r.status !== 201 || !r.body || !r.body.id) throw new Error('Create order failed: ' + JSON.stringify(r));
  const orderId = r.body.id;
  console.log('   created order', orderId);

  console.log('4) Login as admin...');
  r = await req('/api/auth/login', { method: 'POST', body: { email: 'admin@example.com', password: 'adminpass' } });
  if (r.status !== 200 || !r.body || !r.body.token) throw new Error('Admin login failed');
  const adminToken = r.body.token;

  console.log('5) Update order status to paid as admin...');
  r = await req('/api/orders/' + encodeURIComponent(orderId), { method: 'PUT', headers: { Authorization: 'Bearer ' + adminToken }, body: { status: 'paid' } });
  if (r.status !== 200) throw new Error('Failed to update order status: ' + JSON.stringify(r));
  console.log('   updated order to paid');

  console.log('6) Check admin logs for update_order_status...');
  // fetch all order-related logs (don't filter by q because details may not include order id)
  r = await req('/api/admin/logs?target_type=order', { headers: { Authorization: 'Bearer ' + adminToken } });
  if (r.status !== 200 || !Array.isArray(r.body)) throw new Error('Failed to fetch logs: ' + JSON.stringify(r));
  // allow a short retry in case log write is slightly delayed
  let found = r.body.find(item => item.action && item.action.includes('update_order_status') && String(item.target_id) === String(orderId));
  if (!found) {
    await new Promise(res => setTimeout(res, 250));
    r = await req('/api/admin/logs?target_type=order', { headers: { Authorization: 'Bearer ' + adminToken } });
    found = (r.body || []).find(item => item.action && item.action.includes('update_order_status') && String(item.target_id) === String(orderId));
  }
  if (!found) throw new Error('No admin log entry found for update_order_status, logs: ' + JSON.stringify(r.body));
  console.log('   found admin log:', found.id || '(no id)');

  console.log('7) PASS: smoke test completed successfully');
}

run().then(()=>process.exit(0)).catch(err => { console.error('SMOKE TEST FAILED:', err); process.exit(2); });
