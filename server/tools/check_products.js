const { db } = require('../db');

function all(sql, params=[]) { return new Promise((res, rej)=> db.all(sql, params, (e, r)=> e?rej(e):res(r))); }

(async ()=>{
  try{
    const cols = await all("PRAGMA table_info('products')");
    console.log('products schema:'); console.table(cols);
    const rows = await all("SELECT id,title,category,image,images FROM products LIMIT 20");
    console.log('sample product rows (up to 20):'); console.table(rows);
    process.exit(0);
  }catch(err){ console.error('check failed', err); process.exit(2); }
})();