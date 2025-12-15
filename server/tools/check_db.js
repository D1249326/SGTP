const { db } = require('../db');

function all(sql, params=[]) { return new Promise((res, rej)=> db.all(sql, params, (e, r)=> e?rej(e):res(r))); }
function get(sql, params=[]) { return new Promise((res, rej)=> db.get(sql, params, (e, r)=> e?rej(e):res(r))); }

(async ()=>{
  try{
    const tables = await all("SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY name");
    console.log('Tables/views found:'); console.table(tables);

    const check = ['users','products','orders','cart_items','admin_logs'];
    for(const t of check){
      try{
        const c = await get(`SELECT COUNT(*) AS cnt FROM ${t}`);
        console.log(`${t}: ${c.cnt} rows`);
      }catch(e){
        console.log(`${t}: not present or query failed (${e.message})`);
      }
    }

    // schema for admin_logs
    try{
      const cols = await all("PRAGMA table_info('admin_logs')");
      console.log('admin_logs schema:'); console.table(cols);
    }catch(e){ console.log('admin_logs schema: not present'); }

    process.exit(0);
  }catch(err){ console.error('check failed', err); process.exit(2); }
})();