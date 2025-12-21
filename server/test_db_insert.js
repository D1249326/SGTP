const { db } = require('./db');
const bcrypt = require('bcryptjs');
(async () => {
  console.log('TEST DB INSERT START');
  try {
    const hash = await bcrypt.hash('password123', 10);
    db.run('INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)', ['DBTester', 'dbtester@example.com', hash, 'buyer'], function(err) {
      if (err) return console.error('DB ERR', err.message);
      console.log('INSERTED ID', this.lastID);
      db.get('SELECT id, name, email, role FROM users WHERE id = ?', [this.lastID], (e, row) => {
        if (e) return console.error('SELECT ERR', e.message);
        console.log('ROW', row);
      });
    });
  } catch (e) {
    console.error('ERR', e);
  }
  // keep process alive briefly
  setTimeout(() => { console.log('END'); }, 500);
})();