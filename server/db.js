const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

const dbPath = path.join(dataDir, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error('Failed to open DB:', err);
});

function runMigration() {
  const migrationsDir = path.join(__dirname, 'migrations');
  if (!fs.existsSync(migrationsDir)) {
    console.warn('Migrations directory not found:', migrationsDir);
    return Promise.resolve();
  }

  const files = fs.readdirSync(migrationsDir)
    .filter(f => f.endsWith('.sql'))
    .sort();

  // execute each migration and wait for completion
  const promises = files.map(file => {
    const sqlPath = path.join(migrationsDir, file);
    return new Promise((resolve) => {
      try {
        const sql = fs.readFileSync(sqlPath, 'utf8');
        db.exec(sql, (err) => {
          if (err) {
            if (typeof err.message === 'string' && err.message.includes('duplicate column')) {
              console.log('Migration skipped (duplicate column):', file);
            } else {
              console.error('Migration error for', file, err);
            }
          } else {
            console.log('Applied migration:', file);
          }
          // always resolve to continue with others
          resolve();
        });
      } catch (err) {
        console.error('Migration error for', file, err);
        resolve();
      }
    });
  });

  return Promise.all(promises).then(() => undefined);
}

module.exports = { db, runMigration };
