const fs = require('fs');
const path = require('path');
const config = require('./config');

let DatabaseSync;
try {
  ({ DatabaseSync } = require('node:sqlite'));
} catch (err) {
  throw new Error(
    `This Node runtime doesn't provide node:sqlite (${err.message}). ` +
      'Requires Node 22.5+ built with sqlite support - check `node -e "require(\'node:sqlite\')"` on this machine.'
  );
}

const dbPath = path.resolve(config.historyDbPath);
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = new DatabaseSync(dbPath);
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    global_message_id TEXT UNIQUE NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    file_name TEXT,
    file_size_bytes INTEGER,
    resolution TEXT,
    verdict TEXT,
    http_status INTEGER,
    elapsed_ms INTEGER,
    source_host_ips TEXT,
    source_host_name TEXT,
    data_channel TEXT,
    protector_id TEXT,
    protector_name TEXT,
    max_number_of_matches INTEGER,
    actions_json TEXT,
    error TEXT,
    error_code TEXT,
    failed_over INTEGER,
    attempted_protectors_json TEXT,
    schema_version INTEGER NOT NULL DEFAULT 2
  );

  CREATE INDEX IF NOT EXISTS idx_history_timestamp ON scan_history(timestamp_ms);
  CREATE INDEX IF NOT EXISTS idx_history_protector ON scan_history(protector_id);
  CREATE INDEX IF NOT EXISTS idx_history_verdict ON scan_history(verdict);
  CREATE INDEX IF NOT EXISTS idx_history_channel ON scan_history(data_channel);
  CREATE INDEX IF NOT EXISTS idx_history_filename ON scan_history(file_name);
  CREATE INDEX IF NOT EXISTS idx_history_elapsed ON scan_history(elapsed_ms);

  CREATE TABLE IF NOT EXISTS scan_violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scan_history(id) ON DELETE CASCADE,
    policy_id TEXT,
    policy_name TEXT,
    rule_id TEXT,
    rule_name TEXT,
    severity TEXT,
    matches INTEGER
  );

  CREATE INDEX IF NOT EXISTS idx_violations_scan ON scan_violations(scan_id);
  CREATE INDEX IF NOT EXISTS idx_violations_policy ON scan_violations(policy_id);
  CREATE INDEX IF NOT EXISTS idx_violations_rule ON scan_violations(rule_id);

  CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

// CREATE TABLE IF NOT EXISTS above never alters a table that already exists, so any
// column added after a database was first created has to be applied separately.
// Guarded by PRAGMA table_info so this is safe to run on every boot.
function ensureColumn(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!columns.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

// Which scheme the file was actually sent over ('http' | 'https'). NULL for rows
// written before this was tracked - deliberately not defaulted to 'http', since
// guessing would misreport older scans that really did go over TLS.
ensureColumn('scan_history', 'transport', 'TEXT');
db.exec('CREATE INDEX IF NOT EXISTS idx_history_transport ON scan_history(transport)');

module.exports = { db };
