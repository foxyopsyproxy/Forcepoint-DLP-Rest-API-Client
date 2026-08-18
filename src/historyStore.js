const fs = require('fs');
const path = require('path');
const config = require('./config');
const { db } = require('./db');

const insertScanStmt = db.prepare(`
  INSERT INTO scan_history (
    global_message_id, timestamp_ms, file_name, file_size_bytes, resolution, verdict,
    http_status, elapsed_ms, source_host_ips, source_host_name, data_channel,
    protector_id, protector_name, max_number_of_matches, actions_json, error, error_code,
    failed_over, attempted_protectors_json, schema_version
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const insertViolationStmt = db.prepare(`
  INSERT INTO scan_violations (scan_id, policy_id, policy_name, rule_id, rule_name, severity, matches)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);
const violationsByScanStmt = db.prepare('SELECT * FROM scan_violations WHERE scan_id = ?');

function isBlockingAction(actions) {
  return Array.isArray(actions) && actions.some((a) => /block|quarantine|drop/i.test(a || ''));
}

// Mirrors the frontend's classifyEntry() exactly (public/index.html) - kept in sync
// deliberately so the persisted `verdict` column always agrees with what the UI
// would compute client-side from the same fields.
function computeVerdict({ resolution, violations, actions, error }) {
  if (!resolution && error) return 'error';
  const hasViolations = Array.isArray(violations) && violations.length > 0;
  if (hasViolations && isBlockingAction(actions)) return 'block';
  if (hasViolations) return 'warn';
  return 'pass';
}

// Degraded verdict for schema_version 1 (pre-violations-detail) migrated rows,
// which only ever recorded a violationCount - no actions array exists to prove
// an actual block, so the best we can honestly say is "warn".
function computeLegacyVerdict(old) {
  if (!old.resolution && old.error) return 'error';
  const violationCount = typeof old.violationCount === 'number' ? old.violationCount : 0;
  return violationCount > 0 ? 'warn' : 'pass';
}

function insertScanRow(params) {
  const {
    globalMessageId, timestampMs, fileName, fileSizeBytes, resolution, verdict,
    httpStatus, elapsedMs, sourceHostIps, sourceHostName, dataChannel,
    protectorId, protectorName, maxNumberOfMatches, actionsJson, error, errorCode,
    failedOver, attemptedProtectorsJson, schemaVersion,
  } = params;
  return insertScanStmt.run(
    globalMessageId, timestampMs, fileName ?? null, fileSizeBytes ?? null, resolution ?? null, verdict,
    httpStatus ?? null, elapsedMs ?? 0, sourceHostIps, sourceHostName, dataChannel ?? null,
    protectorId ?? null, protectorName ?? null, maxNumberOfMatches ?? null, actionsJson, error ?? null, errorCode ?? null,
    failedOver ? 1 : 0, attemptedProtectorsJson, schemaVersion
  );
}

function insertViolations(scanId, violations) {
  for (const v of violations) {
    const rules = Array.isArray(v.rules) && v.rules.length ? v.rules : [{}];
    for (const r of rules) {
      insertViolationStmt.run(
        scanId,
        v.policyId ?? v.policy_id ?? null,
        v.policyName ?? v.policy_name ?? null,
        r.ruleId ?? null,
        r.ruleName ?? null,
        r.severity ?? null,
        r.matches !== undefined ? r.matches : null
      );
    }
  }
}

/**
 * Persists one scan attempt (success, Protector-side error, or connection failure).
 * Replaces the old logger.js logScanEvent - same call shape from server.js, now
 * backed by SQLite instead of an append-only JSONL file. Never throws - a logging
 * failure must not be mistaken for a scan failure by the caller.
 */
function recordScanEvent(entry) {
  try {
    const violations = Array.isArray(entry.violations) ? entry.violations : [];
    const actions = Array.isArray(entry.actions) ? entry.actions : undefined;
    const verdict = computeVerdict({ resolution: entry.resolution, violations, actions, error: entry.error });
    const source = entry.source || {};
    const sourceHostIps = Array.isArray(source.host_ips) && source.host_ips.length ? source.host_ips.join(',') : null;
    const sourceHostName = source.host_name || null;

    db.exec('BEGIN');
    try {
      const info = insertScanRow({
        globalMessageId: entry.globalMessageId,
        timestampMs: Date.now(),
        fileName: entry.fileName,
        fileSizeBytes: entry.fileSizeBytes,
        resolution: entry.resolution,
        verdict,
        httpStatus: entry.httpStatus,
        elapsedMs: entry.elapsedMs,
        sourceHostIps,
        sourceHostName,
        dataChannel: entry.dataChannel,
        protectorId: entry.protectorId,
        protectorName: entry.protectorName,
        maxNumberOfMatches: entry.maxNumberOfMatches !== undefined ? entry.maxNumberOfMatches : null,
        actionsJson: actions ? JSON.stringify(actions) : null,
        error: entry.error,
        errorCode: entry.errorCode,
        failedOver: entry.failedOver,
        attemptedProtectorsJson: entry.attemptedProtectors ? JSON.stringify(entry.attemptedProtectors) : null,
        schemaVersion: 2,
      });
      insertViolations(info.lastInsertRowid, violations);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  } catch (err) {
    console.error('Failed to record scan event:', err.message);
  }
}

function median(values) {
  if (!values.length) return 0;
  const sorted = values.slice().sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? Math.round((sorted[mid - 1] + sorted[mid]) / 2) : sorted[mid];
}

function computeStats() {
  const startOfToday = new Date();
  startOfToday.setHours(0, 0, 0, 0);
  const startMs = startOfToday.getTime();

  const scansToday = db.prepare('SELECT COUNT(*) as c FROM scan_history WHERE timestamp_ms >= ?').get(startMs).c;
  const blockedToday = db
    .prepare("SELECT COUNT(*) as c FROM scan_history WHERE timestamp_ms >= ? AND verdict = 'block'")
    .get(startMs).c;
  const elapsedRows = db
    .prepare('SELECT elapsed_ms FROM scan_history WHERE timestamp_ms >= ? AND elapsed_ms IS NOT NULL')
    .all(startMs)
    .map((r) => r.elapsed_ms);
  const timeoutsToday = db
    .prepare("SELECT COUNT(*) as c FROM scan_history WHERE timestamp_ms >= ? AND error_code = 'TIMEOUT'")
    .get(startMs).c;

  return {
    scansToday,
    blockedToday,
    medianElapsedMsToday: median(elapsedRows),
    timeoutsToday,
  };
}

// Reconstructs the exact legacy JS object shape the frontend already expects
// (public/index.html's columnCellHtml/classifyEntry/formatSource/getEntrySize and
// the Verdict Detail renderer all depend on this shape) so no frontend changes
// were needed for this migration. Fields the old code always omitted when not
// applicable (maxNumberOfMatches in particular - see index.html's `!== undefined`
// checks) are omitted here too, never set to null, to avoid rendering "null".
function rowToEntry(row) {
  const violationRows = violationsByScanStmt.all(row.id);
  const violationsByPolicy = new Map();
  for (const vr of violationRows) {
    const key = `${vr.policy_id || ''}|${vr.policy_name || ''}`;
    if (!violationsByPolicy.has(key)) {
      violationsByPolicy.set(key, { policyId: vr.policy_id, policyName: vr.policy_name, rules: [] });
    }
    violationsByPolicy.get(key).rules.push({
      ruleId: vr.rule_id,
      ruleName: vr.rule_name,
      severity: vr.severity,
      matches: vr.matches !== null ? vr.matches : undefined,
    });
  }

  const entry = {
    timestamp: new Date(row.timestamp_ms).toISOString(),
    globalMessageId: row.global_message_id,
    fileName: row.file_name,
    fileSizeBytes: row.file_size_bytes,
    resolution: row.resolution,
    httpStatus: row.http_status,
    elapsedMs: row.elapsed_ms,
    violations: Array.from(violationsByPolicy.values()),
    dataChannel: row.data_channel,
    protectorId: row.protector_id,
    protectorName: row.protector_name,
  };

  if (row.source_host_ips || row.source_host_name) {
    entry.source = {};
    if (row.source_host_ips) entry.source.host_ips = row.source_host_ips.split(',');
    if (row.source_host_name) entry.source.host_name = row.source_host_name;
  }
  if (row.max_number_of_matches !== null) entry.maxNumberOfMatches = row.max_number_of_matches;
  if (row.actions_json) entry.actions = JSON.parse(row.actions_json);
  if (row.error !== null) entry.error = row.error;
  if (row.error_code !== null) entry.errorCode = row.error_code;
  if (row.failed_over) {
    entry.failedOver = true;
    if (row.attempted_protectors_json) entry.attemptedProtectors = JSON.parse(row.attempted_protectors_json);
  }
  return entry;
}

// Maps the sort key the API/frontend uses to the actual indexed column - never
// interpolate req.query.sortBy directly into SQL, always go through this whitelist.
const SORT_COLUMNS = {
  timestamp: 'timestamp_ms',
  fileName: 'file_name',
  fileSizeBytes: 'file_size_bytes',
  resolution: 'resolution',
  protectorName: 'protector_name',
  dataChannel: 'data_channel',
  elapsedMs: 'elapsed_ms',
  maxNumberOfMatches: 'max_number_of_matches',
};

function parseDateMs(value) {
  if (!value) return undefined;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : undefined;
}

function buildFilterClauses(filters) {
  const clauses = [];
  const params = [];
  const fromMs = parseDateMs(filters.from);
  const toMs = parseDateMs(filters.to);
  if (fromMs !== undefined) { clauses.push('timestamp_ms >= ?'); params.push(fromMs); }
  if (toMs !== undefined) { clauses.push('timestamp_ms <= ?'); params.push(toMs); }
  if (filters.protectorId) { clauses.push('protector_id = ?'); params.push(filters.protectorId); }
  if (filters.verdict) { clauses.push('verdict = ?'); params.push(filters.verdict); }
  if (filters.dataChannel) { clauses.push('data_channel = ?'); params.push(filters.dataChannel); }
  if (filters.fileName) {
    const escaped = String(filters.fileName).replace(/[\\%_]/g, (c) => `\\${c}`);
    clauses.push("file_name LIKE ? ESCAPE '\\'");
    params.push(`%${escaped}%`);
  }
  if (Number.isFinite(filters.minElapsedMs)) { clauses.push('elapsed_ms >= ?'); params.push(filters.minElapsedMs); }
  return { clauses, params };
}

function buildWhereClause(filters) {
  const { clauses, params } = buildFilterClauses(filters);
  return { where: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '', params };
}

/**
 * General-purpose history query: filtering, sorting, and pagination all in one
 * indexed SQL statement.
 *
 * @param {object} filters - from/to (ISO date strings), protectorId, verdict,
 *   dataChannel, fileName (substring), minElapsedMs, sortBy, sortDir, page, pageSize
 */
function queryHistory(filters = {}) {
  const { where, params } = buildWhereClause(filters);
  const sortColumn = SORT_COLUMNS[filters.sortBy] || 'timestamp_ms';
  const sortDir = String(filters.sortDir).toLowerCase() === 'asc' ? 'ASC' : 'DESC';
  const pageSize = Math.max(1, Math.min(500, filters.pageSize || 50));
  const page = Math.max(1, filters.page || 1);
  const offset = (page - 1) * pageSize;

  const totalCount = db.prepare(`SELECT COUNT(*) as c FROM scan_history ${where}`).get(...params).c;
  const rows = db
    .prepare(`SELECT * FROM scan_history ${where} ORDER BY ${sortColumn} ${sortDir}, id ${sortDir} LIMIT ? OFFSET ?`)
    .all(...params, pageSize, offset);

  return {
    entries: rows.map(rowToEntry),
    stats: computeStats(),
    pagination: { page, pageSize, totalCount, totalPages: Math.max(1, Math.ceil(totalCount / pageSize)) },
  };
}

/**
 * Same filters/sort as queryHistory, but unpaginated (up to maxRows) - used for
 * CSV export, where the point is to get the whole filtered set in one response
 * rather than one page of it. Capped so a huge unfiltered export can't produce
 * a multi-GB response.
 */
function getHistoryForExport(filters = {}, maxRows = 50000) {
  const { where, params } = buildWhereClause(filters);
  const sortColumn = SORT_COLUMNS[filters.sortBy] || 'timestamp_ms';
  const sortDir = String(filters.sortDir).toLowerCase() === 'asc' ? 'ASC' : 'DESC';
  const rows = db
    .prepare(`SELECT * FROM scan_history ${where} ORDER BY ${sortColumn} ${sortDir}, id ${sortDir} LIMIT ?`)
    .all(...params, maxRows);
  return rows.map(rowToEntry);
}

/**
 * Aggregates for the Analytics dashboard - scans-over-time/block-rate trend,
 * per-protector and per-data-channel volume splits, and top violated
 * policies/rules. All computed as indexed SQL GROUP BYs rather than re-parsing
 * JSON blobs in JS - this is the reason scan_violations is its own table.
 *
 * @param {object} filters - same shape as queryHistory's filters (from/to/protectorId/dataChannel)
 */
function getAnalytics(filters = {}) {
  const { clauses, params } = buildFilterClauses(filters);
  const whereWith = (extraClause) => {
    const all = extraClause ? [...clauses, extraClause] : clauses;
    return all.length ? `WHERE ${all.join(' AND ')}` : '';
  };

  // Bucketed by local calendar day, matching computeStats()'s "since local midnight"
  // definition of "today" elsewhere in this file.
  const trend = db
    .prepare(
      `SELECT strftime('%Y-%m-%d', timestamp_ms / 1000, 'unixepoch', 'localtime') as day,
              COUNT(*) as total,
              SUM(CASE WHEN verdict = 'block' THEN 1 ELSE 0 END) as blocked
       FROM scan_history ${whereWith()}
       GROUP BY day ORDER BY day ASC`
    )
    .all(...params);

  const byProtector = db
    .prepare(
      `SELECT protector_name as name, COUNT(*) as count FROM scan_history
       ${whereWith('protector_name IS NOT NULL')}
       GROUP BY protector_name ORDER BY count DESC`
    )
    .all(...params);

  const byChannel = db
    .prepare(
      `SELECT data_channel as name, COUNT(*) as count FROM scan_history
       ${whereWith('data_channel IS NOT NULL')}
       GROUP BY data_channel ORDER BY count DESC`
    )
    .all(...params);

  const topPolicies = db
    .prepare(
      `SELECT v.policy_name as name, COUNT(*) as hits, COALESCE(SUM(v.matches), 0) as totalMatches
       FROM scan_violations v JOIN scan_history sh ON sh.id = v.scan_id
       ${whereWith('v.policy_name IS NOT NULL')}
       GROUP BY v.policy_name ORDER BY hits DESC LIMIT 10`
    )
    .all(...params);

  const topRules = db
    .prepare(
      `SELECT v.rule_name as name, COUNT(*) as hits, COALESCE(SUM(v.matches), 0) as totalMatches
       FROM scan_violations v JOIN scan_history sh ON sh.id = v.scan_id
       ${whereWith('v.rule_name IS NOT NULL')}
       GROUP BY v.rule_name ORDER BY hits DESC LIMIT 10`
    )
    .all(...params);

  return { trend, byProtector, byChannel, topPolicies, topRules };
}

/**
 * @param {string} id - globalMessageId to look up
 * @returns {object|null}
 */
function getHistoryEntry(id) {
  const row = db.prepare('SELECT * FROM scan_history WHERE global_message_id = ?').get(id);
  return row ? rowToEntry(row) : null;
}

function migrateOneEntry(old) {
  if (!old.globalMessageId) {
    console.warn('Skipping a JSONL history row with no globalMessageId during migration');
    return;
  }
  const isLegacy = !Array.isArray(old.violations) && typeof old.violationCount === 'number';
  const violations = Array.isArray(old.violations) ? old.violations : [];
  const actions = Array.isArray(old.actions) ? old.actions : undefined;
  const verdict = isLegacy
    ? computeLegacyVerdict(old)
    : computeVerdict({ resolution: old.resolution, violations, actions, error: old.error });

  const parsedTimestamp = old.timestamp ? new Date(old.timestamp).getTime() : NaN;
  const source = old.source || {};
  const sourceHostIps = Array.isArray(source.host_ips) && source.host_ips.length ? source.host_ips.join(',') : null;
  const sourceHostName = source.host_name || null;

  let info;
  try {
    info = insertScanRow({
      globalMessageId: old.globalMessageId,
      timestampMs: Number.isFinite(parsedTimestamp) ? parsedTimestamp : Date.now(),
      fileName: old.fileName,
      fileSizeBytes: old.fileSizeBytes ?? old.sizeBytes,
      resolution: old.resolution,
      verdict,
      httpStatus: old.httpStatus,
      elapsedMs: old.elapsedMs,
      sourceHostIps,
      sourceHostName,
      dataChannel: old.dataChannel,
      protectorId: old.protectorId,
      protectorName: old.protectorName,
      maxNumberOfMatches: old.maxNumberOfMatches !== undefined ? old.maxNumberOfMatches : null,
      actionsJson: actions ? JSON.stringify(actions) : null,
      error: old.error,
      errorCode: old.errorCode,
      failedOver: old.failedOver,
      attemptedProtectorsJson: old.attemptedProtectors ? JSON.stringify(old.attemptedProtectors) : null,
      schemaVersion: isLegacy ? 1 : 2,
    });
  } catch (err) {
    if (String(err.message).includes('UNIQUE')) return; // duplicate globalMessageId - already migrated
    throw err;
  }
  insertViolations(info.lastInsertRowid, violations);
}

// Imports logs/requests.log.jsonl into the DB exactly once. Guarded by a flag in
// schema_meta so re-running the app never re-imports. The JSONL file itself is
// never modified or deleted - it stays on disk as an untouched backup, and new
// scans are recorded only via recordScanEvent going forward.
function migrateFromJsonlIfNeeded() {
  const already = db.prepare('SELECT value FROM schema_meta WHERE key = ?').get('migrated_from_jsonl');
  if (already) return;

  const jsonlPath = path.resolve(config.logFilePath);
  if (fs.existsSync(jsonlPath)) {
    const raw = fs.readFileSync(jsonlPath, 'utf8');
    const rows = [];
    for (const line of raw.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        rows.push(JSON.parse(trimmed));
      } catch (err) {
        // Skip malformed lines rather than failing the whole migration.
      }
    }

    db.exec('BEGIN');
    try {
      for (const old of rows) migrateOneEntry(old);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw new Error(`JSONL-to-SQLite history migration failed: ${err.message}`);
    }
    console.log(`Migrated ${rows.length} history entries from ${jsonlPath} into ${config.historyDbPath}`);
  }

  db.prepare('INSERT INTO schema_meta (key, value) VALUES (?, ?)').run('migrated_from_jsonl', '1');
}

module.exports = {
  getHistoryEntry,
  queryHistory,
  getHistoryForExport,
  getAnalytics,
  recordScanEvent,
  isBlockingAction,
  migrateFromJsonlIfNeeded,
};
