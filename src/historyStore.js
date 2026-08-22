const fs = require('fs');
const path = require('path');
const config = require('./config');
const { db } = require('./db');

const insertScanStmt = db.prepare(`
  INSERT INTO scan_history (
    global_message_id, timestamp_ms, file_name, file_size_bytes, resolution, verdict,
    http_status, elapsed_ms, source_host_ips, source_host_name, data_channel,
    protector_id, protector_name, max_number_of_matches, actions_json, error, error_code,
    failed_over, attempted_protectors_json, transport, schema_version
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    failedOver, attemptedProtectorsJson, transport, schemaVersion,
  } = params;
  return insertScanStmt.run(
    globalMessageId, timestampMs, fileName ?? null, fileSizeBytes ?? null, resolution ?? null, verdict,
    httpStatus ?? null, elapsedMs ?? 0, sourceHostIps, sourceHostName, dataChannel ?? null,
    protectorId ?? null, protectorName ?? null, maxNumberOfMatches ?? null, actionsJson, error ?? null, errorCode ?? null,
    failedOver ? 1 : 0, attemptedProtectorsJson, transport ?? null, schemaVersion
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
        transport: entry.transport,
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

// Nearest-rank percentile. Small result sets here (one range's worth of scans),
// so sorting in JS is cheaper than a windowed SQL query.
function percentile(sortedValues, p) {
  if (!sortedValues.length) return 0;
  const rank = Math.ceil((p / 100) * sortedValues.length);
  return sortedValues[Math.min(sortedValues.length - 1, Math.max(0, rank - 1))];
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
// Worst-first: a single scan can violate several rules at once, possibly at
// different severities, and a table row can only show one badge - "what's the worst
// thing this scan matched" is the more useful summary than "the first rule returned".
const SEVERITY_RANK = { HIGH: 3, MEDIUM: 2, LOW: 1 };

function rowToEntry(row) {
  const violationRows = violationsByScanStmt.all(row.id);
  let highestSeverity;
  let highestRank = 0;
  for (const vr of violationRows) {
    const rank = SEVERITY_RANK[(vr.severity || '').toUpperCase()] || 0;
    if (rank > highestRank) { highestRank = rank; highestSeverity = vr.severity; }
  }
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
  if (highestSeverity) entry.highestSeverity = highestSeverity;

  if (row.source_host_ips || row.source_host_name) {
    entry.source = {};
    if (row.source_host_ips) entry.source.host_ips = row.source_host_ips.split(',');
    if (row.source_host_name) entry.source.host_name = row.source_host_name;
  }
  if (row.max_number_of_matches !== null) entry.maxNumberOfMatches = row.max_number_of_matches;
  if (row.actions_json) entry.actions = JSON.parse(row.actions_json);
  if (row.error !== null) entry.error = row.error;
  if (row.error_code !== null) entry.errorCode = row.error_code;
  if (row.transport) entry.transport = row.transport;
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
  // Severity/policy/rule live on the CHILD scan_violations table (a scan can violate
  // several policies/rules at once, each with its own severity), so "this scan
  // matches" has to be expressed as EXISTS(...) rather than a plain column equality -
  // a JOIN here would duplicate the parent row once per matching violation and break
  // both the total count and the pagination math.
  if (filters.severity) {
    clauses.push('EXISTS (SELECT 1 FROM scan_violations v WHERE v.scan_id = scan_history.id AND v.severity = ?)');
    params.push(filters.severity);
  }
  if (filters.policyName) {
    clauses.push('EXISTS (SELECT 1 FROM scan_violations v WHERE v.scan_id = scan_history.id AND v.policy_name = ?)');
    params.push(filters.policyName);
  }
  if (filters.ruleName) {
    clauses.push('EXISTS (SELECT 1 FROM scan_violations v WHERE v.scan_id = scan_history.id AND v.rule_name = ?)');
    params.push(filters.ruleName);
  }
  // Backs "export selected rows" - the frontend already holds these exact rows in
  // memory (they came from a prior real query), this just re-fetches them by their
  // own id for a clean server-authored CSV rather than duplicating export formatting
  // client-side.
  if (Array.isArray(filters.ids) && filters.ids.length) {
    clauses.push(`global_message_id IN (${filters.ids.map(() => '?').join(',')})`);
    params.push(...filters.ids);
  }
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
 * Distinct severities/policies/rules that have actually occurred, for populating
 * History's filter dropdowns. Deliberately sourced from real data rather than a
 * fixed list - this app has no endpoint onto the Protector's own policy configuration
 * (the Inspection API only ever reports a policy/rule AFTER it fires), so "every
 * policy that could theoretically match" is not something this client can know;
 * "every policy that HAS matched so far" is the honest, available substitute.
 */
function getHistoryFacets() {
  const severities = db
    .prepare("SELECT DISTINCT severity FROM scan_violations WHERE severity IS NOT NULL AND severity != '' ORDER BY severity")
    .all()
    .map((r) => r.severity)
    .sort((a, b) => (SEVERITY_RANK[b] || 0) - (SEVERITY_RANK[a] || 0));
  const policies = db
    .prepare("SELECT DISTINCT policy_name FROM scan_violations WHERE policy_name IS NOT NULL AND policy_name != '' ORDER BY policy_name COLLATE NOCASE")
    .all()
    .map((r) => r.policy_name);
  const rules = db
    .prepare("SELECT DISTINCT rule_name FROM scan_violations WHERE rule_name IS NOT NULL AND rule_name != '' ORDER BY rule_name COLLATE NOCASE")
    .all()
    .map((r) => r.rule_name);
  return { severities, policies, rules };
}

/**
 * Most recent HIGH-severity violations across all scans, each resolved back to its
 * parent scan for display (filename, timestamp, global_message_id to link to Verdict
 * Detail). Backs a "what should I look at first" dashboard panel - the analyst
 * question this app previously had no direct answer for; Analytics' existing
 * top-policies/top-rules charts show aggregate counts, not a scannable recent list.
 */
function getRecentHighSeverityFindings(limit = 8) {
  const rows = db
    .prepare(
      `SELECT sh.global_message_id, sh.file_name, sh.timestamp_ms, sh.protector_name,
              v.policy_name, v.rule_name, v.severity, v.matches
       FROM scan_violations v
       JOIN scan_history sh ON sh.id = v.scan_id
       WHERE v.severity = 'HIGH'
       ORDER BY sh.timestamp_ms DESC, v.id DESC
       LIMIT ?`
    )
    .all(Math.max(1, Math.min(50, limit)));
  return rows.map((r) => ({
    globalMessageId: r.global_message_id,
    fileName: r.file_name,
    timestamp: new Date(r.timestamp_ms).toISOString(),
    protectorName: r.protector_name,
    policyName: r.policy_name,
    ruleName: r.rule_name,
    severity: r.severity,
    matches: r.matches !== null ? r.matches : undefined,
  }));
}

/**
 * Aggregates for the Analytics dashboard - scans-over-time/block-rate/high-severity
 * trend, per-protector and per-data-channel volume splits, top violated policies/rules
 * (each with a HIGH-severity sub-count), a summary (totalScans/totalBlocked/blockRate/
 * highSeverityFindings/medianElapsedMs), a verdict breakdown (block/warn/pass/error
 * counts), and a priorityFindings list (the most recent HIGH-severity violations in
 * the same filtered window). All computed as indexed SQL GROUP BYs rather than
 * re-parsing JSON blobs in JS - this is the reason scan_violations is its own table.
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
  // definition of "today" elsewhere in this file. Over a single day that would collapse
  // to one point and stop being a graph at all, so the caller can ask for hourly
  // buckets instead - the bucket key stays in the same `day` field either way, and the
  // frontend formats the axis label from `bucket`.
  const bucket = filters.bucket === 'hour' ? 'hour' : 'day';
  const bucketExpr =
    bucket === 'hour'
      ? "strftime('%Y-%m-%d %H:00', timestamp_ms / 1000, 'unixepoch', 'localtime')"
      : "strftime('%Y-%m-%d', timestamp_ms / 1000, 'unixepoch', 'localtime')";
  // highSeverity uses a correlated scalar subquery, not a JOIN, for the same reason
  // buildFilterClauses' severity filter does - joining scan_violations here would
  // duplicate a scan_history row once per violation and inflate `total`/`blocked`.
  const trend = db
    .prepare(
      `SELECT ${bucketExpr} as day,
              COUNT(*) as total,
              SUM(CASE WHEN verdict = 'block' THEN 1 ELSE 0 END) as blocked,
              SUM((SELECT COUNT(*) FROM scan_violations v WHERE v.scan_id = scan_history.id AND v.severity = 'HIGH')) as highSeverity
       FROM scan_history ${whereWith()}
       GROUP BY day ORDER BY day ASC`
    )
    .all(...params);

  // Grouped by protector_id, not protector_name: a Protector that was renamed in .env
  // has old rows under its previous name, which would otherwise show up as extra bars
  // for what is really the same appliance. Rows whose id is no longer configured at all
  // (e.g. the legacy single-Protector 'default' id) are left out entirely, so this chart
  // only ever lists Protectors that currently exist in config.
  const configuredProtectors = config.protectors;
  const byProtector = configuredProtectors.length
    ? (() => {
        const idPlaceholders = configuredProtectors.map(() => '?').join(',');
        const nameById = new Map(configuredProtectors.map((p) => [p.id, p.name]));
        return db
          .prepare(
            `SELECT protector_id as id, COUNT(*) as count FROM scan_history
             ${whereWith(`protector_id IN (${idPlaceholders})`)}
             GROUP BY protector_id ORDER BY count DESC`
          )
          .all(...params, ...configuredProtectors.map((p) => p.id))
          .map((r) => ({ name: nameById.get(r.id) || r.id, count: r.count }));
      })()
    : [];

  const byChannel = db
    .prepare(
      `SELECT data_channel as name, COUNT(*) as count FROM scan_history
       ${whereWith('data_channel IS NOT NULL')}
       GROUP BY data_channel ORDER BY count DESC`
    )
    .all(...params);

  const topPolicies = db
    .prepare(
      `SELECT v.policy_name as name, COUNT(*) as hits, COALESCE(SUM(v.matches), 0) as totalMatches,
              SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) as highCount
       FROM scan_violations v JOIN scan_history sh ON sh.id = v.scan_id
       ${whereWith('v.policy_name IS NOT NULL')}
       GROUP BY v.policy_name ORDER BY hits DESC LIMIT 10`
    )
    .all(...params);

  const totals = db
    .prepare(
      `SELECT COUNT(*) as total,
              SUM(CASE WHEN verdict = 'block' THEN 1 ELSE 0 END) as blocked,
              SUM(CASE WHEN verdict = 'error' THEN 1 ELSE 0 END) as errors,
              COALESCE(SUM(file_size_bytes), 0) as bytes,
              COUNT(DISTINCT file_name) as uniqueFiles
       FROM scan_history ${whereWith()}`
    )
    .get(...params);
  // A scan-level count (verdict = 'block') already exists above; this is the
  // rule-level count of specifically HIGH-severity violations in the same window -
  // "how much of the risk here is actually high-severity" isn't answerable from
  // totals.blocked alone, since one blocked scan can carry several rules at once.
  const highSeverityTotal = db
    .prepare(`SELECT COUNT(*) as c FROM scan_violations v JOIN scan_history sh ON sh.id = v.scan_id ${whereWith("v.severity = 'HIGH'")}`)
    .get(...params).c;
  const elapsedValues = db
    .prepare(`SELECT elapsed_ms FROM scan_history ${whereWith('elapsed_ms IS NOT NULL')}`)
    .all(...params)
    .map((r) => r.elapsed_ms);
  const sortedElapsed = elapsedValues.slice().sort((a, b) => a - b);
  const verdictBreakdown = db
    .prepare(`SELECT verdict, COUNT(*) as count FROM scan_history ${whereWith('verdict IS NOT NULL')} GROUP BY verdict`)
    .all(...params);

  const summary = {
    totalScans: totals.total || 0,
    totalBlocked: totals.blocked || 0,
    totalErrors: totals.errors || 0,
    blockRate: totals.total ? (totals.blocked || 0) / totals.total : 0,
    errorRate: totals.total ? (totals.errors || 0) / totals.total : 0,
    highSeverityFindings: highSeverityTotal || 0,
    medianElapsedMs: median(elapsedValues),
    p95ElapsedMs: percentile(sortedElapsed, 95),
    p99ElapsedMs: percentile(sortedElapsed, 99),
    maxElapsedMs: sortedElapsed.length ? sortedElapsed[sortedElapsed.length - 1] : 0,
    totalBytes: totals.bytes || 0,
    uniqueFiles: totals.uniqueFiles || 0,
  };

  // Same metrics over the immediately-preceding window of equal length, so the UI
  // can show "vs previous period" deltas. Only meaningful for a bounded range -
  // "all time" has no earlier period to compare against.
  const fromMs = parseDateMs(filters.from);
  const toMs = parseDateMs(filters.to) ?? Date.now();
  let previous = null;
  if (fromMs !== undefined && toMs > fromMs) {
    const windowMs = toMs - fromMs;
    const prevFilters = { ...filters, from: new Date(fromMs - windowMs).toISOString(), to: new Date(fromMs).toISOString() };
    const { clauses: pc, params: pp } = buildFilterClauses(prevFilters);
    const prevWhere = pc.length ? `WHERE ${pc.join(' AND ')}` : '';
    const prevTotals = db
      .prepare(
        `SELECT COUNT(*) as total,
                SUM(CASE WHEN verdict = 'block' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN verdict = 'error' THEN 1 ELSE 0 END) as errors
         FROM scan_history ${prevWhere}`
      )
      .get(...pp);
    const prevElapsed = db
      .prepare(`SELECT elapsed_ms FROM scan_history ${prevWhere ? prevWhere + ' AND' : 'WHERE'} elapsed_ms IS NOT NULL`)
      .all(...pp)
      .map((r) => r.elapsed_ms);
    const prevHighSeverity = db
      .prepare(
        `SELECT COUNT(*) as c FROM scan_violations v JOIN scan_history sh ON sh.id = v.scan_id
         ${prevWhere ? prevWhere + " AND v.severity = 'HIGH'" : "WHERE v.severity = 'HIGH'"}`
      )
      .get(...pp).c;
    previous = {
      totalScans: prevTotals.total || 0,
      totalBlocked: prevTotals.blocked || 0,
      totalErrors: prevTotals.errors || 0,
      blockRate: prevTotals.total ? (prevTotals.blocked || 0) / prevTotals.total : 0,
      medianElapsedMs: median(prevElapsed),
      highSeverityFindings: prevHighSeverity || 0,
    };
  }

  // Severity mix across every matched rule - answers "are these mostly HIGH-severity
  // hits or noise?", which the raw block count alone can't tell you.
  const severityBreakdown = db
    .prepare(
      `SELECT COALESCE(v.severity, 'UNKNOWN') as name, COUNT(*) as count
       FROM scan_violations v JOIN scan_history sh ON sh.id = v.scan_id
       ${whereWith()}
       GROUP BY COALESCE(v.severity, 'UNKNOWN') ORDER BY count DESC`
    )
    .all(...params);

  // Activity by local hour of day (0-23), for spotting when scanning actually happens.
  const hourRows = db
    .prepare(
      `SELECT CAST(strftime('%H', timestamp_ms / 1000, 'unixepoch', 'localtime') AS INTEGER) as hour,
              COUNT(*) as total,
              SUM(CASE WHEN verdict = 'block' THEN 1 ELSE 0 END) as blocked
       FROM scan_history ${whereWith()} GROUP BY hour`
    )
    .all(...params);
  const hourMap = new Map(hourRows.map((r) => [r.hour, r]));
  const byHourOfDay = Array.from({ length: 24 }, (_, h) => ({
    hour: h,
    total: hourMap.get(h)?.total || 0,
    blocked: hourMap.get(h)?.blocked || 0,
  }));

  const topFiles = db
    .prepare(
      `SELECT file_name as name, COUNT(*) as count,
              SUM(CASE WHEN verdict = 'block' THEN 1 ELSE 0 END) as blocked,
              SUM((SELECT COUNT(*) FROM scan_violations v WHERE v.scan_id = scan_history.id AND v.severity = 'HIGH')) as highCount
       FROM scan_history ${whereWith('file_name IS NOT NULL')}
       GROUP BY file_name ORDER BY count DESC LIMIT 10`
    )
    .all(...params);

  const topRules = db
    .prepare(
      `SELECT v.rule_name as name, COUNT(*) as hits, COALESCE(SUM(v.matches), 0) as totalMatches,
              SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) as highCount
       FROM scan_violations v JOIN scan_history sh ON sh.id = v.scan_id
       ${whereWith('v.rule_name IS NOT NULL')}
       GROUP BY v.rule_name ORDER BY hits DESC LIMIT 10`
    )
    .all(...params);

  // Backs the Analytics "Priority findings" panel - the most recent HIGH-severity
  // violations within the SAME filtered window as the rest of this page (unlike
  // getRecentHighSeverityFindings, which is deliberately unfiltered for the Home
  // dashboard's "most recent, full stop" panel).
  const priorityFindings = db
    .prepare(
      `SELECT sh.global_message_id, sh.file_name, sh.timestamp_ms, sh.protector_name,
              v.policy_name, v.rule_name, v.severity, v.matches
       FROM scan_violations v JOIN scan_history sh ON sh.id = v.scan_id
       ${whereWith("v.severity = 'HIGH'")}
       ORDER BY sh.timestamp_ms DESC, v.id DESC
       LIMIT 8`
    )
    .all(...params)
    .map((r) => ({
      globalMessageId: r.global_message_id,
      fileName: r.file_name,
      timestamp: new Date(r.timestamp_ms).toISOString(),
      protectorName: r.protector_name,
      policyName: r.policy_name,
      ruleName: r.rule_name,
      severity: r.severity,
      matches: r.matches !== null ? r.matches : undefined,
    }));

  return {
    trend, bucket, byProtector, byChannel, topPolicies, topRules,
    summary, previous, verdictBreakdown, severityBreakdown, byHourOfDay, topFiles,
    priorityFindings,
    generatedAt: new Date().toISOString(),
  };
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
  getHistoryFacets,
  getRecentHighSeverityFindings,
  getAnalytics,
  recordScanEvent,
  isBlockingAction,
  migrateFromJsonlIfNeeded,
};
