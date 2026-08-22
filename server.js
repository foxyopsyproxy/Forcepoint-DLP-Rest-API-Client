const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const config = require('./src/config');
const { inspectRaw, checkProtectorReachability, listProtectorSummaries, isConnectionClassError, isTlsError } = require('./src/protectorClient');
const { getSettings, getFieldStates, getDefaults, updateSettings, DATA_CHANNEL_OPTIONS, WEBHOOK_FORMAT_OPTIONS, WEBHOOK_TRIGGER_OPTIONS, TRANSPORT_OPTIONS } = require('./src/settingsStore');
const {
  getHistoryEntry,
  queryHistory,
  getHistoryForExport,
  getHistoryFacets,
  getRecentHighSeverityFindings,
  getAnalytics,
  recordScanEvent,
  isBlockingAction,
  migrateFromJsonlIfNeeded,
} = require('./src/historyStore');
const { notifyScan, sendTestWebhook } = require('./src/webhookNotifier');
const { bus, publish } = require('./src/eventBus');
// Whole-module reference (not destructured) alongside the destructured import above -
// SanitizationService always calls `protectorClient.inspectFile(...)` through this
// object so tests can inject a fake with the same shape; both references point at
// the same cached module, so nothing is duplicated.
const protectorClient = require('./src/protectorClient');
const { VALIDATORS: KEY_PHRASE_VALIDATORS } = require('./src/keyPhraseValidators');
const { createKeyPhraseStore } = require('./src/keyPhraseStore');
// Key Phrase Redaction is opt-in: with no KEY_PHRASE_CONFIG_PATH set, keyPhraseStore
// resolves to a harmless disabled stub and the rest of the app is unaffected. If a
// path IS set but the file is invalid, getCompiled() throws - called here, eagerly,
// specifically so a broken config fails application startup, exactly like a bad TLS
// cert path already does elsewhere in config.js, rather than surfacing on first scan.
const keyPhraseStore = createKeyPhraseStore();
if (keyPhraseStore.isEnabled()) keyPhraseStore.getCompiled();
const { createSanitizationService, BLOCK_REASONS } = require('./src/sanitizationService');
const sanitizationService = createSanitizationService({
  protectorClient,
  // Thin adapter to the shape SanitizationService expects - keeps it unaware that
  // the config can change at runtime at all; keyPhraseStore.getCompiled() is what
  // actually re-reads the file only when it has changed (see keyPhraseStore.js).
  keyPhraseConfig: {
    isEnabled: () => keyPhraseStore.getCompiled().isEnabled(),
    getRuleMapping: (ruleName) => keyPhraseStore.getCompiled().getRuleMapping(ruleName),
  },
});

// Semantic AI DLP (Milestone 1 - shadow mode). Entirely additive and optional - see
// docs/semantic-dlp-architecture.md. Wired up regardless of config.semanticAi.enabled
// so the off/on switch is a pure runtime check inside semanticScanner.scan(), not a
// conditional require() - keeps this boot section simple and matches how
// keyPhraseStore above is always constructed even when unconfigured.
const { extractText } = require('./src/contentExtractor');
const { createOllamaProvider } = require('./src/ollamaProvider');
const { createSemanticPolicyStore } = require('./src/semanticPolicyStore');
const { createSemanticScanner } = require('./src/semanticScanner');
const { createForcepointScanner } = require('./src/forcepointScanner');
const { createScanOrchestrator } = require('./src/scanOrchestrator');
const { createDecisionEngine } = require('./src/decisionEngine');
const { createAiMetrics } = require('./src/aiMetrics');
const semanticPolicyStore = createSemanticPolicyStore();
const semanticScanner = createSemanticScanner({
  provider: createOllamaProvider({
    baseUrl: config.semanticAi.ollamaBaseUrl,
    model: config.semanticAi.ollamaModel,
    timeoutMs: config.semanticAi.ollamaTimeoutMs,
    keepAlive: config.semanticAi.ollamaKeepAlive,
    numCtx: config.semanticAi.ollamaNumCtx,
    numPredict: config.semanticAi.ollamaNumPredict,
    temperature: config.semanticAi.ollamaTemperature,
  }),
  policy: semanticPolicyStore,
  aiConfig: config.semanticAi,
});
if (config.semanticAi.enabled) semanticPolicyStore.getPolicy(); // fail fast on a broken policy file, same philosophy as keyPhraseStore above

// Named wrapper around the existing Forcepoint client (src/forcepointScanner.js is
// a pure pass-through - see its own header comment) and the orchestrator that
// starts it and the Semantic AI scanner together under one scan_id
// (src/scanOrchestrator.js). Neither changes any existing behavior; they exist so
// the Forcepoint + Semantic AI relationship matches the
// ScanOrchestrator/ForcepointScanner/SemanticScanner shape in
// docs/semantic-dlp-architecture.md instead of being two inline statements in the
// /api/scan route.
const forcepointScanner = createForcepointScanner({ protectorClient });
const scanOrchestrator = createScanOrchestrator({ forcepointScanner, runSemanticAnalysis });
// Shadow-mode only (src/decisionEngine.js) - computes and logs what a theoretical
// enforcement decision would have been, never applied to a real scan's outcome.
const decisionEngine = createDecisionEngine();
// In-process observability counters (src/aiMetrics.js), exposed read-only at
// GET /api/ai-metrics. Resets on restart - see that file's header comment.
const aiMetrics = createAiMetrics();

// Runs the Semantic AI layer for one scan's bytes. Returns null (not a result
// object) when the feature is off, so callers can cheaply skip adding an
// `aiAnalysis` field at all rather than adding a DISABLED placeholder to every scan
// response - `config.semanticAi.enabled` is checked here BEFORE doing any
// extraction/hashing work, so a disabled feature costs nothing per scan.
// Never throws: semanticScanner.scan() already guarantees this, and this function
// adds nothing between here and there that could - the existing Forcepoint call in
// /api/scan must never be affected by anything going wrong on this path.
async function runSemanticAnalysis(buffer, fileName, scanId) {
  if (!config.semanticAi.enabled) return null;
  const extracted = extractText(buffer, fileName);
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  // extracted.status !== 'OK' -> passing null makes semanticScanner.scan() resolve
  // to EXTRACTION_FAILED on its own (see its `typeof text !== 'string'` check) -
  // no need to duplicate that branch here.
  return semanticScanner.scan(extracted.status === 'OK' ? extracted.text : null, { scanId, fileName, fileSizeBytes: buffer.length, sha256 });
}

// Shadow-mode only: updates observability counters (src/aiMetrics.js) and
// computes + logs what a theoretical enforcement decision would have been
// (src/decisionEngine.js). Never affects the actual scan response - purely
// logging/metrics, called from every /api/scan response branch below.
// fileSizeBytes stands in for "characters analyzed" (ai_input_chars) - an
// approximation, not the real extracted-text length, kept this way so this
// function never needs to touch (or re-extract) the content itself.
function recordAiObservability(aiAnalysis, { scanId, forcepointMatched, dataChannel, fileSizeBytes }) {
  aiMetrics.recordAiResult(aiAnalysis, { inputChars: fileSizeBytes });
  if (typeof forcepointMatched === 'boolean') {
    aiMetrics.recordAgreement(forcepointMatched, aiAnalysis && aiAnalysis.classification);
  }
  const decision = decisionEngine.decide({
    aiClassification: aiAnalysis && aiAnalysis.classification,
    transactionContext: { channel: dataChannel },
  });
  console.log(JSON.stringify({ scan_id: scanId, theoretical_decision: decision.theoreticalDecision, theoretical_decision_reason: decision.reason }));
}

migrateFromJsonlIfNeeded();

const app = express();
const memoryStorage = multer.memoryStorage();
const startedAt = Date.now();

// multer/busboy decode multipart filenames as Latin-1 by default (per the original
// multipart spec), but browsers send non-ASCII filenames (Hebrew, emoji, etc.) as raw
// UTF-8 bytes - so every multi-byte character comes out garbled unless re-decoded here.
function fixFilenameEncoding(name) {
  return Buffer.from(name, 'latin1').toString('utf8');
}

// Node's raw network error messages embed the actual host:port being connected to
// (e.g. "connect ETIMEDOUT 192.168.50.199:8443") - safe to log to this process's own
// console, but must never reach the browser or the persisted history log, which both
// this app's UI and its API expose. Always resolve to one of these generic messages
// instead of touching error.message for anything connection-related.
// TLS failures get their own messages because the generic "unable to connect" text
// sends people looking at firewalls when the real fix is a certificate setting. These
// name the env var to change without revealing the appliance's host or port.
const TLS_ERROR_MESSAGES = {
  SELF_SIGNED_CERT_IN_CHAIN: "The Protector's certificate chain is not trusted. Set PROTECTOR_<n>_CA_CERT_PATH to its issuing CA, or PROTECTOR_<n>_TLS_REJECT_UNAUTHORIZED=false to skip verification.",
  DEPTH_ZERO_SELF_SIGNED_CERT: "The Protector is using a self-signed certificate. Set PROTECTOR_<n>_CA_CERT_PATH to trust it, or PROTECTOR_<n>_TLS_REJECT_UNAUTHORIZED=false to skip verification.",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: "The Protector's certificate could not be verified. Set PROTECTOR_<n>_CA_CERT_PATH to its issuing CA.",
  UNABLE_TO_GET_ISSUER_CERT: "The Protector's certificate issuer is unknown. Set PROTECTOR_<n>_CA_CERT_PATH to its issuing CA.",
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: "The Protector's certificate issuer is unknown. Set PROTECTOR_<n>_CA_CERT_PATH to its issuing CA.",
  CERT_HAS_EXPIRED: "The Protector's TLS certificate has expired.",
  CERT_NOT_YET_VALID: "The Protector's TLS certificate is not valid yet (check clock skew).",
  ERR_TLS_CERT_ALTNAME_INVALID: "The Protector's certificate does not match the address it was contacted on. Set PROTECTOR_<n>_TLS_SERVERNAME to the name on the certificate.",
  ERR_SSL_WRONG_VERSION_NUMBER: 'Sent HTTPS to a port that is not speaking TLS. Check the Protector\'s HTTPS port (PROTECTOR_<n>_HTTPS_PORT, default 8443).',
  EPROTO: 'TLS handshake failed with the Protector. Check that its HTTPS port is correct and that TLS is enabled on the appliance.',
};

function sanitizeProtectorError(error) {
  if (error.code === 'TIMEOUT') {
    return 'Timed out waiting for a response from the Protector';
  }
  // Checked before the connection-class branch: a TLS error is not a connectivity
  // problem and must not be reported as one.
  if (isTlsError(error)) {
    return TLS_ERROR_MESSAGES[error.code] || `TLS error contacting the Protector (${error.code})`;
  }
  if (isConnectionClassError(error)) {
    return `Unable to connect to the Protector (${error.code})`;
  }
  if (error.code === 'INVALID_RESPONSE') {
    return 'Protector returned a response this app could not parse';
  }
  return 'Unexpected error while contacting the Protector';
}

// The browser sends the secure toggle as a string; anything other than an explicit
// choice means "use whatever the Protector is configured for".
function parseTransport(value) {
  if (value === undefined || value === null || value === '') return undefined;
  const v = String(value).trim().toLowerCase();
  if (v === 'https' || v === 'true' || v === '1') return 'https';
  if (v === 'http' || v === 'false' || v === '0') return 'http';
  return undefined;
}

// Gzips every response the client accepts gzip for - index.html (~300KB -> ~70KB),
// docs.html, and every JSON/CSV API response, all in one place instead of
// per-route. Hand-rolled on Node's built-in zlib rather than the `compression`
// npm package: this machine's corporate proxy rejects npm's registry TLS
// handshake even with its own root CA already in .npmrc, so a new dependency
// isn't installable here right now. Wraps res.write/res.end (not res.send) so it
// covers express.static's and res.sendFile's internal stream.pipe(res) too, not
// just routes that call res.send/res.json directly - and since it only ever acts
// on whatever bytes the wrapped handler actually sends, a 304 Not Modified (empty
// body) or an already-encoded response both pass through untouched.
const zlib = require('zlib');
const COMPRESSIBLE_MIN_BYTES = 1024;

function normalizeWriteArgs(chunk, encoding, callback) {
  if (typeof chunk === 'function') return { chunk: undefined, encoding: undefined, callback: chunk };
  if (typeof encoding === 'function') return { chunk, encoding: undefined, callback: encoding };
  return { chunk, encoding, callback };
}

function gzipResponses(req, res, next) {
  if (!String(req.headers['accept-encoding'] || '').includes('gzip')) return next();

  const chunks = [];
  const originalWrite = res.write.bind(res);
  const originalEnd = res.end.bind(res);
  let finished = false;

  function collect(chunk, encoding) {
    if (!chunk) return;
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, typeof encoding === 'string' ? encoding : undefined));
  }

  res.write = (chunkArg, encodingArg, callbackArg) => {
    const { chunk, encoding, callback } = normalizeWriteArgs(chunkArg, encodingArg, callbackArg);
    collect(chunk, encoding);
    if (callback) callback();
    return true;
  };

  res.end = (chunkArg, encodingArg, callbackArg) => {
    if (finished) return res;
    finished = true;
    const { chunk, encoding, callback } = normalizeWriteArgs(chunkArg, encodingArg, callbackArg);
    collect(chunk, encoding);
    const body = Buffer.concat(chunks);

    const alreadyEncoded = !!res.getHeader('Content-Encoding');
    if (body.length < COMPRESSIBLE_MIN_BYTES || alreadyEncoded) {
      if (body.length) res.setHeader('Content-Length', body.length);
      originalWrite(body);
      originalEnd();
      if (callback) callback();
      return res;
    }

    zlib.gzip(body, (err, compressed) => {
      if (err) {
        res.setHeader('Content-Length', body.length);
        originalWrite(body);
      } else {
        res.setHeader('Content-Encoding', 'gzip');
        res.setHeader('Content-Length', compressed.length);
        originalWrite(compressed);
      }
      originalEnd();
      if (callback) callback();
    });
    return res;
  };

  res.setHeader('Vary', 'Accept-Encoding');
  next();
}

app.use(gzipResponses);
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

app.get('/docs', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'docs.html'));
});

app.get('/api/health', async (req, res) => {
  let protector;
  try {
    protector = await checkProtectorReachability(req.query.protectorId, 3000, parseTransport(req.query.secure));
  } catch (err) {
    if (err.code === 'UNKNOWN_PROTECTOR') {
      return res.status(400).json({ error: err.message });
    }
    throw err;
  }
  res.json({
    status: 'ok',
    uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
    timestamp: new Date().toISOString(),
    protector: {
      // Host/port/token are intentionally omitted - never exposed to the browser.
      reachable: protector.reachable,
      checkedInMs: protector.elapsedMs,
      ...(protector.error ? { error: protector.error } : {}),
    },
  });
});

// Shared by GET /api/protectors and the periodic SSE health broadcaster below, so
// there's exactly one place that decides what a Protector's public status looks like.
async function buildProtectorStatus(transport) {
  const summaries = listProtectorSummaries();
  const withReachability = await Promise.all(
    summaries.map(async (p) => {
      if (p.disabled) {
        return { id: p.id, name: p.name, disabled: true, unavailableReason: p.unavailableReason, defaultTransport: p.defaultTransport };
      }
      const check = await checkProtectorReachability(p.id, 3000, transport);
      return {
        id: p.id,
        name: p.name,
        defaultTransport: p.defaultTransport,
        // Which scheme this reachability result actually describes - the pill would be
        // misleading otherwise, since http and https live on different ports.
        checkedTransport: transport || p.defaultTransport,
        reachable: check.reachable,
        checkedInMs: check.elapsedMs,
        ...(check.error ? { error: check.error } : {}),
      };
    })
  );
  return { protectors: withReachability, defaultProtectorId: config.defaultProtectorId };
}

app.get('/api/protectors', async (req, res) => {
  res.json(await buildProtectorStatus(parseTransport(req.query.secure)));
});

// Live updates over Server-Sent Events: new scans and Protector reachability changes
// are pushed to every connected tab instead of each tab polling on its own timer.
// SSE (not WebSocket) because this is one-directional server->browser push and the
// browser's native EventSource already handles reconnection - no new dependency.
app.get('/api/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no', // in case this ever sits behind a buffering reverse proxy
  });
  res.write('\n');

  const send = ({ event, data }) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };
  bus.on('message', send);

  // Keeps idle connections alive through any intermediary that closes on inactivity.
  // A line starting with ":" is a comment per the SSE spec - EventSource ignores it,
  // so this never triggers a client-side message event.
  const heartbeat = setInterval(() => res.write(': ping\n\n'), 25000);

  req.on('close', () => {
    clearInterval(heartbeat);
    bus.off('message', send);
  });
});

// Broadcasts Protector reachability only when it actually changes, so idle tabs
// aren't woken up every few seconds for no reason - this replaces each client's own
// polling interval for /api/protectors (see loadProtectors() in index.html).
//
// The change-detection digest deliberately excludes checkedInMs (the TCP round-trip
// time of the reachability probe): that number is essentially never identical
// between two checks even when nothing meaningful changed, so comparing the full
// status object - as an earlier version of this function did - broadcast on every
// single 10s tick regardless of whether anything a user would call a "change" had
// happened. Only id/name/reachable/disabled/unavailableReason/error drive the diff;
// the freshly-measured checkedInMs still goes out in the payload when a real change
// does trigger a broadcast.
function protectorStatusDigest(status) {
  return JSON.stringify(
    status.protectors.map((p) => ({
      id: p.id,
      name: p.name,
      reachable: p.reachable,
      disabled: p.disabled,
      unavailableReason: p.unavailableReason,
      error: p.error,
    }))
  );
}

let lastProtectorStatusDigest = null;
async function broadcastProtectorStatusIfChanged() {
  try {
    const status = await buildProtectorStatus();
    const digest = protectorStatusDigest(status);
    if (digest !== lastProtectorStatusDigest) {
      lastProtectorStatusDigest = digest;
      publish('protectors', status);
    }
  } catch (err) {
    console.error('Protector health broadcast failed:', err.message);
  }
}
setInterval(broadcastProtectorStatusIfChanged, 10000);

app.get('/api/history', (req, res) => {
  const q = req.query;
  const pageSizeRaw = q.pageSize || q.limit;
  res.json(
    queryHistory({
      from: q.from,
      to: q.to,
      protectorId: q.protectorId,
      verdict: q.verdict,
      dataChannel: q.dataChannel,
      fileName: q.fileName,
      minElapsedMs: q.minElapsedMs !== undefined ? parseInt(q.minElapsedMs, 10) : undefined,
      severity: q.severity,
      policyName: q.policyName,
      ruleName: q.ruleName,
      sortBy: q.sortBy,
      sortDir: q.sortDir,
      page: q.page ? parseInt(q.page, 10) : undefined,
      pageSize: pageSizeRaw ? parseInt(pageSizeRaw, 10) : undefined,
    })
  );
});

// Populates History's Severity/Policy/Rule filter dropdowns from values that have
// actually occurred - there is no endpoint onto the Protector's own policy
// configuration to list "every possible" value from instead. Registered before
// /api/history/:id for the same reason /analytics and /export.csv are.
app.get('/api/history/facets', (req, res) => {
  res.json(getHistoryFacets());
});

// Backs the "recent high-severity findings" dashboard panel.
app.get('/api/history/recent-high-severity', (req, res) => {
  const limit = req.query.limit !== undefined ? parseInt(req.query.limit, 10) : undefined;
  res.json({ findings: getRecentHighSeverityFindings(limit) });
});

// Registered before /api/history/:id - otherwise Express would match "analytics" as an :id.
app.get('/api/history/analytics', (req, res) => {
  const q = req.query;
  res.json(
    getAnalytics({ from: q.from, to: q.to, protectorId: q.protectorId, dataChannel: q.dataChannel, bucket: q.bucket })
  );
});

function csvEscape(value) {
  const s = value === undefined || value === null ? '' : String(value);
  return /["\n,]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

// Exports the Analytics dashboard itself (the aggregates), not the underlying rows -
// /api/history/export.csv already covers raw rows. Written as labelled sections in one
// file so it opens as a readable report in Excel rather than needing several downloads.
// Registered before /api/history/:id, same reason as /analytics above.
app.get('/api/history/analytics.csv', (req, res) => {
  const q = req.query;
  const a = getAnalytics({ from: q.from, to: q.to, protectorId: q.protectorId, dataChannel: q.dataChannel, bucket: q.bucket });
  const rows = [];
  const section = (title, header, data) => {
    rows.push([title]);
    rows.push(header);
    data.forEach((r) => rows.push(r));
    rows.push([]);
  };

  const s = a.summary;
  section('SUMMARY', ['Metric', 'Value'], [
    ['Total scans', s.totalScans],
    ['Blocked', s.totalBlocked],
    ['Block rate', (s.blockRate * 100).toFixed(1) + '%'],
    ['High-severity findings', s.highSeverityFindings],
    ['Errors', s.totalErrors],
    ['Error rate', (s.errorRate * 100).toFixed(1) + '%'],
    ['Median elapsed (ms)', s.medianElapsedMs],
    ['P95 elapsed (ms)', s.p95ElapsedMs],
    ['P99 elapsed (ms)', s.p99ElapsedMs],
    ['Slowest scan (ms)', s.maxElapsedMs],
    ['Unique files', s.uniqueFiles],
    ['Total bytes scanned', s.totalBytes],
  ]);

  if (a.previous) {
    section('PREVIOUS PERIOD (same length, immediately before)', ['Metric', 'Value'], [
      ['Total scans', a.previous.totalScans],
      ['Blocked', a.previous.totalBlocked],
      ['Block rate', (a.previous.blockRate * 100).toFixed(1) + '%'],
      ['High-severity findings', a.previous.highSeverityFindings],
      ['Errors', a.previous.totalErrors],
      ['Median elapsed (ms)', a.previous.medianElapsedMs],
    ]);
  }

  section(a.bucket === 'hour' ? 'TREND (per hour)' : 'TREND (per day)', ['Bucket', 'Total scans', 'Blocked', 'High severity'], a.trend.map((t) => [t.day, t.total, t.blocked, t.highSeverity]));
  section('VERDICT BREAKDOWN', ['Verdict', 'Count'], a.verdictBreakdown.map((v) => [v.verdict, v.count]));
  section('SEVERITY OF MATCHED RULES', ['Severity', 'Matches'], a.severityBreakdown.map((v) => [v.name, v.count]));
  section('VOLUME BY PROTECTOR', ['Protector', 'Scans'], a.byProtector.map((p) => [p.name, p.count]));
  section('VOLUME BY DATA CHANNEL', ['Channel', 'Scans'], a.byChannel.map((c) => [c.name, c.count]));
  section('TOP VIOLATED POLICIES', ['Policy', 'Rule matches', 'Total matches', 'High severity'], a.topPolicies.map((p) => [p.name, p.hits, p.totalMatches, p.highCount]));
  section('TOP VIOLATED RULES', ['Rule', 'Scans matched', 'Total matches', 'High severity'], a.topRules.map((r) => [r.name, r.hits, r.totalMatches, r.highCount]));
  section('MOST-SCANNED FILES', ['File', 'Scans', 'Blocked', 'High severity'], a.topFiles.map((f) => [f.name, f.count, f.blocked, f.highCount]));
  section('ACTIVITY BY HOUR OF DAY', ['Hour', 'Total scans', 'Blocked'], a.byHourOfDay.map((h) => [String(h.hour).padStart(2, '0') + ':00', h.total, h.blocked]));
  section(
    'PRIORITY FINDINGS (most recent high-severity)',
    ['Detected At', 'File', 'Policy', 'Rule', 'Matches', 'Protector', 'Global Message ID'],
    a.priorityFindings.map((f) => [f.timestamp, f.fileName, f.policyName, f.ruleName, f.matches, f.protectorName, f.globalMessageId])
  );

  const csv = '﻿' + rows.map((r) => r.map(csvEscape).join(',')).join('\r\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="dlp-analytics-report.csv"');
  res.send(csv);
});

const CSV_EXPORT_MAX_ROWS = 50000;
const CSV_HEADER = [
  'Timestamp', 'File Name', 'File Size (bytes)', 'Resolution', 'Highest Severity', 'Protector', 'Data Channel',
  'Source Host IPs', 'Source Host Name', 'Policies', 'Max Matches', 'Elapsed (ms)', 'HTTP Status', 'Error', 'Error Code',
];

// Registered before /api/history/:id, same reason as /analytics above.
app.get('/api/history/export.csv', (req, res) => {
  const q = req.query;
  // "Export selected" (bulk-select checkboxes in History) sends an explicit id list
  // instead of the usual filter fields - it means "exactly these rows", so it's kept
  // separate from fileName/date/etc. rather than combined with them.
  const ids = typeof q.ids === 'string' && q.ids.trim() ? q.ids.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
  const entries = getHistoryForExport(
    {
      from: q.from,
      to: q.to,
      protectorId: q.protectorId,
      verdict: q.verdict,
      dataChannel: q.dataChannel,
      fileName: q.fileName,
      minElapsedMs: q.minElapsedMs !== undefined ? parseInt(q.minElapsedMs, 10) : undefined,
      severity: q.severity,
      policyName: q.policyName,
      ruleName: q.ruleName,
      ids,
      sortBy: q.sortBy,
      sortDir: q.sortDir,
    },
    CSV_EXPORT_MAX_ROWS
  );

  const lines = [CSV_HEADER.map(csvEscape).join(',')];
  for (const e of entries) {
    const policies = (e.violations || []).map((v) => v.policyName || v.policyId).filter(Boolean).join('; ');
    lines.push(
      [
        e.timestamp,
        e.fileName,
        e.fileSizeBytes,
        e.resolution,
        e.highestSeverity || '',
        e.protectorName,
        e.dataChannel,
        e.source && e.source.host_ips ? e.source.host_ips.join(' ') : '',
        e.source && e.source.host_name ? e.source.host_name : '',
        policies,
        e.maxNumberOfMatches,
        e.elapsedMs,
        e.httpStatus,
        e.error,
        e.errorCode,
      ]
        .map(csvEscape)
        .join(',')
    );
  }

  // Leading BOM so Excel on Windows renders UTF-8 (Hebrew/emoji filenames etc.) correctly
  // instead of mojibake - a well-known Excel-specific quirk, not needed by other consumers.
  const csv = '\uFEFF' + lines.join('\r\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="dlp-history-export.csv"`);
  res.send(csv);
});

app.get('/api/history/:id', (req, res) => {
  const entry = getHistoryEntry(req.params.id);
  if (!entry) {
    return res.status(404).json({ error: 'No scan found with that id' });
  }
  res.json(entry);
});

app.get('/api/settings', (req, res) => {
  res.json({
    fields: getFieldStates(),
    effective: getSettings(),
    // What each field falls back to when its override is off - shown in the UI so
    // a disabled field isn't a mystery.
    defaults: getDefaults(),
    options: {
      dataChannel: DATA_CHANNEL_OPTIONS,
      webhookFormat: WEBHOOK_FORMAT_OPTIONS,
      webhookTriggerLevel: WEBHOOK_TRIGGER_OPTIONS,
      defaultTransport: TRANSPORT_OPTIONS,
    },
  });
});

app.post('/api/settings', (req, res) => {
  try {
    const fields = updateSettings(req.body || {});
    res.json({ fields, effective: getSettings() });
  } catch (err) {
    if (err.code === 'INVALID_SETTINGS') {
      return res.status(400).json({ error: `Invalid value(s) for: ${err.fields.join(', ')}` });
    }
    res.status(500).json({ error: `Unexpected error: ${err.message}` });
  }
});

// Sends a labelled test payload so a webhook can be proven to work from the Settings
// screen instead of being discovered broken during a real BLOCK. Accepts a URL in the
// body so it can be tested before saving.
app.post('/api/settings/test-webhook', async (req, res) => {
  const { url, format } = req.body || {};
  if (url !== undefined && typeof url !== 'string') {
    return res.status(400).json({ error: 'url must be a string' });
  }
  if (url && !/^https?:\/\/.+/i.test(url.trim())) {
    return res.status(400).json({ error: 'Must be a valid http(s):// URL' });
  }
  try {
    const result = await sendTestWebhook(url, format);
    res.json(result);
  } catch (err) {
    res.status(500).json({ ok: false, error: `Unexpected error: ${err.message}` });
  }
});

// Read-only view of what this process is actually running with. Deliberately scheme
// and posture only - host, port, and token are never exposed to the browser (same
// rule as /api/health and /api/protectors).
app.get('/api/runtime', (req, res) => {
  res.json({
    uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
    node: process.version,
    version: require('./package.json').version,
    // Lets the UI grey out the "Redact before scan" toggle with an explanation
    // instead of letting the user flip it on and get a 503 from /api/sanitize.
    keyPhraseRedactionEnabled: keyPhraseStore.isEnabled(),
    server: {
      httpsEnabled: !!config.server.https,
      port: config.server.port,
      httpRedirectPort: config.server.httpRedirectPort || null,
    },
    storage: {
      historyDbPath: config.historyDbPath,
      legacyLogPath: config.logFilePath,
    },
    protectors: config.protectors.map((p) => ({
      id: p.id,
      name: p.name,
      defaultTransport: p.protocol,
      httpPort: p.httpPort,
      httpsPort: p.httpsPort,
      // TLS posture for outbound HTTPS - the two things that decide whether a secure
      // send is actually authenticated rather than merely encrypted.
      caConfigured: !!p.caCert,
      certificateVerification: p.rejectUnauthorized,
      tlsServername: p.tlsServername || null,
      isDefault: p.id === config.defaultProtectorId,
      disabled: !!p.disabled,
      ...(p.disabled ? { unavailableReason: p.unavailableReason } : {}),
    })),
  });
});

// Read-only Semantic AI observability counters (src/aiMetrics.js) - see
// docs/semantic-dlp-architecture.md, Observability. In-process only, resets on
// restart. Never includes content, prompts, or evidence - counts and labels only.
app.get('/api/ai-metrics', (req, res) => {
  res.json({ aiDlpEnabled: config.semanticAi.enabled, mode: config.semanticAi.mode, ...aiMetrics.getSnapshot() });
});

app.post('/api/scan', (req, res) => {
  const maxFileSizeMb = getSettings().maxFileSizeMb;
  const upload = multer({ storage: memoryStorage, limits: { fileSize: maxFileSizeMb * 1024 * 1024 } });

  upload.single('file')(req, res, async (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({
          error: `File exceeds the maximum allowed size (${maxFileSizeMb}MB)`,
        });
      }
      return res.status(400).json({ error: `File upload error: ${err.message}` });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file was sent' });
    }

    const { size, buffer } = req.file;
    const originalname = fixFilenameEncoding(req.file.originalname);
    // Generated up front (rather than inside inspectFile) so the same id can be logged
    // on both success and failure - lets the History/Verdict Detail screens look up any
    // past attempt, including ones that timed out or never reached the Protector.
    const requestId = crypto.randomUUID();
    // scanOrchestrator starts Forcepoint and Semantic AI together under this one
    // scan_id (see docs/semantic-dlp-architecture.md) - forcepointPromise
    // resolves/rejects exactly as inspectFileWithFailover always has (nothing
    // below this line changed to accommodate it); aiAnalysisPromise never rejects.
    const { forcepointPromise, aiAnalysisPromise } = scanOrchestrator.startScan({
      buffer, fileName: originalname, scanId: requestId, clientIp: req.ip,
      protectorId: req.body.protectorId, transport: parseTransport(req.body.secure),
    });

    try {
      const result = await forcepointPromise;
      const { httpStatus, body, elapsedMs, globalMessageId, source, dataChannel, protectorId, protectorName, transport, failedOver, attemptedProtectors } = result;

      if (httpStatus < 200 || httpStatus >= 300) {
        const failedEntry = {
          globalMessageId,
          fileName: originalname,
          fileSizeBytes: size,
          resolution: null,
          httpStatus,
          elapsedMs,
          source,
          dataChannel,
          protectorId,
          protectorName,
          transport,
          ...(failedOver ? { failedOver, attemptedProtectors } : {}),
          error: `Protector returned HTTP ${httpStatus}`,
        };
        recordScanEvent(failedEntry);
        publish('scan', { ...failedEntry, timestamp: new Date().toISOString() });
        // aiAnalysis is additive on the HTTP response only - never persisted to
        // History/SSE in this milestone (see docs/semantic-dlp-architecture.md,
        // section 8), so failedEntry above is deliberately left as-is.
        const aiAnalysis = await aiAnalysisPromise;
        recordAiObservability(aiAnalysis, { scanId: requestId, dataChannel, fileSizeBytes: size });
        return res.status(502).json({
          error: `Protector returned an error (HTTP ${httpStatus})`,
          details: body,
          ...(aiAnalysis ? { aiAnalysis } : {}),
        });
      }

      const violations = Array.isArray(body.violations) ? body.violations : [];
      const actions = Array.isArray(body.actions) ? body.actions : [];

      const responsePayload = {
        globalMessageId,
        resolution: body.resolution || 'UNKNOWN',
        violations: violations.map((v) => ({
          policyId: v.policy_id,
          policyName: v.policy_name,
          rules: (v.violated_rules || []).map((r) => ({
            ruleId: r.rule_id,
            ruleName: r.rule_name,
            severity: r.rule_severity,
            matches: r.rule_number_of_matches,
          })),
        })),
        actions: actions.map((a) => a.action_type),
        maxNumberOfMatches: body.max_number_of_matches || 0,
        elapsedMs,
        fileName: originalname,
        fileSizeBytes: size,
        source,
        dataChannel,
        protectorId,
        protectorName,
        transport,
        ...(failedOver ? { failedOver, attemptedProtectors } : {}),
      };

      recordScanEvent({ ...responsePayload, httpStatus });
      publish('scan', { ...responsePayload, httpStatus, timestamp: new Date().toISOString() });

      // aiAnalysis is additive on the HTTP response only - added after the fields
      // above are built/recorded so History/SSE/webhooks are entirely unaffected by
      // it (see docs/semantic-dlp-architecture.md, section 8).
      const aiAnalysis = await aiAnalysisPromise;
      recordAiObservability(aiAnalysis, {
        scanId: requestId,
        forcepointMatched: responsePayload.resolution === 'MATCHED',
        dataChannel,
        fileSizeBytes: size,
      });
      res.json({ ...responsePayload, ...(aiAnalysis ? { aiAnalysis } : {}) });

      // Fire-and-forget: sent after the response so a slow/dead webhook endpoint
      // can never add latency to the user-facing scan. Failures are logged
      // server-side only, never surfaced as a scan failure.
      {
        const hasViolations = (responsePayload.violations || []).length > 0;
        const verdict = hasViolations && isBlockingAction(responsePayload.actions) ? 'block' : hasViolations ? 'warn' : 'pass';
        notifyScan(responsePayload, verdict).catch((err) => console.error('Webhook notify failed:', err.message));
      }
      return;
    } catch (error) {
      if (error.code === 'UNKNOWN_PROTECTOR' || error.code === 'PROTECTOR_DISABLED') {
        return res.status(400).json({ error: error.message });
      }

      console.error('Scan failed:', error);
      const safeMessage = sanitizeProtectorError(error);
      const elapsedMs = error.elapsedMs || 0;
      const failedEntry = {
        globalMessageId: requestId,
        fileName: originalname,
        fileSizeBytes: size,
        resolution: null,
        elapsedMs,
        protectorId: error.protectorId,
        protectorName: error.protectorName,
        ...(error.attemptedProtectors ? { attemptedProtectors: error.attemptedProtectors } : {}),
        error: safeMessage,
        errorCode: error.code || null,
      };
      recordScanEvent(failedEntry);
      publish('scan', { ...failedEntry, timestamp: new Date().toISOString() });

      // Forcepoint failing here (a connection error, a timeout, an unknown
      // Protector) has no bearing on whether the Semantic AI analysis of the same
      // bytes succeeded - it was started independently above and may well have
      // already completed. See docs/semantic-dlp-architecture.md.
      const aiAnalysis = await aiAnalysisPromise;
      recordAiObservability(aiAnalysis, { scanId: requestId, fileSizeBytes: size });
      const aiField = aiAnalysis ? { aiAnalysis } : {};

      if (error.code === 'TIMEOUT') {
        return res.status(504).json({ error: safeMessage, ...aiField });
      }
      if (isConnectionClassError(error)) {
        return res.status(502).json({ error: safeMessage, ...aiField });
      }
      return res.status(500).json({ error: safeMessage, ...aiField });
    }
  });
});

// Developer passthrough: sends a caller-supplied raw metadata JSON straight to the
// Protector, bypassing this app's own metadata construction (Settings, source
// auto-detection, etc). Still goes through this backend (never exposes the
// Protector's host/port/token to the browser) - just skips the app's own logic.
// Returns the Protector's raw, unprocessed response. Used by the "Try it out"
// panel in /docs.
app.post('/api/protector/raw', (req, res) => {
  const maxFileSizeMb = getSettings().maxFileSizeMb;
  const upload = multer({ storage: memoryStorage, limits: { fileSize: maxFileSizeMb * 1024 * 1024 } });

  upload.single('file')(req, res, async (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: `File exceeds the maximum allowed size (${maxFileSizeMb}MB)` });
      }
      return res.status(400).json({ error: `File upload error: ${err.message}` });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file was sent' });
    }
    if (!req.body.metadata) {
      return res.status(400).json({ error: 'No metadata JSON was sent' });
    }

    const wrap = req.body.wrap !== 'false';
    const originalname = fixFilenameEncoding(req.file.originalname);

    try {
      const result = await inspectRaw(req.body.metadata, req.file.buffer, originalname, wrap, req.body.protectorId, parseTransport(req.body.secure));
      return res.status(result.httpStatus).json(result.body);
    } catch (error) {
      if (error.code === 'INVALID_METADATA' || error.code === 'UNKNOWN_PROTECTOR' || error.code === 'PROTECTOR_DISABLED') {
        return res.status(400).json({ error: error.message });
      }
      console.error('Direct-to-Protector request failed:', error);
      const safeMessage = sanitizeProtectorError(error);
      if (error.code === 'TIMEOUT') {
        return res.status(504).json({ error: safeMessage });
      }
      if (isConnectionClassError(error)) {
        return res.status(502).json({ error: safeMessage });
      }
      return res.status(500).json({ error: safeMessage });
    }
  });
});

// Key Phrase Redaction: inspect -> (if MATCHED) redact configured phrases for the
// violated rule(s) -> re-inspect the redacted text -> only ever return content that
// Forcepoint has verified as clean. See src/sanitizationService.js for the full
// workflow; this route is a thin, additive wrapper - it does not touch history,
// webhooks, or the existing /api/scan file-upload flow at all.
// Reasons where Forcepoint genuinely matched real content and the app withheld it
// (either it still matched after redaction, or the local phrase config couldn't be
// trusted to have actually cleared it) - these get verdict='block', matching a
// normal scan's own DLP-decision block. Every other BLOCKED reason is an
// operational/config failure, not a content decision, and gets verdict='error'.
const SANITIZE_CONTENT_BLOCK_REASONS = new Set([
  BLOCK_REASONS.POST_REDACTION_DLP_MATCH,
  BLOCK_REASONS.UNMAPPED_RULE,
  BLOCK_REASONS.ZERO_REDACTIONS,
]);
const SANITIZE_ERROR_MESSAGES = {
  [BLOCK_REASONS.INSPECTION_FAILED]: 'The Protector could not be reached while redacting this content',
  [BLOCK_REASONS.INVALID_RESPONSE]: 'The Protector returned a response this app could not interpret',
  [BLOCK_REASONS.NO_IDENTIFIABLE_RULES]: 'The Protector matched a policy but returned no identifiable rule to redact',
  [BLOCK_REASONS.REDACTION_ERROR]: 'An internal error occurred while redacting matched content',
};

// Builds a recordScanEvent()-compatible entry from a sanitize() result, so a
// redact-then-scan attempt shows up in History/Analytics/Verdict Detail exactly
// like a normal scan does - see src/sanitizationService.js's sanitize() JSDoc for
// exactly which fields it echoes back and why. Returns null for the two reasons
// where no Protector was ever actually contacted (bad input, feature not
// configured) - there is no real scan attempt to record there.
function buildSanitizeHistoryEntry(result, { globalMessageId, fileName, fileSizeBytes, elapsedMs, protectorId, protectorName }) {
  const base = {
    globalMessageId, fileName, fileSizeBytes, elapsedMs,
    protectorId, protectorName: result.protectorName || protectorName,
    dataChannel: result.dataChannel, transport: result.transport, source: result.source,
  };
  if (result.status === 'CLEAN') {
    return { ...base, resolution: 'UNMATCHED', violations: [], actions: [] };
  }
  if (result.status === 'SANITIZED') {
    return {
      ...base,
      resolution: 'MATCHED',
      violations: result.violations || [],
      actions: [], // ultimately allowed through after redaction - never a blocking action
      maxNumberOfMatches: result.maxNumberOfMatches || 0,
    };
  }
  // BLOCKED
  if (result.reason === BLOCK_REASONS.INVALID_INPUT || result.reason === BLOCK_REASONS.FEATURE_NOT_CONFIGURED) {
    return null;
  }
  if (SANITIZE_CONTENT_BLOCK_REASONS.has(result.reason)) {
    return {
      ...base,
      resolution: 'MATCHED',
      violations: result.violations || [],
      actions: ['Block'],
      maxNumberOfMatches: result.maxNumberOfMatches || 0,
    };
  }
  return {
    ...base,
    resolution: null,
    error: SANITIZE_ERROR_MESSAGES[result.reason] || 'Redaction failed for an unknown reason',
    errorCode: result.reason,
  };
}

app.post('/api/sanitize', async (req, res) => {
  if (!keyPhraseStore.isEnabled()) {
    return res.status(503).json({ error: 'Key Phrase Redaction is not configured on this server' });
  }
  const { content, protectorId, fileName, fileSizeBytes } = req.body || {};
  if (typeof content !== 'string') {
    return res.status(400).json({ error: 'content must be a string' });
  }

  const globalMessageId = crypto.randomUUID();
  const startedAt = Date.now();
  try {
    const result = await sanitizationService.sanitize(content, {
      protectorId,
      transport: parseTransport(req.body && req.body.secure),
      clientIp: req.ip,
    });

    const resolvedProtectorId = protectorId || config.defaultProtectorId;
    const entry = buildSanitizeHistoryEntry(result, {
      globalMessageId,
      // No fixFilenameEncoding() here (unlike /api/scan's multer-sourced filename) -
      // this arrives as a JSON string body field, which express.json() already
      // decodes correctly as UTF-8; that fixup exists only for multer/busboy's
      // Latin-1-by-default multipart field decoding, and would corrupt this one.
      fileName: typeof fileName === 'string' ? fileName : undefined,
      fileSizeBytes: typeof fileSizeBytes === 'number' ? fileSizeBytes : undefined,
      elapsedMs: Date.now() - startedAt,
      protectorId: resolvedProtectorId,
      protectorName: config.protectors.find((p) => p.id === resolvedProtectorId)?.name,
    });
    if (entry) {
      recordScanEvent(entry);
      publish('scan', { ...entry, timestamp: new Date().toISOString() });
    }

    // Normalized result only - never the raw Forcepoint response, and BLOCKED never
    // carries content (sanitizationService already enforces this; nothing to redo here).
    res.json(result);
  } catch (err) {
    // Reaching here means sanitizationService itself threw, which it isn't designed
    // to do (every expected failure mode resolves to a BLOCKED result) - so this is
    // an actual bug, not a DLP verdict. Never leak err.message/stack to the caller.
    console.error('Sanitization request failed unexpectedly:', err);
    res.status(500).json({ error: 'Unexpected error while sanitizing content' });
  }
});

// Read/write the Key Phrase Redaction dictionary from the Settings UI, instead of
// hand-editing config/key-phrases.json on the host. A save is validated (via
// buildConfig, same as at boot) before anything is written, and takes effect on the
// very next scan - see keyPhraseStore.js's saveRaw()/getCompiled() for why this
// needs no restart.
app.get('/api/key-phrases', (req, res) => {
  const enabled = keyPhraseStore.isEnabled();
  res.json({
    enabled,
    config: enabled ? keyPhraseStore.getRaw() : null,
    // Real rule names this app has actually seen fire, so the UI can offer a
    // dropdown instead of requiring an exact, hand-typed match - Forcepoint has no
    // "list configured policies" endpoint this app can query up front (see
    // getHistoryFacets()'s own comment on this same limitation).
    knownRuleNames: getHistoryFacets().rules,
    validators: Object.keys(KEY_PHRASE_VALIDATORS),
  });
});

app.put('/api/key-phrases', (req, res) => {
  if (!keyPhraseStore.isEnabled()) {
    return res.status(503).json({ error: 'Key Phrase Redaction is not configured on this server' });
  }
  try {
    const saved = keyPhraseStore.saveRaw(req.body || {});
    res.json({ config: saved });
  } catch (err) {
    // err.details (see keyPhraseConfig.js's throwIfAny) is the plain list of
    // problems when this is a validation failure; a thrown error with no .details
    // is an actual bug (e.g. a disk write failure), not a bad edit.
    if (err.details) {
      return res.status(400).json({ error: err.message, details: err.details });
    }
    console.error('Saving Key Phrase config failed unexpectedly:', err);
    res.status(500).json({ error: 'Unexpected error while saving the Key Phrase dictionary' });
  }
});

function logStartup(scheme) {
  console.log(`DLP Protector client listening on ${scheme}://localhost:${config.server.port}`);
  config.protectors.forEach((p) => {
    const isDefault = p.id === config.defaultProtectorId ? ' (default)' : '';
    console.log(`  - ${p.name}${isDefault}: ${p.protocol}://${p.host}:${p.port}/inspection/v4.0`);
  });
}

if (config.server.https) {
  https.createServer(config.server.https, app).listen(config.server.port, () => {
    logStartup('https');

    // Optional plaintext listener that does nothing but redirect to the HTTPS URL,
    // so an existing http:// bookmark still lands somewhere useful instead of
    // failing with a confusing TLS error. Reuses the requested Host header (minus
    // any port) so this works whatever hostname/IP the app is reached by.
    if (config.server.httpRedirectPort) {
      http
        .createServer((req, res) => {
          const host = String(req.headers.host || 'localhost').replace(/:\d+$/, '');
          const target = `https://${host}:${config.server.port}${req.url}`;
          res.writeHead(301, { Location: target });
          res.end();
        })
        .listen(config.server.httpRedirectPort, () => {
          console.log(`  (http://localhost:${config.server.httpRedirectPort} redirects to https)`);
        });
    }
  });
} else {
  app.listen(config.server.port, () => logStartup('http'));
}
