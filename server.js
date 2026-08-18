const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const config = require('./src/config');
const { inspectFileWithFailover, inspectRaw, checkProtectorReachability, listProtectorSummaries, isConnectionClassError } = require('./src/protectorClient');
const { getSettings, getFieldStates, updateSettings, DATA_CHANNEL_OPTIONS, WEBHOOK_FORMAT_OPTIONS } = require('./src/settingsStore');
const {
  getHistoryEntry,
  queryHistory,
  getHistoryForExport,
  getAnalytics,
  recordScanEvent,
  isBlockingAction,
  migrateFromJsonlIfNeeded,
} = require('./src/historyStore');
const { notifyBlock } = require('./src/webhookNotifier');

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
function sanitizeProtectorError(error) {
  if (error.code === 'TIMEOUT') {
    return 'Timed out waiting for a response from the Protector';
  }
  if (isConnectionClassError(error)) {
    return `Unable to connect to the Protector (${error.code})`;
  }
  if (error.code === 'INVALID_RESPONSE') {
    return 'Protector returned a response this app could not parse';
  }
  return 'Unexpected error while contacting the Protector';
}

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

app.get('/docs', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'docs.html'));
});

app.get('/api/health', async (req, res) => {
  let protector;
  try {
    protector = await checkProtectorReachability(req.query.protectorId);
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

app.get('/api/protectors', async (req, res) => {
  const summaries = listProtectorSummaries();
  const withReachability = await Promise.all(
    summaries.map(async (p) => {
      if (p.disabled) {
        return { id: p.id, name: p.name, disabled: true, unavailableReason: p.unavailableReason };
      }
      const check = await checkProtectorReachability(p.id);
      return {
        id: p.id,
        name: p.name,
        reachable: check.reachable,
        checkedInMs: check.elapsedMs,
        ...(check.error ? { error: check.error } : {}),
      };
    })
  );
  res.json({ protectors: withReachability, defaultProtectorId: config.defaultProtectorId });
});

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
      sortBy: q.sortBy,
      sortDir: q.sortDir,
      page: q.page ? parseInt(q.page, 10) : undefined,
      pageSize: pageSizeRaw ? parseInt(pageSizeRaw, 10) : undefined,
    })
  );
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

const CSV_EXPORT_MAX_ROWS = 50000;
const CSV_HEADER = [
  'Timestamp', 'File Name', 'File Size (bytes)', 'Resolution', 'Protector', 'Data Channel',
  'Source Host IPs', 'Source Host Name', 'Policies', 'Max Matches', 'Elapsed (ms)', 'HTTP Status', 'Error', 'Error Code',
];

// Registered before /api/history/:id, same reason as /analytics above.
app.get('/api/history/export.csv', (req, res) => {
  const q = req.query;
  const entries = getHistoryForExport(
    {
      from: q.from,
      to: q.to,
      protectorId: q.protectorId,
      verdict: q.verdict,
      dataChannel: q.dataChannel,
      fileName: q.fileName,
      minElapsedMs: q.minElapsedMs !== undefined ? parseInt(q.minElapsedMs, 10) : undefined,
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
    options: { dataChannel: DATA_CHANNEL_OPTIONS, webhookFormat: WEBHOOK_FORMAT_OPTIONS },
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

    try {
      const result = await inspectFileWithFailover(buffer, originalname, req.ip, requestId, req.body.protectorId);
      const { httpStatus, body, elapsedMs, globalMessageId, source, dataChannel, protectorId, protectorName, failedOver, attemptedProtectors } = result;

      if (httpStatus < 200 || httpStatus >= 300) {
        recordScanEvent({
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
          ...(failedOver ? { failedOver, attemptedProtectors } : {}),
          error: `Protector returned HTTP ${httpStatus}`,
        });
        return res.status(502).json({
          error: `Protector returned an error (HTTP ${httpStatus})`,
          details: body,
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
        ...(failedOver ? { failedOver, attemptedProtectors } : {}),
      };

      recordScanEvent({ ...responsePayload, httpStatus });

      res.json(responsePayload);

      // Fire-and-forget: sent after the response so a slow/dead webhook endpoint
      // can never add latency to the user-facing scan. Failures are logged
      // server-side only, never surfaced as a scan failure.
      if (isBlockingAction(responsePayload.actions)) {
        notifyBlock(responsePayload).catch((err) => console.error('Webhook notify failed:', err.message));
      }
      return;
    } catch (error) {
      if (error.code === 'UNKNOWN_PROTECTOR' || error.code === 'PROTECTOR_DISABLED') {
        return res.status(400).json({ error: error.message });
      }

      console.error('Scan failed:', error);
      const safeMessage = sanitizeProtectorError(error);
      const elapsedMs = error.elapsedMs || 0;
      recordScanEvent({
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
      });

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
      const result = await inspectRaw(req.body.metadata, req.file.buffer, originalname, wrap, req.body.protectorId);
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
