const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const config = require('./src/config');
const { inspectFile, inspectRaw, checkProtectorReachability } = require('./src/protectorClient');
const { logScanEvent } = require('./src/logger');
const { getSettings, getFieldStates, updateSettings, DATA_CHANNEL_OPTIONS } = require('./src/settingsStore');
const { getHistory, getHistoryEntry } = require('./src/historyStore');

const app = express();
const memoryStorage = multer.memoryStorage();
const startedAt = Date.now();

// multer/busboy decode multipart filenames as Latin-1 by default (per the original
// multipart spec), but browsers send non-ASCII filenames (Hebrew, emoji, etc.) as raw
// UTF-8 bytes - so every multi-byte character comes out garbled unless re-decoded here.
function fixFilenameEncoding(name) {
  return Buffer.from(name, 'latin1').toString('utf8');
}

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

app.get('/docs', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'docs.html'));
});

app.get('/api/health', async (req, res) => {
  const protector = await checkProtectorReachability();
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

app.get('/api/history', (req, res) => {
  const limit = Math.max(1, Math.min(500, parseInt(req.query.limit, 10) || 50));
  res.json(getHistory(limit));
});

app.get('/api/history/:id', (req, res) => {
  const entry = getHistoryEntry(req.params.id);
  if (!entry) {
    return res.status(404).json({ error: 'No scan found with that id' });
  }
  res.json(entry);
});

app.get('/api/settings', (req, res) => {
  res.json({ fields: getFieldStates(), effective: getSettings(), options: { dataChannel: DATA_CHANNEL_OPTIONS } });
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
      const result = await inspectFile(buffer, originalname, req.ip, requestId);
      const { httpStatus, body, elapsedMs, globalMessageId, source, dataChannel } = result;

      if (httpStatus < 200 || httpStatus >= 300) {
        logScanEvent({
          globalMessageId,
          fileName: originalname,
          fileSizeBytes: size,
          resolution: null,
          httpStatus,
          elapsedMs,
          source,
          dataChannel,
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
      };

      logScanEvent({ ...responsePayload, httpStatus });

      return res.json(responsePayload);
    } catch (error) {
      const elapsedMs = error.elapsedMs || 0;
      logScanEvent({
        globalMessageId: requestId,
        fileName: originalname,
        fileSizeBytes: size,
        resolution: null,
        elapsedMs,
        error: error.message,
        errorCode: error.code || null,
      });

      if (error.code === 'TIMEOUT') {
        return res.status(504).json({ error: 'Timed out waiting for a response from the Protector' });
      }
      if (error.code === 'ECONNREFUSED' || error.code === 'EHOSTUNREACH' || error.code === 'ENOTFOUND') {
        return res.status(502).json({ error: `Unable to connect to the Protector (${error.code})` });
      }
      return res.status(500).json({ error: `Unexpected error: ${error.message}` });
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
      const result = await inspectRaw(req.body.metadata, req.file.buffer, originalname, wrap);
      return res.status(result.httpStatus).json(result.body);
    } catch (error) {
      if (error.code === 'INVALID_METADATA') {
        return res.status(400).json({ error: error.message });
      }
      if (error.code === 'TIMEOUT') {
        return res.status(504).json({ error: 'Timed out waiting for a response from the Protector' });
      }
      if (error.code === 'ECONNREFUSED' || error.code === 'EHOSTUNREACH' || error.code === 'ENOTFOUND') {
        return res.status(502).json({ error: `Unable to connect to the Protector (${error.code})` });
      }
      return res.status(500).json({ error: `Unexpected error: ${error.message}` });
    }
  });
});

app.listen(config.server.port, () => {
  console.log(`DLP Protector client listening on http://localhost:${config.server.port}`);
  console.log(
    `Configured to send inspection requests to ${config.protector.protocol}://${config.protector.host}:${config.protector.port}/inspection/v4.0`
  );
});
