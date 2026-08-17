const express = require('express');
const multer = require('multer');
const path = require('path');
const config = require('./src/config');
const { inspectFile } = require('./src/protectorClient');
const { logScanEvent } = require('./src/logger');
const { getSettings, getFieldStates, updateSettings } = require('./src/settingsStore');

const app = express();
const memoryStorage = multer.memoryStorage();

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

app.get('/docs', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'docs.html'));
});

app.get('/api/settings', (req, res) => {
  res.json({ fields: getFieldStates(), effective: getSettings() });
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

    const { originalname, size, buffer } = req.file;

    try {
      const result = await inspectFile(buffer, originalname, req.ip);
      const { httpStatus, body, elapsedMs, globalMessageId } = result;

      if (httpStatus < 200 || httpStatus >= 300) {
        logScanEvent({
          fileName: originalname,
          sizeBytes: size,
          resolution: null,
          httpStatus,
          elapsedMs,
          error: `Protector returned HTTP ${httpStatus}`,
        });
        return res.status(502).json({
          error: `Protector returned an error (HTTP ${httpStatus})`,
          details: body,
        });
      }

      const violations = Array.isArray(body.violations) ? body.violations : [];
      const actions = Array.isArray(body.actions) ? body.actions : [];

      logScanEvent({
        fileName: originalname,
        sizeBytes: size,
        resolution: body.resolution || null,
        globalMessageId,
        httpStatus,
        elapsedMs,
        violationCount: violations.length,
      });

      return res.json({
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
      });
    } catch (error) {
      const elapsedMs = error.elapsedMs || 0;
      logScanEvent({
        fileName: originalname,
        sizeBytes: size,
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

app.listen(config.server.port, () => {
  console.log(`DLP Protector client listening on http://localhost:${config.server.port}`);
  console.log(
    `Configured to send inspection requests to ${config.protector.protocol}://${config.protector.host}:${config.protector.port}/inspection/v4.0`
  );
});
