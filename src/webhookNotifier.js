const http = require('http');
const https = require('https');
const { getSettings } = require('./settingsStore');

const WEBHOOK_TIMEOUT_MS = 5000;

function buildPayload(format, entry) {
  const policyNames = (entry.violations || []).map((v) => v.policyName || v.policyId).filter(Boolean);
  const summary =
    `DLP scan blocked: "${entry.fileName || 'unknown file'}"` +
    (policyNames.length ? ` (policies: ${policyNames.join(', ')})` : '') +
    (entry.protectorName ? ` via ${entry.protectorName}` : '');

  if (format === 'slack') {
    return { text: summary };
  }
  if (format === 'teams') {
    return {
      '@type': 'MessageCard',
      '@context': 'http://schema.org/extensions',
      summary,
      title: 'DLP scan blocked',
      text: summary,
    };
  }
  // 'generic' - the scan's own response shape, so a receiving system gets full detail.
  return {
    event: 'dlp.scan.blocked',
    globalMessageId: entry.globalMessageId,
    fileName: entry.fileName,
    resolution: entry.resolution,
    violations: entry.violations,
    protectorId: entry.protectorId,
    protectorName: entry.protectorName,
    dataChannel: entry.dataChannel,
  };
}

function postJson(url, payload) {
  return new Promise((resolve) => {
    let target;
    try {
      target = new URL(url);
    } catch (err) {
      return resolve({ ok: false, error: 'Malformed webhook URL' });
    }
    const transport = target.protocol === 'https:' ? https : http;
    const body = JSON.stringify(payload);
    const req = transport.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (target.protocol === 'https:' ? 443 : 80),
        path: target.pathname + target.search,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        timeout: WEBHOOK_TIMEOUT_MS,
      },
      (res) => {
        res.resume(); // drain, we don't care about the response body
        resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode });
      }
    );
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: `Timed out after ${WEBHOOK_TIMEOUT_MS}ms` }); });
    req.on('error', (err) => resolve({ ok: false, error: err.code || err.message }));
    req.end(body);
  });
}

/**
 * Fire-and-forget webhook POST for a scan that resolved to BLOCK. Must be called
 * only after the scan's own HTTP response has already been sent - never awaited
 * by the request path, so a slow/dead webhook endpoint can't add latency to a
 * user-facing scan. Any failure here is swallowed by the caller's .catch, not
 * propagated as a scan failure.
 *
 * @param {object} entry - the same object shape as /api/scan's success response
 */
async function notifyBlock(entry) {
  const settings = getSettings();
  if (!settings.webhookUrl) return; // disabled (see settingsStore.js DEFAULTS.webhookUrl)
  const payload = buildPayload(settings.webhookFormat, entry);
  await postJson(settings.webhookUrl, payload);
}

/**
 * Decides whether a finished scan should fire the webhook, honouring the configured
 * trigger level, then sends it. Keeps the "which verdicts count" rule in one place
 * instead of leaving it implicit at the call site in server.js.
 *
 * @param {object} entry - /api/scan's success response shape
 * @param {'block'|'warn'|'pass'|'error'} verdict
 */
async function notifyScan(entry, verdict) {
  const settings = getSettings();
  if (!settings.webhookUrl) return;
  const wanted = settings.webhookTriggerLevel === 'block_and_flagged' ? ['block', 'warn'] : ['block'];
  if (!wanted.includes(verdict)) return;
  await postJson(settings.webhookUrl, buildPayload(settings.webhookFormat, entry));
}

/**
 * Sends a clearly-labelled synthetic payload and RETURNS the outcome, so the Settings
 * screen can tell the user whether their webhook actually works instead of leaving
 * them to discover it during a real incident.
 *
 * @param {string} [url] - test this URL instead of the saved one (lets the user verify
 *   before saving). Falls back to the saved setting.
 * @param {string} [format]
 * @returns {Promise<{ok: boolean, status?: number, error?: string}>}
 */
async function sendTestWebhook(url, format) {
  const settings = getSettings();
  const target = (url || settings.webhookUrl || '').trim();
  if (!target) return { ok: false, error: 'No webhook URL configured' };

  const sample = {
    globalMessageId: 'test-' + Date.now(),
    fileName: 'webhook-test.txt',
    resolution: 'MATCHED',
    violations: [{ policyId: 'TEST', policyName: 'Webhook connectivity test' }],
    protectorName: 'Settings test',
    dataChannel: settings.dataChannel,
  };
  const payload = buildPayload(format || settings.webhookFormat, sample);
  // Marked so a receiving system (and whoever reads the channel) can tell this
  // apart from a real BLOCK.
  if (payload.text) payload.text = '[TEST] ' + payload.text;
  if (payload.event) payload.event = 'dlp.scan.test';
  if (payload.title) payload.title = '[TEST] ' + payload.title;

  return postJson(target, payload);
}

module.exports = { notifyBlock, notifyScan, sendTestWebhook };
