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
      return resolve();
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
        resolve();
      }
    );
    req.on('timeout', () => req.destroy());
    req.on('error', () => {}); // fire-and-forget - failures are the caller's problem to log, not surface to the user
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

module.exports = { notifyBlock };
