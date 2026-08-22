const http = require('http');
const https = require('https');
const net = require('net');
const crypto = require('crypto');
const os = require('os');
const path = require('path');
const FormData = require('form-data');
const config = require('./config');
const { getSettings } = require('./settingsStore');

const EXTENSION_MIME_TYPES = {
  '.txt': 'text/plain',
  '.csv': 'text/csv',
  '.json': 'application/json',
  '.xml': 'application/xml',
  '.html': 'text/html',
  '.pdf': 'application/pdf',
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.ppt': 'application/vnd.ms-powerpoint',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  '.zip': 'application/zip',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
};

function guessMimeType(fileName) {
  return EXTENSION_MIME_TYPES[path.extname(fileName).toLowerCase()] || 'application/octet-stream';
}

// Error codes that mean "this Protector didn't answer" (network/connect/timeout level)
// as opposed to "this Protector answered, just with an error/unparseable response."
// Shared by server.js's sanitizeProtectorError/status-code mapping and by
// inspectFileWithFailover below, so both agree on what counts as failover-worthy.
const CONNECTION_ERROR_CODES = new Set(['ECONNREFUSED', 'EHOSTUNREACH', 'ENOTFOUND', 'ETIMEDOUT', 'ECONNRESET', 'TIMEOUT']);

function isConnectionClassError(error) {
  return CONNECTION_ERROR_CODES.has(error.code);
}

// TLS handshake/verification failures. Deliberately NOT part of CONNECTION_ERROR_CODES:
// a TLS failure means we reached the appliance but could not trust it, and silently
// failing over to a different Protector on that basis could end up sending the same
// bytes somewhere the user didn't intend. These surface as their own actionable error.
const TLS_ERROR_CODES = new Set([
  'SELF_SIGNED_CERT_IN_CHAIN',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'CERT_HAS_EXPIRED',
  'CERT_NOT_YET_VALID',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'ERR_SSL_WRONG_VERSION_NUMBER',
  'EPROTO',
]);

function isTlsError(error) {
  return TLS_ERROR_CODES.has(error.code);
}

/**
 * Resolves the transport a request should actually use, and returns a copy of the
 * Protector with `protocol`/`port` set accordingly.
 *
 * The Inspection API serves both schemes (http :8080 / https :8443), so the caller
 * may override the .env-configured default per request - that is what backs the
 * "send securely" toggle in the UI. `undefined` keeps the configured default.
 *
 * @param {object} protector - entry from resolveProtector
 * @param {'http'|'https'} [transport]
 * @returns {object} effective protector (never mutates the config entry)
 */
function withTransport(protector, transport) {
  const protocol = transport === 'https' || transport === 'http' ? transport : protector.protocol;
  const port = protocol === 'https'
    ? (protector.httpsPort ?? protector.port)
    : (protector.httpPort ?? protector.port);
  return { ...protector, protocol, port };
}

/**
 * Looks up a configured Protector by id, falling back to the configured default
 * when no id is given. Throws a clear, mappable error for an unknown id rather
 * than silently falling back - the caller asked for a specific target.
 *
 * @param {string} [protectorId]
 * @returns {{id: string, name: string, protocol: string, host: string, port: number, token: string, caCert?: Buffer, rejectUnauthorized: boolean}}
 */
function resolveProtector(protectorId) {
  const id = protectorId || config.defaultProtectorId;
  const protector = config.protectors.find((p) => p.id === id);
  if (!protector) {
    throw Object.assign(new Error(`Unknown protectorId: "${protectorId}"`), { code: 'UNKNOWN_PROTECTOR' });
  }
  return protector;
}

/**
 * Safe-to-expose summary of every configured Protector - id + name (+ disabled state)
 * only, never host/port/token. Used by GET /api/protectors to populate the "Send to" picker.
 */
function listProtectorSummaries() {
  return config.protectors.map((p) => ({
    id: p.id,
    name: p.name,
    // Scheme only - never the host/port/token. The UI needs to know which transport a
    // Protector defaults to (so the secure toggle can reflect reality) without this
    // endpoint becoming a way to enumerate appliance addresses from the browser.
    defaultTransport: p.protocol,
    tlsVerified: p.protocol === 'https' || !!p.caCert ? p.rejectUnauthorized : undefined,
    ...(p.disabled ? { disabled: true, unavailableReason: p.unavailableReason } : {}),
  }));
}

/**
 * Builds a synthetic captured-HTTP-transaction buffer for the "0" content
 * part, as required by the Inspection API's `application/http` content type:
 * an HTTP-style header block followed by a nested multipart/form-data body
 * containing the actual file, mimicking a web upload transaction (see the
 * Forcepoint "Complete HTTP Web Inspection Request Sample").
 */
function buildHttpWrappedUpload(fileBuffer, fileName) {
  const nestedBoundary = `----WebKitFormBoundary${crypto.randomBytes(16).toString('hex')}`;
  const mimeType = guessMimeType(fileName);

  const nestedBody = Buffer.concat([
    Buffer.from(
      `--${nestedBoundary}\r\n` +
        `Content-Disposition: form-data; name="file"; filename="${fileName}"\r\n` +
        `Content-Type: ${mimeType}\r\n\r\n`,
      'utf8'
    ),
    fileBuffer,
    Buffer.from(`\r\n--${nestedBoundary}--\r\n`, 'utf8'),
  ]);

  const httpHeaders =
    `Accept: application/json\r\n` +
    `Content-Type: multipart/form-data; boundary=${nestedBoundary}\r\n` +
    `\r\n`;

  return Buffer.concat([Buffer.from(httpHeaders, 'utf8'), nestedBody]);
}

/**
 * Low-level sender: POSTs a pre-built metadata object + file buffer to the
 * Protector's Inspection API and returns the raw (unreshaped) response. Shared
 * by the normal app flow (inspectFile) and the raw developer passthrough
 * (inspectRaw) so both send bytes-for-bytes the same way.
 *
 * @param {object} metadata - the full metadata object (context/contentDescriptors/source/destinations)
 * @param {Buffer} filePartBuffer - the exact bytes to send as the "0" form-data part
 * @param {string} fileName - filename to use for the "0" part
 * @param {object} protector - resolved Protector entry (see resolveProtector) to send to
 * @returns {Promise<{httpStatus: number, body: object, elapsedMs: number}>}
 */
async function sendToProtector(metadata, filePartBuffer, fileName, protector) {
  const settings = getSettings();
  const form = new FormData();
  form.append('metadata', JSON.stringify(metadata), {
    contentType: 'application/json',
    filename: 'metadata.json',
  });
  form.append('0', filePartBuffer, {
    contentType: 'application/http',
    filename: fileName,
  });

  const headers = form.getHeaders();
  headers['Content-Length'] = form.getLengthSync();
  if (protector.token) {
    headers['Authorization'] = `Bearer ${protector.token}`;
  }

  const requestOptions = {
    protocol: protector.protocol === 'https' ? 'https:' : 'http:',
    hostname: protector.host,
    port: protector.port,
    path: '/inspection/v4.0',
    method: 'POST',
    headers,
    timeout: settings.requestTimeoutMs,
  };

  if (protector.protocol === 'https') {
    requestOptions.ca = protector.caCert;
    requestOptions.rejectUnauthorized = protector.rejectUnauthorized;
    // Verify the certificate against a configured name rather than the address we
    // dialled. Protector certs are typically issued to a hostname (and often carry
    // no subjectAltName at all) while this app connects by IP, which otherwise fails
    // with ERR_TLS_CERT_ALTNAME_INVALID even when the chain itself is perfectly good.
    // Setting servername also sets SNI, and Node's default identity check honours it.
    if (protector.tlsServername) {
      requestOptions.servername = protector.tlsServername;
    }
  }

  const transport = protector.protocol === 'https' ? https : http;
  const startedAt = Date.now();

  return new Promise((resolve, reject) => {
    const req = transport.request(requestOptions, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const elapsedMs = Date.now() - startedAt;
        const rawBody = Buffer.concat(chunks).toString('utf8');
        let parsedBody;
        try {
          parsedBody = rawBody ? JSON.parse(rawBody) : {};
        } catch (err) {
          return reject(
            Object.assign(new Error(`Protector returned non-JSON response (HTTP ${res.statusCode}): ${rawBody.slice(0, 500)}`), {
              code: 'INVALID_RESPONSE',
              httpStatus: res.statusCode,
              elapsedMs,
            })
          );
        }
        resolve({ httpStatus: res.statusCode, body: parsedBody, elapsedMs });
      });
    });

    req.on('timeout', () => {
      req.destroy(Object.assign(new Error('Request to Protector timed out'), { code: 'TIMEOUT' }));
    });

    req.on('error', (err) => {
      reject(Object.assign(err, { elapsedMs: Date.now() - startedAt }));
    });

    form.pipe(req);
  });
}

/**
 * Sends a file to the Forcepoint DLP Protector Inspection REST API (v4.0)
 * and returns the parsed response along with timing info.
 *
 * @param {Buffer} fileBuffer - raw file content (never written to disk)
 * @param {string} originalName - original filename as uploaded by the user
 * @param {string} [requestId] - pre-generated id to use as global_message_id, so the
 *   caller can log the same id on both success and failure (network errors, timeouts).
 *   Defaults to a fresh UUID if not supplied.
 * @param {string} [protectorId] - which configured Protector to send to. Defaults to
 *   config.defaultProtectorId. Throws (code UNKNOWN_PROTECTOR) if given an unrecognized id.
 * @param {'http'|'https'} [transport] - override the scheme for this request only
 *   (the Inspection API serves both). Omit to use the Protector's configured default.
 * @returns {Promise<{httpStatus: number, body: object, elapsedMs: number, globalMessageId: string}>}
 */
async function inspectFile(fileBuffer, originalName, clientIp, requestId, protectorId, transport) {
  const protector = withTransport(resolveProtector(protectorId), transport);
  if (protector.disabled) {
    throw Object.assign(new Error(`${protector.name} is unavailable: ${protector.unavailableReason}`), {
      code: 'PROTECTOR_DISABLED',
      protectorId: protector.id,
      protectorName: protector.name,
    });
  }
  const settings = getSettings();
  const globalMessageId = requestId || crypto.randomUUID();
  const httpWrappedFile = buildHttpWrappedUpload(fileBuffer, originalName);

  const metadata = {
    context: {
      global_message_id: globalMessageId,
      client_name: 'CUSTOM_APPLICATION',
      data_channel: settings.dataChannel,
      activity_type: 'UPLOAD',
      occurred_message_timestamp_utc_ms: Date.now(),
    },
    contentDescriptors: [
      {
        id: '0',
        name: originalName,
        item_type: 'FILE',
        size_bytes: httpWrappedFile.length,
      },
    ],
    // Only include the fields the user actually enabled - so testing with just an IP or
    // just a hostname doesn't silently include the other one via auto-detection. If neither
    // is enabled, fall back to auto-detecting both (the zero-config default).
    source: (() => {
      const source = {};
      if (settings.hostIps) {
        source.host_ips = settings.hostIps.split(',').map((ip) => ip.trim());
      }
      if (settings.hostName) {
        source.host_name = settings.hostName;
      }
      if (!source.host_ips && !source.host_name) {
        source.host_ips = [clientIp || '127.0.0.1'];
        source.host_name = os.hostname();
      }
      return source;
    })(),
    destinations: [
      {
        destination_type: 'WEB_APPLICATION',
        http_request_url: settings.destinationHttpUrl,
        http_request_url_hostname: settings.destinationHttpHostname,
        http_request_method: 'POST',
      },
    ],
  };

  try {
    const result = await sendToProtector(metadata, httpWrappedFile, originalName, protector);
    return {
      ...result,
      globalMessageId,
      source: metadata.source,
      dataChannel: metadata.context.data_channel,
      protectorId: protector.id,
      protectorName: protector.name,
      transport: protector.protocol,
    };
  } catch (err) {
    // Attach which Protector this attempt targeted even on failure (timeout, connection
    // refused, ...) so a failed scan is still identifiable in history when there's more
    // than one Protector configured. The transport goes along too - "it failed" reads
    // very differently depending on whether it was sent in the clear or over TLS.
    throw Object.assign(err, { protectorId: protector.id, protectorName: protector.name, transport: protector.protocol });
  }
}

/**
 * Same as inspectFile, but when the caller didn't force a specific Protector
 * (protectorId omitted - the "use the default" case), automatically tries the
 * next configured, non-disabled Protector if one candidate fails with a
 * connection-class error (the Protector never answered) rather than failing
 * the scan outright. An explicit protectorId is always honored as-is - no
 * failover - so a user deliberately testing "Protector B" via the picker still
 * gets Protector B's real error, not a silent substitution.
 *
 * Only connection-class errors (see isConnectionClassError) trigger trying the
 * next candidate. Any other error (e.g. INVALID_RESPONSE - the Protector did
 * answer, just not usefully) fails immediately.
 *
 * @param {string} [protectorId]
 * @returns {Promise<object>} same shape as inspectFile's return, plus
 *   { failedOver: true, attemptedProtectors: [...] } when a fallback was used.
 */
async function inspectFileWithFailover(fileBuffer, originalName, clientIp, requestId, protectorId, transport) {
  if (protectorId) {
    return inspectFile(fileBuffer, originalName, clientIp, requestId, protectorId, transport);
  }

  const enabledIds = config.protectors.filter((p) => !p.disabled).map((p) => p.id);
  if (!enabledIds.length) {
    // Nothing enabled at all - let inspectFile produce its normal (PROTECTOR_DISABLED
    // or similar) error against the configured default rather than duplicating that logic.
    return inspectFile(fileBuffer, originalName, clientIp, requestId, undefined, transport);
  }
  const candidates = enabledIds.includes(config.defaultProtectorId)
    ? [config.defaultProtectorId, ...enabledIds.filter((id) => id !== config.defaultProtectorId)]
    : enabledIds;

  const attemptedProtectors = [];
  let lastError;
  for (const candidateId of candidates) {
    try {
      const result = await inspectFile(fileBuffer, originalName, clientIp, requestId, candidateId, transport);
      return attemptedProtectors.length ? { ...result, failedOver: true, attemptedProtectors } : result;
    } catch (err) {
      attemptedProtectors.push({ protectorId: err.protectorId || candidateId, protectorName: err.protectorName, error: err.code || err.message });
      lastError = err;
      if (!isConnectionClassError(err)) {
        throw err;
      }
    }
  }
  throw Object.assign(lastError, { attemptedProtectors });
}

/**
 * Developer passthrough: sends a caller-supplied raw metadata JSON string
 * straight to the Protector, bypassing this app's own metadata construction
 * (Settings, auto-detected source, etc.) entirely. Used by the "Try it out"
 * panel in /docs so developers can experiment with the Inspection API's raw
 * request/response shape directly, without needing Postman or curl.
 *
 * @param {string} metadataJsonString - raw JSON text as typed by the developer
 * @param {Buffer} fileBuffer - raw file content
 * @param {string} fileName
 * @param {boolean} wrap - whether to apply the HTTP-wrap trick (see buildHttpWrappedUpload).
 *   Defaults to true; set false to demonstrate the "raw bytes always produce 0 matches" gotcha.
 * @param {string} [protectorId] - which configured Protector to send to. Defaults to
 *   config.defaultProtectorId. Throws (code UNKNOWN_PROTECTOR) if given an unrecognized id.
 * @returns {Promise<{httpStatus: number, body: object, elapsedMs: number}>}
 */
async function inspectRaw(metadataJsonString, fileBuffer, fileName, wrap = true, protectorId, transport) {
  const protector = withTransport(resolveProtector(protectorId), transport);
  if (protector.disabled) {
    throw Object.assign(new Error(`${protector.name} is unavailable: ${protector.unavailableReason}`), {
      code: 'PROTECTOR_DISABLED',
      protectorId: protector.id,
      protectorName: protector.name,
    });
  }
  let metadata;
  try {
    metadata = JSON.parse(metadataJsonString);
  } catch (err) {
    throw Object.assign(new Error(`metadata is not valid JSON: ${err.message}`), { code: 'INVALID_METADATA' });
  }

  const filePart = wrap ? buildHttpWrappedUpload(fileBuffer, fileName) : fileBuffer;
  return sendToProtector(metadata, filePart, fileName, protector);
}

/**
 * Quick TCP reachability check against one configured Protector's host/port -
 * does NOT send an actual inspection request (no side effects, no dependency
 * on a valid metadata payload). Used by GET /api/health and GET /api/protectors.
 *
 * @param {string} [protectorId] - defaults to config.defaultProtectorId
 * @param {number} timeoutMs
 * @returns {Promise<{reachable: boolean, elapsedMs: number, error?: string}>}
 */
function checkProtectorReachability(protectorId, timeoutMs = 3000, transport) {
  // Probes the port the next scan would actually use, so the health pill can't read
  // "reachable" on :8080 while the secure toggle is sending to a closed :8443.
  const protector = withTransport(resolveProtector(protectorId), transport);
  return new Promise((resolve) => {
    const startedAt = Date.now();
    const socket = net.connect({ host: protector.host, port: protector.port });

    const finish = (reachable, error) => {
      socket.destroy();
      resolve({ reachable, elapsedMs: Date.now() - startedAt, ...(error ? { error } : {}) });
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false, 'Timed out'));
    socket.once('error', (err) => finish(false, err.code || err.message));
  });
}

module.exports = {
  inspectFile,
  inspectFileWithFailover,
  inspectRaw,
  buildHttpWrappedUpload,
  checkProtectorReachability,
  listProtectorSummaries,
  resolveProtector,
  isConnectionClassError,
  isTlsError,
  withTransport,
};
