const http = require('http');
const https = require('https');
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
 * Sends a file to the Forcepoint DLP Protector Inspection REST API (v4.0)
 * and returns the parsed response along with timing info.
 *
 * @param {Buffer} fileBuffer - raw file content (never written to disk)
 * @param {string} originalName - original filename as uploaded by the user
 * @returns {Promise<{httpStatus: number, body: object, elapsedMs: number, globalMessageId: string}>}
 */
async function inspectFile(fileBuffer, originalName, clientIp) {
  const settings = getSettings();
  const globalMessageId = crypto.randomUUID();
  const httpWrappedFile = buildHttpWrappedUpload(fileBuffer, originalName);

  const metadata = {
    context: {
      global_message_id: globalMessageId,
      client_name: 'CUSTOM_APPLICATION',
      data_channel: 'HTTP',
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

  const form = new FormData();
  form.append('metadata', JSON.stringify(metadata), {
    contentType: 'application/json',
    filename: 'metadata.json',
  });
  form.append('0', httpWrappedFile, {
    contentType: 'application/http',
    filename: originalName,
  });

  const headers = form.getHeaders();
  headers['Content-Length'] = form.getLengthSync();
  if (config.protector.token) {
    headers['Authorization'] = `Bearer ${config.protector.token}`;
  }

  const requestOptions = {
    protocol: config.protector.protocol === 'https' ? 'https:' : 'http:',
    hostname: config.protector.host,
    port: config.protector.port,
    path: '/inspection/v4.0',
    method: 'POST',
    headers,
    timeout: settings.requestTimeoutMs,
  };

  if (config.protector.protocol === 'https') {
    requestOptions.ca = config.protector.caCert;
    requestOptions.rejectUnauthorized = config.protector.rejectUnauthorized;
  }

  const transport = config.protector.protocol === 'https' ? https : http;
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
        resolve({ httpStatus: res.statusCode, body: parsedBody, elapsedMs, globalMessageId });
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

module.exports = { inspectFile };
