require('dotenv').config();
const fs = require('fs');
const path = require('path');

function parseBool(value, defaultValue) {
  if (value === undefined || value === null || value === '') return defaultValue;
  return String(value).trim().toLowerCase() === 'true';
}

function parseIntEnv(value, defaultValue) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) ? n : defaultValue;
}

const protocol = (process.env.PROTECTOR_PROTOCOL || 'http').trim().toLowerCase();
if (protocol !== 'http' && protocol !== 'https') {
  throw new Error(`PROTECTOR_PROTOCOL must be "http" or "https", got: "${protocol}"`);
}

const defaultPort = protocol === 'https' ? 8443 : 8080;

let caCert = undefined;
const caCertPath = (process.env.PROTECTOR_CA_CERT_PATH || '').trim();
if (protocol === 'https' && caCertPath) {
  const resolved = path.resolve(caCertPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`PROTECTOR_CA_CERT_PATH is set but file does not exist: ${resolved}`);
  }
  caCert = fs.readFileSync(resolved);
}

const config = {
  protector: {
    protocol,
    host: process.env.PROTECTOR_HOST || 'localhost',
    port: parseIntEnv(process.env.PROTECTOR_PORT, defaultPort),
    token: (process.env.PROTECTOR_TOKEN || '').trim(),
    caCert,
    rejectUnauthorized: parseBool(process.env.PROTECTOR_TLS_REJECT_UNAUTHORIZED, true),
    timeoutMs: parseIntEnv(process.env.REQUEST_TIMEOUT_MS, 30000),
  },
  destination: {
    httpRequestUrl: process.env.DESTINATION_HTTP_URL || 'https://dlp-client.local/upload',
    httpRequestUrlHostname: process.env.DESTINATION_HTTP_HOSTNAME || 'dlp-client.local',
  },
  maxFileSizeMb: parseIntEnv(process.env.MAX_FILE_SIZE_MB, 30),
  server: {
    port: parseIntEnv(process.env.PORT, 3000),
  },
  logFilePath: process.env.LOG_FILE_PATH || './logs/requests.log.jsonl',
};

module.exports = config;
