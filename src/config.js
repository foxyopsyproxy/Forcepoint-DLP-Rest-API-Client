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

// Builds one protector entry from a set of PREFIX_HOST / PREFIX_PORT / ... env vars.
// Returns null if PREFIX_HOST isn't set (so callers can detect "this slot is unused").
function buildProtectorEntry(prefix, id, defaultName) {
  const host = (process.env[`${prefix}_HOST`] || '').trim();
  if (!host) return null;

  const protocol = (process.env[`${prefix}_PROTOCOL`] || 'http').trim().toLowerCase();
  if (protocol !== 'http' && protocol !== 'https') {
    throw new Error(`${prefix}_PROTOCOL must be "http" or "https", got: "${protocol}"`);
  }

  const defaultPort = protocol === 'https' ? 8443 : 8080;

  let caCert;
  const caCertPath = (process.env[`${prefix}_CA_CERT_PATH`] || '').trim();
  if (protocol === 'https' && caCertPath) {
    const resolved = path.resolve(caCertPath);
    if (!fs.existsSync(resolved)) {
      throw new Error(`${prefix}_CA_CERT_PATH is set but file does not exist: ${resolved}`);
    }
    caCert = fs.readFileSync(resolved);
  }

  return {
    id,
    name: (process.env[`${prefix}_NAME`] || '').trim() || defaultName,
    protocol,
    host,
    port: parseIntEnv(process.env[`${prefix}_PORT`], defaultPort),
    token: (process.env[`${prefix}_TOKEN`] || '').trim(),
    caCert,
    rejectUnauthorized: parseBool(process.env[`${prefix}_TLS_REJECT_UNAUTHORIZED`], true),
    // Lets a Protector stay configured in .env (so it reappears the moment it's fixed)
    // while being hidden from selection and blocked from scanning - e.g. while its
    // Inspection API license/service is still pending on the appliance side.
    disabled: parseBool(process.env[`${prefix}_DISABLED`], false),
    unavailableReason: (process.env[`${prefix}_UNAVAILABLE_REASON`] || '').trim() || 'Unavailable',
  };
}

// Numbered format (PROTECTOR_1_HOST, PROTECTOR_2_HOST, ...) - for more than one Protector.
const protectors = [];
for (let i = 1; process.env[`PROTECTOR_${i}_HOST`]; i++) {
  protectors.push(buildProtectorEntry(`PROTECTOR_${i}`, String(i), `Protector ${i}`));
}

// Legacy single-protector format (PROTECTOR_HOST, PROTECTOR_PORT, ...) - only used when
// none of the numbered PROTECTOR_N_HOST vars are present, so existing .env files from
// before multi-protector support keep working unchanged.
if (!protectors.length) {
  const legacy = buildProtectorEntry('PROTECTOR', 'default', 'Default');
  if (legacy) protectors.push(legacy);
}

if (!protectors.length) {
  throw new Error(
    'No Protector configured. Set PROTECTOR_HOST (single Protector) or PROTECTOR_1_HOST, ' +
      'PROTECTOR_2_HOST, ... (multiple) in .env'
  );
}

const requestedDefault = (process.env.PROTECTOR_DEFAULT || '').trim();
const defaultProtectorId = protectors.some((p) => p.id === requestedDefault)
  ? requestedDefault
  : protectors[0].id;

const config = {
  protectors,
  defaultProtectorId,
  requestTimeoutMs: parseIntEnv(process.env.REQUEST_TIMEOUT_MS, 30000),
  destination: {
    httpRequestUrl: process.env.DESTINATION_HTTP_URL || 'https://dlp-client.local/upload',
    httpRequestUrlHostname: process.env.DESTINATION_HTTP_HOSTNAME || 'dlp-client.local',
  },
  maxFileSizeMb: parseIntEnv(process.env.MAX_FILE_SIZE_MB, 30),
  server: {
    port: parseIntEnv(process.env.PORT, 3000),
  },
  logFilePath: process.env.LOG_FILE_PATH || './logs/requests.log.jsonl',
  // SQLite-backed history store (see src/db.js). logFilePath above stays as the
  // untouched legacy JSONL file - migrated into this DB once on first boot, then
  // left alone as a backup; new scans are recorded only here going forward.
  historyDbPath: process.env.HISTORY_DB_PATH || './data/history.db',
};

module.exports = config;
