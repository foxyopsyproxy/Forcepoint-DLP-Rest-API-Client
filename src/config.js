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
  const explicitPort = parseIntEnv(process.env[`${prefix}_PORT`], null);

  // The Inspection API is reachable over BOTH schemes on the same appliance, on
  // different ports - 8080 for http and 8443 for https (Forcepoint DLP 10.4
  // "Inspection API" docs). Resolving both up front is what lets a single scan
  // choose its transport at request time instead of being locked to whichever
  // scheme .env happens to name. An explicit _PORT still wins, but only for the
  // scheme it was written for; the other scheme falls back to its documented port.
  const httpPort = parseIntEnv(process.env[`${prefix}_HTTP_PORT`], protocol === 'http' ? (explicitPort ?? 8080) : 8080);
  const httpsPort = parseIntEnv(process.env[`${prefix}_HTTPS_PORT`], protocol === 'https' ? (explicitPort ?? 8443) : 8443);

  // CA is loaded regardless of the configured default protocol: an http-by-default
  // Protector can still be sent to over https via the per-request toggle, and it
  // would need its CA at that moment.
  let caCert;
  const caCertPath = (process.env[`${prefix}_CA_CERT_PATH`] || '').trim();
  if (caCertPath) {
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
    port: explicitPort ?? defaultPort,
    httpPort,
    httpsPort,
    token: (process.env[`${prefix}_TOKEN`] || '').trim(),
    caCert,
    rejectUnauthorized: parseBool(process.env[`${prefix}_TLS_REJECT_UNAUTHORIZED`], true),
    // Protector certificates are commonly issued to a hostname while this app connects
    // by IP, and they often carry no subjectAltName at all. Setting this verifies the
    // certificate against that name instead of the connect address, which keeps full
    // chain + name validation working without needing the name to resolve in DNS.
    tlsServername: (process.env[`${prefix}_TLS_SERVERNAME`] || '').trim(),
    // Lets a Protector stay configured in .env (so it reappears the moment it's fixed)
    // while being hidden from selection and blocked from scanning - e.g. while its
    // Inspection API license/service is still pending on the appliance side.
    disabled: parseBool(process.env[`${prefix}_DISABLED`], false),
    unavailableReason: (process.env[`${prefix}_UNAVAILABLE_REASON`] || '').trim() || 'Unavailable',
  };
}

// Reads a required PEM file for the app's own TLS listener. Fails loudly at startup
// rather than letting the server boot and then refuse every connection - a missing
// cert path is a deployment mistake worth stopping for.
function readTlsFile(envVar, label) {
  const raw = (process.env[envVar] || '').trim();
  if (!raw) {
    throw new Error(`SERVER_HTTPS_ENABLED is true but ${envVar} is not set (path to the ${label}).`);
  }
  const resolved = path.resolve(raw);
  if (!fs.existsSync(resolved)) {
    throw new Error(`${envVar} points to a file that does not exist: ${resolved}`);
  }
  return fs.readFileSync(resolved);
}

// Returns null when HTTPS is disabled, otherwise { cert, key, ca?, passphrase? }
// ready to hand straight to https.createServer().
function buildServerTls() {
  if (!parseBool(process.env.SERVER_HTTPS_ENABLED, false)) return null;

  const options = {
    cert: readTlsFile('SERVER_TLS_CERT_PATH', 'server certificate'),
    key: readTlsFile('SERVER_TLS_KEY_PATH', 'server private key'),
  };

  // Only needed when the issuing CA is not already trusted by the client, or when
  // intermediates must be presented - a chain file here is sent alongside the leaf.
  const caPath = (process.env.SERVER_TLS_CA_PATH || '').trim();
  if (caPath) {
    const resolved = path.resolve(caPath);
    if (!fs.existsSync(resolved)) {
      throw new Error(`SERVER_TLS_CA_PATH points to a file that does not exist: ${resolved}`);
    }
    options.ca = fs.readFileSync(resolved);
  }

  const passphrase = process.env.SERVER_TLS_PASSPHRASE || '';
  if (passphrase) options.passphrase = passphrase;

  return options;
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
    // TLS for THIS app's own listener (not the outbound connection to a Protector,
    // which is configured per-protector above). Off by default so an existing
    // install keeps working unchanged; see buildServerTls() for the file loading.
    https: buildServerTls(),
    // When HTTPS is on, optionally run a tiny listener on this port whose only job
    // is to 301 anyone who typed http:// over to the https:// URL. Empty = no
    // plaintext listener at all.
    httpRedirectPort: parseIntEnv(process.env.HTTP_REDIRECT_PORT, null),
  },
  logFilePath: process.env.LOG_FILE_PATH || './logs/requests.log.jsonl',
  // SQLite-backed history store (see src/db.js). logFilePath above stays as the
  // untouched legacy JSONL file - migrated into this DB once on first boot, then
  // left alone as a backup; new scans are recorded only here going forward.
  historyDbPath: process.env.HISTORY_DB_PATH || './data/history.db',
  // Semantic AI DLP (Milestone 1 - shadow mode only). Entirely optional and additive:
  // AI_DLP_ENABLED=false (the default) means src/semanticScanner.js is never called
  // and nothing else in the app is affected. See docs/semantic-dlp-architecture.md.
  semanticAi: {
    enabled: parseBool(process.env.AI_DLP_ENABLED, false),
    // Only 'shadow' is implemented in this milestone - see semanticScanner.js.
    mode: (process.env.AI_DLP_MODE || 'shadow').trim().toLowerCase(),
    ollamaBaseUrl: process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434',
    // Not hardcoded anywhere else in the AI code path - always read from this value.
    ollamaModel: process.env.OLLAMA_MODEL || 'qwen3:8b',
    // A real end-to-end smoke test on this project's dev machine (Windows 11, 16GB
    // RAM, 4 vCPU, no GPU, qwen3:4b) measured 38s-157s for a single small chunk with
    // this milestone's full evidence-bearing schema - a short default here would
    // produce spurious timeouts on exactly the hardware this milestone targets.
    ollamaTimeoutMs: parseIntEnv(process.env.OLLAMA_TIMEOUT, 240000),
    // These four settings are the actual, measured fix for a real reliability
    // problem: with none of them set, this hardware/model measured a ~50% timeout
    // rate (avg 206s, some calls never returning within 240s) because generation
    // was completely open-ended. keep_alive avoids a model reload between scans;
    // num_ctx/num_predict bound the work per call. num_predict alone is NOT
    // sufficient - qwen3 at temperature 0 can spend its whole budget on a long,
    // unbounded "reason" string and never reach the JSON's closing punctuation.
    // The schema-level maxLength/maxItems bounds in semanticScanner.js's
    // getResponseSchema() are what actually force a valid, complete response
    // inside this budget; num_predict is just the outer safety cap. With all of
    // this together, the same test cases that used to time out completed in
    // 66-95s with zero timeouts.
    ollamaKeepAlive: process.env.OLLAMA_KEEP_ALIVE || '30m',
    ollamaNumCtx: parseIntEnv(process.env.OLLAMA_NUM_CTX, 2048),
    ollamaNumPredict: parseIntEnv(process.env.OLLAMA_NUM_PREDICT, 150),
    ollamaTemperature: (() => { const n = parseFloat(process.env.OLLAMA_TEMPERATURE); return Number.isFinite(n) ? n : 0; })(),
    // Characters, not tokens - simplest thing that works without adding a tokenizer
    // dependency. Paragraph-boundary-aware chunking (see semanticScanner.js) means
    // actual chunks are usually smaller than this, not larger.
    chunkSize: parseIntEnv(process.env.AI_CHUNK_SIZE, 4000),
    chunkOverlap: parseIntEnv(process.env.AI_CHUNK_OVERLAP, 200),
    // Content beyond this is truncated before chunking even starts - this machine has
    // no GPU, so bounding total model work matters more than analyzing every last byte
    // of a huge file. Truncation is always reported in the result, never silent.
    maxContentSize: parseIntEnv(process.env.AI_MAX_CONTENT_SIZE, 40000),
  },
};

module.exports = config;
