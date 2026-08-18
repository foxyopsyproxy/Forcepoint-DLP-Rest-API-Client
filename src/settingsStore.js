const fs = require('fs');
const path = require('path');
const config = require('./config');

const SETTINGS_FILE = path.resolve(__dirname, '..', 'data', 'settings.json');

// Confirmed via the Protector's own validation error message (see DEVELOPER.md) -
// FTP is notably NOT in this list despite appearing in some Forcepoint docs.
const DATA_CHANNEL_OPTIONS = [
  'TESTING_CHANNEL', 'HTTP', 'HTTPS', 'CASB_REAL_TIME', 'ZTNA',
  'CASB_DISCOVERY', 'NETWORK_DISCOVERY', 'CASB_API', 'EMAIL',
];

// Fallback used whenever a field's override is disabled (or never set).
const DEFAULTS = {
  maxFileSizeMb: config.maxFileSizeMb,
  requestTimeoutMs: config.protector.timeoutMs,
  // Source object (see Forcepoint Inspection API "Source Object" spec) - used by
  // the Protector to match a policy's Source condition (network/computer).
  hostIps: '', // disabled = auto-detect from the incoming request's IP
  hostName: '', // disabled = auto-detect from os.hostname()
  destinationHttpUrl: config.destination.httpRequestUrl,
  destinationHttpHostname: config.destination.httpRequestUrlHostname,
  // context.data_channel sent on every scan - affects how the Protector's Traffic
  // Log classifies the request (e.g. HTTP/HTTPS both land under "Network" in our
  // environment; other values land under different channels a policy may not cover).
  dataChannel: 'HTTP',
};

const FIELD_KEYS = Object.keys(DEFAULTS);
const IP_TOKEN_PATTERN = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-f:]+)$/i;

// Only these fields are user-configurable from the Settings screen: limits and
// request metadata that cannot break connectivity to the Protector if misconfigured.
// Each validator only applies while the field is enabled - see updateSettings().
const VALIDATORS = {
  maxFileSizeMb: (v) => {
    const n = Number(v);
    return Number.isFinite(n) && n >= 1 && n <= 500 ? Math.round(n) : undefined;
  },
  requestTimeoutMs: (v) => {
    const n = Number(v);
    return Number.isFinite(n) && n >= 1000 && n <= 300000 ? Math.round(n) : undefined;
  },
  hostIps: (v) => {
    if (typeof v !== 'string' || v.length > 253) return undefined;
    const trimmed = v.trim();
    if (!trimmed) return undefined; // enabled but empty makes no sense - disable it instead
    const tokens = trimmed.split(',').map((t) => t.trim());
    return tokens.every((t) => IP_TOKEN_PATTERN.test(t)) ? tokens.join(', ') : undefined;
  },
  hostName: (v) => (typeof v === 'string' && v.trim() && v.length <= 253 ? v.trim() : undefined),
  destinationHttpUrl: (v) =>
    typeof v === 'string' && v.length <= 2048 && /^https?:\/\/.+/i.test(v.trim()) ? v.trim() : undefined,
  destinationHttpHostname: (v) => (typeof v === 'string' && v.trim() && v.length <= 253 ? v.trim() : undefined),
  dataChannel: (v) => (DATA_CHANNEL_OPTIONS.includes(v) ? v : undefined),
};

function readOverrides() {
  try {
    return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
  } catch (err) {
    return {};
  }
}

// { [field]: { enabled, value } } for every field - what the Settings UI renders.
function getFieldStates() {
  const overrides = readOverrides();
  const result = {};
  for (const key of FIELD_KEYS) {
    const stored = overrides[key];
    if (stored && typeof stored === 'object' && stored.enabled) {
      result[key] = { enabled: true, value: stored.value };
    } else {
      result[key] = { enabled: false, value: stored && typeof stored === 'object' ? stored.value : DEFAULTS[key] };
    }
  }
  return result;
}

// { [field]: effectiveValue } - what the app actually uses: the override's value
// when enabled, otherwise the .env-derived default / auto-detect placeholder.
function getSettings() {
  const states = getFieldStates();
  const effective = {};
  for (const key of FIELD_KEYS) {
    effective[key] = states[key].enabled ? states[key].value : DEFAULTS[key];
  }
  return effective;
}

function updateSettings(partial) {
  const next = { ...getFieldStates() };
  const errors = [];

  for (const key of FIELD_KEYS) {
    if (partial[key] === undefined) continue;
    const entry = partial[key] || {};
    const enabled = Boolean(entry.enabled);
    let rawValue = entry.value;
    if (typeof rawValue !== 'string' && typeof rawValue !== 'number') rawValue = '';

    if (!enabled) {
      // Disabled: keep whatever was typed (bounded), but it won't be applied.
      next[key] = { enabled: false, value: typeof rawValue === 'string' ? rawValue.slice(0, 2048) : rawValue };
      continue;
    }

    const validated = VALIDATORS[key](rawValue);
    if (validated === undefined) {
      errors.push(key);
      continue;
    }
    next[key] = { enabled: true, value: validated };
  }

  if (errors.length) {
    throw Object.assign(new Error(`Invalid value(s) for: ${errors.join(', ')}`), {
      code: 'INVALID_SETTINGS',
      fields: errors,
    });
  }

  fs.mkdirSync(path.dirname(SETTINGS_FILE), { recursive: true });
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(next, null, 2));
  return next;
}

module.exports = { getSettings, getFieldStates, updateSettings, DATA_CHANNEL_OPTIONS };
