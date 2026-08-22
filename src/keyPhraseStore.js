const fs = require('fs');
const path = require('path');
const { buildConfig, DISABLED_CONFIG } = require('./keyPhraseConfig');

/**
 * Owns the actual file (path resolution, read, write, live reload) for Key Phrase
 * Redaction - keyPhraseConfig.js stays pure validation/build logic with no
 * filesystem access, exactly as its own docstring already says. This is what
 * settingsStore.js already is for the rest of Settings: the one place that touches
 * disk for this feature, so an edit from the web app (saveRaw) is visible to the
 * very next scan (getCompiled) with no separate "reload" step and no service
 * restart - the same "applied immediately" property Settings already has.
 *
 * A factory (like createSanitizationService), not a module-level singleton reading
 * process.env directly at require() time, specifically so tests can point several
 * independent instances at their own temp files in the same process - see
 * test/keyPhraseStore.test.js.
 *
 * @param {object} [options]
 * @param {string} [options.configPath] - defaults to process.env.KEY_PHRASE_CONFIG_PATH.
 *   Empty/unset means the feature is off - every method reports that honestly
 *   rather than erroring, matching src/config.js's pattern for optional features.
 */
function createKeyPhraseStore({ configPath = process.env.KEY_PHRASE_CONFIG_PATH } = {}) {
  const trimmed = (configPath || '').trim();
  const resolvedPath = trimmed ? path.resolve(trimmed) : null;

  function isEnabled() {
    return !!resolvedPath;
  }

  function readRawFromDisk() {
    if (!fs.existsSync(resolvedPath)) {
      throw new Error(`KEY_PHRASE_CONFIG_PATH is set but file does not exist: ${resolvedPath}`);
    }
    try {
      return JSON.parse(fs.readFileSync(resolvedPath, 'utf8'));
    } catch (err) {
      throw new Error(`Key Phrase config ${resolvedPath} is not valid JSON: ${err.message}`);
    }
  }

  // Last successfully-built config, kept so a transient read/parse/validation
  // failure (someone hand-editing the file badly while the service is running)
  // degrades to "keep serving the last known-good dictionary" rather than either
  // crashing an in-flight scan or silently disabling redaction outright.
  let cachedCompiled = null;
  let cachedMtimeMs = null;
  let everLoaded = false;

  /**
   * The compiled, ready-to-use config sanitizationService actually calls
   * (isEnabled()/getRuleMapping()) - re-reads and rebuilds from disk only when the
   * file's mtime has actually changed since the last call, so a scan-heavy
   * workload is not re-parsing the whole dictionary on every single scan; an edit
   * from the web app (saveRaw, below) is visible on the very next call regardless,
   * since it clears the cached mtime itself.
   */
  function getCompiled() {
    if (!resolvedPath) return DISABLED_CONFIG;
    try {
      const mtimeMs = fs.statSync(resolvedPath).mtimeMs;
      if (cachedCompiled && cachedMtimeMs === mtimeMs) return cachedCompiled;
      const built = buildConfig(readRawFromDisk(), resolvedPath);
      cachedCompiled = built;
      cachedMtimeMs = mtimeMs;
      everLoaded = true;
      return built;
    } catch (err) {
      if (everLoaded) {
        console.error(`Key Phrase config reload failed, continuing with the last valid version: ${err.message}`);
        return cachedCompiled;
      }
      // Nothing has ever loaded successfully - this is the original "fail
      // application startup on a broken config" behavior, just deferred to first
      // use instead of require()-time (server.js calls this once eagerly at boot
      // specifically to keep that fail-fast property).
      throw err;
    }
  }

  /** The raw, editable {phrase_sets, rules} shape - what the Settings UI reads and writes. */
  function getRaw() {
    if (!resolvedPath) throw new Error('Key Phrase Redaction is not configured on this server');
    return readRawFromDisk();
  }

  /**
   * Validates `nextRaw` (throws with every problem listed, via buildConfig, if
   * invalid - nothing is written in that case) and persists it, so a bad edit from
   * the web app never reaches disk and never disturbs the currently-running,
   * last-known-good dictionary.
   */
  function saveRaw(nextRaw) {
    if (!resolvedPath) throw new Error('Key Phrase Redaction is not configured on this server');
    buildConfig(nextRaw, `${resolvedPath} (pending update)`);
    fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
    fs.writeFileSync(resolvedPath, JSON.stringify(nextRaw, null, 2));
    cachedCompiled = null;
    cachedMtimeMs = null;
    return nextRaw;
  }

  return { isEnabled, getCompiled, getRaw, saveRaw };
}

module.exports = { createKeyPhraseStore };
