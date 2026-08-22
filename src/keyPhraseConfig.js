const { VALIDATORS } = require('./keyPhraseValidators');

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/**
 * Validates a raw parsed Key Phrase config object and builds the rule -> phrase-set
 * lookup SanitizationService needs. Pure and side-effect free (no filesystem access),
 * so it can be unit tested directly against plain objects without touching disk or
 * env vars - see src/keyPhraseStore.js for the disk-loading entry point (including
 * live reload and validated writes from the Settings UI) actually used by the
 * running app.
 *
 * Collects every structural problem rather than stopping at the first one, so a
 * broken config file only has to be fixed once instead of error-by-error.
 *
 * @param {object} raw - parsed JSON, shape: { phrase_sets: {...}, rules: {...} }.
 *   Each phrase_sets entry is {id, value} (a literal, fixed string) or {id, pattern,
 *   validator?} (a regex source string, optionally narrowed by a named validator
 *   from keyPhraseValidators.js) - exactly one of value/pattern, never both.
 * @param {string} [sourceLabel] - included in the thrown error for context (a file
 *   path when loaded from disk, or a caller-supplied label in tests)
 * @returns {{isEnabled: () => true, getRuleMapping: (ruleName: string) => (
 *   {phraseSetId:string, replacement:string, caseSensitive:boolean,
 *    phrases:({id:string,value:string}|{id:string,pattern:string,validator?:string})[]}
 *   | undefined
 * )}}
 * @throws {Error} with every validation problem listed, if the config is structurally invalid
 */
function buildConfig(raw, sourceLabel = 'key-phrases config') {
  const errors = [];

  if (!isPlainObject(raw)) {
    throw new Error(`Invalid Key Phrase config (${sourceLabel}): root must be a JSON object`);
  }

  const phraseSetsRaw = raw.phrase_sets;
  const rulesRaw = raw.rules;
  if (!isPlainObject(phraseSetsRaw)) {
    errors.push('"phrase_sets" must be an object mapping set name -> array of phrases');
  }
  if (!isPlainObject(rulesRaw)) {
    errors.push('"rules" must be an object mapping Forcepoint rule_name -> rule config');
  }
  throwIfAny(errors, sourceLabel);

  // --- phrase_sets: { [setName]: [{id, value} | {id, pattern, validator?}] } ---
  // A phrase is either a literal, fixed string (value - matched verbatim, see
  // KeyPhraseRedactor) or a pattern (a regex source string, for content that varies
  // per instance - a national id number, not a project codename - optionally
  // narrowed by a named validator like a checksum, since "9 digits" alone matches
  // plenty of numbers that are not ids). Exactly one of the two must be present.
  const phraseSets = {}; // setName -> [{id, value} | {id, pattern, validator}], validated entries only
  const seenPhraseIds = new Set();
  for (const [setName, entries] of Object.entries(phraseSetsRaw)) {
    if (!Array.isArray(entries)) {
      errors.push(`phrase_sets.${setName} must be an array`);
      continue;
    }
    const list = [];
    entries.forEach((entry, idx) => {
      if (!isPlainObject(entry)) {
        errors.push(`phrase_sets.${setName}[${idx}] must be an object with "id" and either "value" or "pattern"`);
        return;
      }
      const { id, value, pattern, validator } = entry;
      if (typeof id !== 'string' || !id.trim()) {
        errors.push(`phrase_sets.${setName}[${idx}].id must be a non-empty string`);
        return;
      }
      const hasValue = value !== undefined;
      const hasPattern = pattern !== undefined;
      if (hasValue === hasPattern) {
        errors.push(`phrase_sets.${setName}[${idx}] (id="${id}") must have exactly one of "value" or "pattern", not ${hasValue ? 'both' : 'neither'}`);
        return;
      }
      // Phrase ids are logged (see SanitizationService) so they need to unambiguously
      // identify one phrase across the whole config, not just within one set.
      if (seenPhraseIds.has(id)) {
        errors.push(`Duplicate phrase id "${id}" - phrase ids must be unique across all phrase_sets`);
        return;
      }
      if (hasValue) {
        if (typeof value !== 'string' || !value.trim()) {
          errors.push(`phrase_sets.${setName}[${idx}] (id="${id}") has an empty phrase value`);
          return;
        }
        seenPhraseIds.add(id);
        list.push({ id, value });
        return;
      }
      // hasPattern
      if (typeof pattern !== 'string' || !pattern.trim()) {
        errors.push(`phrase_sets.${setName}[${idx}] (id="${id}") has an empty pattern`);
        return;
      }
      try {
        // eslint-disable-next-line no-new
        new RegExp(pattern);
      } catch (err) {
        errors.push(`phrase_sets.${setName}[${idx}] (id="${id}") has an invalid pattern: ${err.message}`);
        return;
      }
      if (validator !== undefined && !(typeof validator === 'string' && validator in VALIDATORS)) {
        errors.push(`phrase_sets.${setName}[${idx}] (id="${id}") has an unknown validator "${validator}" - known validators: ${Object.keys(VALIDATORS).join(', ')}`);
        return;
      }
      seenPhraseIds.add(id);
      list.push({ id, pattern, ...(validator !== undefined ? { validator } : {}) });
    });
    phraseSets[setName] = list;
  }

  // --- rules: { [ruleName]: {phrase_set, replacement, case_sensitive} } ---
  const ruleMap = new Map();
  const seenRuleNames = new Set();
  for (const [ruleName, ruleCfg] of Object.entries(rulesRaw)) {
    const trimmedName = ruleName.trim();
    if (!trimmedName) {
      errors.push('A rule key is empty or blank');
      continue;
    }
    // JSON object keys are already unique, but this still catches two keys that
    // differ only by surrounding whitespace, which would otherwise silently shadow.
    if (seenRuleNames.has(trimmedName)) {
      errors.push(`Duplicate rule "${trimmedName}"`);
      continue;
    }
    seenRuleNames.add(trimmedName);

    if (!isPlainObject(ruleCfg)) {
      errors.push(`rules["${ruleName}"] must be an object`);
      continue;
    }
    const phraseSetId = ruleCfg.phrase_set;
    const replacement = ruleCfg.replacement;
    const caseSensitive = ruleCfg.case_sensitive;

    if (typeof phraseSetId !== 'string' || !phraseSetId.trim()) {
      errors.push(`rules["${ruleName}"].phrase_set must be a non-empty string`);
      continue;
    }
    if (!(phraseSetId in phraseSets)) {
      errors.push(`rules["${ruleName}"] references nonexistent phrase_set "${phraseSetId}"`);
      continue;
    }
    if (typeof replacement !== 'string' || !replacement.length) {
      errors.push(`rules["${ruleName}"].replacement must be a non-empty string`);
      continue;
    }
    if (caseSensitive !== undefined && typeof caseSensitive !== 'boolean') {
      errors.push(`rules["${ruleName}"].case_sensitive must be a boolean if present`);
      continue;
    }
    if (!phraseSets[phraseSetId].length) {
      errors.push(`rules["${ruleName}"] uses phrase_set "${phraseSetId}", which has no valid phrases`);
      continue;
    }

    ruleMap.set(ruleName, {
      phraseSetId,
      replacement,
      caseSensitive: caseSensitive === true,
      phrases: phraseSets[phraseSetId],
    });
  }

  throwIfAny(errors, sourceLabel);

  return {
    isEnabled: () => true,
    getRuleMapping: (ruleName) => ruleMap.get(ruleName),
  };
}

function throwIfAny(errors, sourceLabel) {
  if (errors.length) {
    // `.details` is the plain list, for a caller that wants to render its own
    // bullets (e.g. the Settings UI) without text-parsing the formatted message,
    // which also embeds the server-side file path - fine for a log line, not
    // something an API response needs to echo back to the browser.
    throw Object.assign(new Error(`Invalid Key Phrase config (${sourceLabel}):\n  - ${errors.join('\n  - ')}`), {
      details: errors,
    });
  }
}

// Returned when the feature is simply not configured for this deployment (no
// KEY_PHRASE_CONFIG_PATH set) - every Key Phrase concept in the app already existed
// and works fine without this feature, so its absence must not be an error.
const DISABLED_CONFIG = {
  isEnabled: () => false,
  getRuleMapping: () => undefined,
};

// Disk access (reading KEY_PHRASE_CONFIG_PATH, live reload, and writing updates
// from the Settings UI) lives in src/keyPhraseStore.js, which uses buildConfig()
// above for validation - kept separate so buildConfig() stays unit-testable
// against plain objects with no filesystem/env var involved at all.
module.exports = { buildConfig, DISABLED_CONFIG };
