const crypto = require('crypto');
const { KeyPhraseRedactor: DefaultKeyPhraseRedactor } = require('./keyPhraseRedactor');

const RESULT_STATUS = { CLEAN: 'CLEAN', SANITIZED: 'SANITIZED', BLOCKED: 'BLOCKED' };

// Every reason a transaction can end up BLOCKED. POST_REDACTION_DLP_MATCH is the one
// name mandated by spec; the rest exist so "why was this blocked" is always
// answerable from the structured log alone, without needing the original content.
const BLOCK_REASONS = {
  INVALID_INPUT: 'INVALID_INPUT',
  FEATURE_NOT_CONFIGURED: 'FEATURE_NOT_CONFIGURED',
  INSPECTION_FAILED: 'INSPECTION_FAILED',
  INVALID_RESPONSE: 'INVALID_RESPONSE',
  NO_IDENTIFIABLE_RULES: 'NO_IDENTIFIABLE_RULES',
  UNMAPPED_RULE: 'UNMAPPED_RULE',
  ZERO_REDACTIONS: 'ZERO_REDACTIONS',
  REDACTION_ERROR: 'REDACTION_ERROR',
  POST_REDACTION_DLP_MATCH: 'POST_REDACTION_DLP_MATCH',
};

/**
 * Builds a SanitizationService instance. Takes its Forcepoint client and Key Phrase
 * config as constructor dependencies (rather than requiring the real singletons
 * directly) purely so unit tests can substitute a fake Protector client and an
 * in-memory config, without touching the network, the filesystem, or env vars.
 *
 * @param {object} deps
 * @param {{inspectFile: Function, isConnectionClassError: Function, isTlsError: Function}} deps.protectorClient
 *   The existing Forcepoint client (src/protectorClient.js) - reused as-is, never
 *   reimplemented. Always called as `protectorClient.inspectFile(...)` (never
 *   destructured at module scope) so a test's fake object is actually exercised.
 * @param {{isEnabled: Function, getRuleMapping: Function}} deps.keyPhraseConfig
 *   src/keyPhraseConfig.js's buildConfig()/loadFromEnv() result.
 * @param {typeof DefaultKeyPhraseRedactor} [deps.KeyPhraseRedactor] - override for tests.
 * @param {Console} [deps.logger] - override for tests (assert on what would be logged).
 */
function createSanitizationService({ protectorClient, keyPhraseConfig, KeyPhraseRedactor = DefaultKeyPhraseRedactor, logger = console }) {
  // Errors worth one retry: the Protector never answered (connection-class) or a TLS
  // handshake failed - both can be transient blips. Anything else (unknown/disabled
  // Protector, a non-JSON response) will fail identically on a second try, so
  // retrying would just waste a round trip against a problem retrying can't fix.
  function isRetryable(err) {
    return protectorClient.isConnectionClassError(err) || protectorClient.isTlsError(err) || err.code === 'TIMEOUT';
  }

  async function inspectWithRetry(buffer, requestId, options) {
    try {
      return await protectorClient.inspectFile(buffer, 'content.txt', options.clientIp, requestId, options.protectorId, options.transport);
    } catch (err) {
      if (!isRetryable(err)) throw err;
      return protectorClient.inspectFile(buffer, 'content.txt', options.clientIp, requestId, options.protectorId, options.transport);
    }
  }

  // Reads Forcepoint's RAW response fields (policy_name / rule_name / violated_rules /
  // rule_number_of_matches) directly - this is not a duplicate of server.js's
  // /api/scan reshaping into camelCase, which is display logic for that route, not
  // something this service needs.
  //
  // Defensively drops null/malformed entries: per this project's own DEVELOPER.md,
  // `resolution: "MATCHED"` with `violations: [null]` is Forcepoint's documented
  // default fallback-rule response when nothing real actually matched - not a sign
  // of a bug, but something that would throw here if not filtered out first.
  function extractMatchedRules(body) {
    const violations = Array.isArray(body.violations) ? body.violations : [];
    const rules = [];
    for (const v of violations) {
      if (!v || typeof v !== 'object') continue;
      const violatedRules = Array.isArray(v.violated_rules) ? v.violated_rules : [];
      for (const r of violatedRules) {
        if (!r || typeof r.rule_name !== 'string' || !r.rule_name) continue;
        rules.push({
          policyId: v.policy_id,
          policyName: v.policy_name,
          ruleId: r.rule_id,
          ruleName: r.rule_name,
          severity: r.rule_severity,
          matches: r.rule_number_of_matches,
        });
      }
    }
    return rules;
  }

  // Reshapes extractMatchedRules()'s flat per-rule list into the {policyId,
  // policyName, rules:[{ruleId, ruleName, severity, matches}]} shape
  // historyStore.recordScanEvent() (and everything downstream of it - Analytics,
  // Verdict Detail) already expects, identical to how server.js's /api/scan builds
  // it from the raw Forcepoint response. Policy/rule NAMES and severity only -
  // the same "safe to log, the phrase VALUE is not" line the rest of this file draws.
  function toViolationsShape(matchedRules) {
    const byPolicy = new Map();
    for (const r of matchedRules) {
      const key = `${r.policyId ?? ''}|${r.policyName ?? ''}`;
      if (!byPolicy.has(key)) byPolicy.set(key, { policyId: r.policyId, policyName: r.policyName, rules: [] });
      byPolicy.get(key).rules.push({ ruleId: r.ruleId, ruleName: r.ruleName, severity: r.severity, matches: r.matches });
    }
    return Array.from(byPolicy.values());
  }

  function classifyResolution(body) {
    const resolution = body && body.resolution;
    return resolution === 'MATCHED' || resolution === 'UNMATCHED' ? resolution : null;
  }

  function emitLog(entry) {
    // SECURITY: this object must never gain a field holding original content,
    // sanitized content, or an actual phrase value - only counts, rule/policy NAMES
    // (which come from Forcepoint's own policy configuration, not the inspected
    // content) and phrase IDs (explicitly fine to log; the phrase VALUE is not).
    logger.log(JSON.stringify(entry));
  }

  function blockedResult(reason, extra) {
    return { status: RESULT_STATUS.BLOCKED, reason, ...extra };
  }

  // protectorName/dataChannel/transport/source come from Forcepoint's own response
  // metadata (see protectorClient.js's inspectFile), not something server.js could
  // reconstruct on its own - so the caller needs these echoed back to build a real
  // history entry. globalMessageId/protectorId/elapsedMs are deliberately NOT
  // repeated here: the caller already has protectorId/transport (it's what it
  // passed in as options), and a wall-clock measurement around the whole sanitize()
  // call is a more honest elapsed time than summing internal per-inspection values.
  function inspectionMeta(inspection) {
    if (!inspection) return {};
    const meta = {
      protectorName: inspection.protectorName,
      dataChannel: inspection.dataChannel,
      transport: inspection.transport,
      source: inspection.source,
    };
    // Only include fields the inspection actually had - keeps the result shape
    // narrow when a field genuinely wasn't there (real Forcepoint responses always
    // have all four; some test fakes deliberately model a leaner response).
    for (const key of Object.keys(meta)) {
      if (meta[key] === undefined) delete meta[key];
    }
    return meta;
  }

  /**
   * Runs the full Key Phrase Redaction workflow for one piece of content:
   * inspect -> (if clean, stop) -> extract matched rules -> map to phrase sets ->
   * redact -> re-inspect -> classify.
   *
   * @param {string} content - plain text to inspect/sanitize (UTF-8)
   * @param {object} [options]
   * @param {string} [options.protectorId] - forwarded to the existing client as-is
   * @param {'http'|'https'} [options.transport] - forwarded to the existing client as-is
   * @param {string} [options.clientIp]
   * @param {string} [options.correlationId] - reuse an upstream request id if the
   *   caller already has one; otherwise a fresh UUID is generated. The SAME id is
   *   used for both Forcepoint calls (each with a distinct suffix, so Forcepoint
   *   itself still sees two distinct global_message_ids) and for every log line.
   * @returns {Promise<
   *   {status:'CLEAN', content:string, redactions:0}
   *   | {status:'SANITIZED', content:string, redactions:number, violations:Array, maxNumberOfMatches:number}
   *   | {status:'BLOCKED', reason:string, violations?:Array, maxNumberOfMatches?:number}
   * >} violations/maxNumberOfMatches, where present, are policy/rule NAMES and
   *   severity only (same shape server.js's /api/scan builds) - never original or
   *   redacted content. The caller uses these to record a real history entry
   *   instead of a sanitize-mode result leaving no trace in History/Analytics/
   *   Verdict Detail at all.
   */
  async function sanitize(content, options = {}) {
    const correlationId = options.correlationId || crypto.randomUUID();
    const clientIp = options.clientIp || '127.0.0.1';
    const inspectOptions = { clientIp, protectorId: options.protectorId, transport: options.transport };
    const log = { correlation_id: correlationId };

    if (typeof content !== 'string') {
      log.result = 'BLOCKED';
      log.reason = BLOCK_REASONS.INVALID_INPUT;
      emitLog(log);
      return blockedResult(BLOCK_REASONS.INVALID_INPUT);
    }
    if (content.length === 0) {
      // Trivially nothing to find - and nothing to protect against, so this is
      // genuinely CLEAN, not a fail-closed case. Also means we never call Forcepoint
      // for empty input, matching "don't call Forcepoint twice when clean" extended
      // to its logical conclusion: don't call it at all when there's nothing to check.
      log.result = 'CLEAN';
      emitLog(log);
      return { status: RESULT_STATUS.CLEAN, content, redactions: 0 };
    }
    if (!keyPhraseConfig.isEnabled()) {
      log.result = 'BLOCKED';
      log.reason = BLOCK_REASONS.FEATURE_NOT_CONFIGURED;
      emitLog(log);
      return blockedResult(BLOCK_REASONS.FEATURE_NOT_CONFIGURED);
    }

    // --- Inspection #1 ---
    let first;
    try {
      first = await inspectWithRetry(Buffer.from(content, 'utf8'), `${correlationId}-inspect1`, inspectOptions);
    } catch (err) {
      // Never got a response at all, so there is no inspection result to pull
      // protectorName/dataChannel/transport/source from - the caller records this
      // attempt with whatever it already knows (the protectorId/transport it asked
      // for) rather than data this service never received.
      log.inspection_1 = 'FAILED';
      log.error_code = err.code || 'UNKNOWN';
      log.result = 'BLOCKED';
      log.reason = BLOCK_REASONS.INSPECTION_FAILED;
      emitLog(log);
      return blockedResult(BLOCK_REASONS.INSPECTION_FAILED);
    }
    if (first.httpStatus < 200 || first.httpStatus >= 300) {
      log.inspection_1 = 'FAILED';
      log.http_status = first.httpStatus;
      log.result = 'BLOCKED';
      log.reason = BLOCK_REASONS.INSPECTION_FAILED;
      emitLog(log);
      return blockedResult(BLOCK_REASONS.INSPECTION_FAILED, inspectionMeta(first));
    }

    const resolution1 = classifyResolution(first.body || {});
    if (!resolution1) {
      log.inspection_1 = 'INVALID';
      log.result = 'BLOCKED';
      log.reason = BLOCK_REASONS.INVALID_RESPONSE;
      emitLog(log);
      return blockedResult(BLOCK_REASONS.INVALID_RESPONSE, inspectionMeta(first));
    }
    log.inspection_1 = resolution1;

    if (resolution1 === 'UNMATCHED') {
      log.result = 'CLEAN';
      emitLog(log);
      return { status: RESULT_STATUS.CLEAN, content, redactions: 0, ...inspectionMeta(first) };
    }

    // --- MATCHED: resolve every violated rule to a local phrase set ---
    const matchedRules = extractMatchedRules(first.body || {});
    if (!matchedRules.length) {
      // MATCHED but nothing usable came out of `violations` - the documented
      // fallback-rule shape (violations: [null]), or some other unexpected empty
      // shape. Either way, there is nothing to safely map or redact, so fail closed.
      log.result = 'BLOCKED';
      log.reason = BLOCK_REASONS.NO_IDENTIFIABLE_RULES;
      emitLog(log);
      return blockedResult(BLOCK_REASONS.NO_IDENTIFIABLE_RULES, inspectionMeta(first));
    }

    log.policy_name = dedupeJoin(matchedRules.map((r) => r.policyName));
    log.rule_name = dedupeJoin(matchedRules.map((r) => r.ruleName));
    log.forcepoint_match_count = matchedRules.reduce((sum, r) => sum + (Number(r.matches) || 0), 0);

    // Merge every matched rule's phrase set, deduped by phrase id - not by rule - so
    // a phrase referenced from two different matched rules is only ever redacted
    // once ("avoid performing the same replacement multiple times when phrase sets
    // overlap"). First rule encountered wins for a shared id's case-sensitivity/
    // replacement text if rules ever disagree - a documented, deliberate simplification.
    const mergedPhrases = new Map(); // id -> {id, value, caseSensitive, replacement} | {id, pattern, validator?, caseSensitive, replacement}
    for (const { ruleName } of matchedRules) {
      const mapping = keyPhraseConfig.getRuleMapping(ruleName);
      if (!mapping) {
        log.result = 'BLOCKED';
        log.reason = BLOCK_REASONS.UNMAPPED_RULE;
        emitLog(log);
        return blockedResult(BLOCK_REASONS.UNMAPPED_RULE, {
          violations: toViolationsShape(matchedRules),
          maxNumberOfMatches: first.body.max_number_of_matches || 0,
          ...inspectionMeta(first),
        });
      }
      for (const phrase of mapping.phrases) {
        if (!mergedPhrases.has(phrase.id)) {
          // A phrase is either {id, value} (literal) or {id, pattern, validator?}
          // (regex-based) - copy whichever shape this one actually has, not just
          // "value" unconditionally, or a pattern phrase would silently end up with
          // neither field set and KeyPhraseRedactor would just never match it at all.
          const shape = typeof phrase.pattern === 'string'
            ? { pattern: phrase.pattern, ...(phrase.validator !== undefined ? { validator: phrase.validator } : {}) }
            : { value: phrase.value };
          mergedPhrases.set(phrase.id, {
            id: phrase.id,
            ...shape,
            caseSensitive: mapping.caseSensitive,
            replacement: mapping.replacement,
          });
        }
      }
    }

    // --- Redact ---
    let redactResult;
    try {
      const redactor = new KeyPhraseRedactor(Array.from(mergedPhrases.values()));
      redactResult = redactor.redact(content);
    } catch (err) {
      log.result = 'BLOCKED';
      log.reason = BLOCK_REASONS.REDACTION_ERROR;
      emitLog(log);
      return blockedResult(BLOCK_REASONS.REDACTION_ERROR, inspectionMeta(first));
    }

    log.local_redaction_count = redactResult.redactionCount;
    log.redacted_phrase_ids = redactResult.matchedPhraseIds; // ids only - never values

    if (redactResult.redactionCount === 0) {
      // Forcepoint says MATCHED, every matched rule had a valid mapping, yet nothing
      // was actually replaced - the local phrase list and Forcepoint's own policy
      // have drifted apart. Never treat this as "must have been the fallback rule
      // again"; it's exactly the fail-closed case the spec calls out by name.
      log.result = 'BLOCKED';
      log.reason = BLOCK_REASONS.ZERO_REDACTIONS;
      emitLog(log);
      return blockedResult(BLOCK_REASONS.ZERO_REDACTIONS, {
        violations: toViolationsShape(matchedRules),
        maxNumberOfMatches: first.body.max_number_of_matches || 0,
        ...inspectionMeta(first),
      });
    }

    // --- Inspection #2: the authoritative check. Local counts are an observability
    // signal only - never proof the content is actually clean. ---
    let second;
    try {
      // first's metadata is the best available here - the same request's second
      // leg never got a response, but it ran against the same protector/channel.
      second = await inspectWithRetry(Buffer.from(redactResult.text, 'utf8'), `${correlationId}-inspect2`, inspectOptions);
    } catch (err) {
      log.inspection_2 = 'FAILED';
      log.error_code = err.code || 'UNKNOWN';
      log.result = 'BLOCKED';
      log.reason = BLOCK_REASONS.INSPECTION_FAILED;
      emitLog(log);
      return blockedResult(BLOCK_REASONS.INSPECTION_FAILED, inspectionMeta(first));
    }
    if (second.httpStatus < 200 || second.httpStatus >= 300) {
      log.inspection_2 = 'FAILED';
      log.http_status = second.httpStatus;
      log.result = 'BLOCKED';
      log.reason = BLOCK_REASONS.INSPECTION_FAILED;
      emitLog(log);
      return blockedResult(BLOCK_REASONS.INSPECTION_FAILED, inspectionMeta(second));
    }

    const resolution2 = classifyResolution(second.body || {});
    if (!resolution2) {
      log.inspection_2 = 'INVALID';
      log.result = 'BLOCKED';
      log.reason = BLOCK_REASONS.INVALID_RESPONSE;
      emitLog(log);
      return blockedResult(BLOCK_REASONS.INVALID_RESPONSE, inspectionMeta(second));
    }
    log.inspection_2 = resolution2;

    if (resolution2 === 'MATCHED') {
      // Report what's STILL present after redaction (the second inspection's own
      // matches), not what the first inspection found - that's the operative reason
      // this is blocked, and the two can legitimately differ (redaction may have
      // cleared some rules but not all of them).
      const stillMatchedRules = extractMatchedRules(second.body || {});
      log.result = 'BLOCKED';
      log.reason = BLOCK_REASONS.POST_REDACTION_DLP_MATCH;
      emitLog(log);
      return blockedResult(BLOCK_REASONS.POST_REDACTION_DLP_MATCH, {
        violations: toViolationsShape(stillMatchedRules),
        maxNumberOfMatches: second.body.max_number_of_matches || 0,
        ...inspectionMeta(second),
      });
    }

    log.result = 'SANITIZED';
    emitLog(log);
    return {
      status: RESULT_STATUS.SANITIZED,
      content: redactResult.text,
      redactions: redactResult.redactionCount,
      // What was originally found and then redacted - policy/rule names and
      // severity only, the same safe-to-log fields as everywhere else in this file.
      // Lets the caller record this as a real (flagged, not blocked) history entry
      // instead of it vanishing from History/Analytics/Verdict Detail entirely.
      violations: toViolationsShape(matchedRules),
      maxNumberOfMatches: first.body.max_number_of_matches || 0,
      ...inspectionMeta(second),
    };
  }

  return { sanitize };
}

function dedupeJoin(values) {
  return Array.from(new Set(values.filter(Boolean))).join(', ');
}

module.exports = { createSanitizationService, RESULT_STATUS, BLOCK_REASONS };
