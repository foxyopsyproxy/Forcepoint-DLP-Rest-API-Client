const { VALIDATORS } = require('./keyPhraseValidators');

function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Literal-string and pattern-based Key Phrase matching and redaction.
 *
 * Deliberately isolated behind this small constructor(phrases) + redact(text)
 * interface, and nothing else, so SanitizationService (the orchestration layer)
 * never needs to know HOW matching happens. A future, more scalable matcher (e.g.
 * Aho-Corasick, for very large phrase lists where this class's one-pass-per-phrase
 * approach would start to matter) can replace this class's internals - or be swapped
 * in wholesale - without changing a single line of the orchestration layer, as long
 * as it keeps the same redact(text) -> {text, redactionCount, matchedPhraseIds} shape.
 */
class KeyPhraseRedactor {
  /**
   * @param {({id:string, value:string, caseSensitive:boolean, replacement:string}
   *   | {id:string, pattern:string, validator?:string, caseSensitive:boolean, replacement:string})[]} phrases
   */
  constructor(phrases) {
    const valid = (phrases || []).filter(
      (p) => p && typeof p.id === 'string' && ((typeof p.value === 'string' && p.value.length > 0) || (typeof p.pattern === 'string' && p.pattern.length > 0))
    );
    // Longer literal phrases are matched first. Without this, a shorter configured
    // phrase ("PROJECT") could consume part of a longer one ("PROJECT ALPHA") before
    // the longer phrase's own turn ever comes, leaving a stray "ALPHA" behind instead
    // of one clean redaction - see the module tests for the exact scenario. Pattern
    // phrases have no comparable "length" (they match variable-width content, e.g.
    // an id number), so they are simply tried after every literal phrase instead.
    const literals = valid.filter((p) => typeof p.value === 'string').sort((a, b) => b.value.length - a.value.length);
    const patterns = valid.filter((p) => typeof p.pattern === 'string');
    this.phrases = [...literals, ...patterns];
  }

  /**
   * Replaces every occurrence of every configured phrase in `text`. All non-matching
   * content is preserved exactly. A literal phrase's value is looked for as a literal
   * substring (Unicode-aware), never interpreted as regex syntax. A pattern phrase's
   * value IS a regex source string, interpreted as-is; if it also names a validator
   * (see keyPhraseValidators.js), a match is only redacted - and only counted - when
   * the validator accepts it, so e.g. a random 9-digit number that fails an id
   * checksum is left alone rather than redacted as if it were a real one.
   *
   * @param {string} text
   * @returns {{text: string, redactionCount: number, matchedPhraseIds: string[]}}
   */
  redact(text) {
    let result = text;
    let redactionCount = 0;
    const matchedPhraseIds = [];

    for (const phrase of this.phrases) {
      const isPattern = typeof phrase.pattern === 'string';
      // 'u' for correct Unicode handling (Hebrew, emoji, combining marks, ...);
      // 'i' only when the rule allows case-insensitive matching.
      const flags = phrase.caseSensitive ? 'gu' : 'giu';
      const regex = new RegExp(isPattern ? phrase.pattern : escapeRegExp(phrase.value), flags);
      const hasValidator = isPattern && phrase.validator !== undefined;
      const validatorFn = hasValidator ? VALIDATORS[phrase.validator] : null;
      let occurrences = 0;
      result = result.replace(regex, (match) => {
        // keyPhraseConfig.js's validation should make an unrecognized validator name
        // unreachable in the real app, but if it ever did happen, fail closed (never
        // redact) rather than silently falling through to "no validator" behavior -
        // consistent with this file's UNMAPPED_RULE/ZERO_REDACTIONS "when in doubt,
        // don't guess" philosophy.
        if (hasValidator && typeof validatorFn !== 'function') return match;
        if (validatorFn && !validatorFn(match)) return match; // looks right, fails validation - leave it alone
        occurrences += 1;
        return phrase.replacement;
      });
      if (occurrences > 0) {
        redactionCount += occurrences;
        matchedPhraseIds.push(phrase.id);
      }
    }

    return { text: result, redactionCount, matchedPhraseIds };
  }
}

module.exports = { KeyPhraseRedactor, escapeRegExp };
