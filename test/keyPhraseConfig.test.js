const { test } = require('node:test');
const assert = require('node:assert/strict');
const { buildConfig } = require('../src/keyPhraseConfig');

const VALID = {
  phrase_sets: {
    sensitive_projects: [
      { id: 'project_alpha', value: 'PROJECT ALPHA' },
      { id: 'blue_fox', value: 'BLUE FOX' },
    ],
  },
  rules: {
    'Project Names': { phrase_set: 'sensitive_projects', replacement: '[REDACTED]', case_sensitive: false },
  },
};

test('a valid config loads and exposes the rule mapping', () => {
  const cfg = buildConfig(VALID, 'test');
  assert.equal(cfg.isEnabled(), true);
  const mapping = cfg.getRuleMapping('Project Names');
  assert.ok(mapping);
  assert.equal(mapping.phraseSetId, 'sensitive_projects');
  assert.equal(mapping.replacement, '[REDACTED]');
  assert.equal(mapping.caseSensitive, false);
  assert.equal(mapping.phrases.length, 2);
});

test('an unmapped rule name returns undefined, not a throw', () => {
  const cfg = buildConfig(VALID, 'test');
  assert.equal(cfg.getRuleMapping('Some Other Rule'), undefined);
});

test('case_sensitive defaults to false when omitted', () => {
  const cfg = buildConfig(
    { phrase_sets: VALID.phrase_sets, rules: { R: { phrase_set: 'sensitive_projects', replacement: '[X]' } } },
    'test'
  );
  assert.equal(cfg.getRuleMapping('R').caseSensitive, false);
});

test('rejects a root that is not an object', () => {
  assert.throws(() => buildConfig(null, 'test'), /root must be a JSON object/);
  assert.throws(() => buildConfig([1, 2, 3], 'test'), /root must be a JSON object/);
  assert.throws(() => buildConfig('not an object', 'test'), /root must be a JSON object/);
});

test('rejects a config missing phrase_sets or rules entirely', () => {
  assert.throws(() => buildConfig({ rules: {} }, 'test'), /phrase_sets" must be an object/);
  assert.throws(() => buildConfig({ phrase_sets: {} }, 'test'), /rules" must be an object/);
});

test('rejects an empty phrase value', () => {
  const cfg = { phrase_sets: { s: [{ id: 'x', value: '' }] }, rules: {} };
  assert.throws(() => buildConfig(cfg, 'test'), /empty phrase value/);
});

test('rejects a phrase entry missing an id', () => {
  const cfg = { phrase_sets: { s: [{ value: 'X' }] }, rules: {} };
  assert.throws(() => buildConfig(cfg, 'test'), /\.id must be a non-empty string/);
});

test('rejects duplicate phrase ids, even across different phrase sets', () => {
  const cfg = {
    phrase_sets: {
      s1: [{ id: 'dup', value: 'ONE' }],
      s2: [{ id: 'dup', value: 'TWO' }],
    },
    rules: {},
  };
  assert.throws(() => buildConfig(cfg, 'test'), /Duplicate phrase id "dup"/);
});

test('rejects a rule referencing a nonexistent phrase_set', () => {
  const cfg = {
    phrase_sets: { real_set: [{ id: 'a', value: 'A' }] },
    rules: { R: { phrase_set: 'missing_set', replacement: '[X]' } },
  };
  assert.throws(() => buildConfig(cfg, 'test'), /references nonexistent phrase_set "missing_set"/);
});

test('rejects a rule with a missing replacement value', () => {
  const cfg = {
    phrase_sets: { s: [{ id: 'a', value: 'A' }] },
    rules: { R: { phrase_set: 's' } },
  };
  assert.throws(() => buildConfig(cfg, 'test'), /replacement must be a non-empty string/);
});

test('rejects a rule pointing at a phrase_set with zero valid phrases (an empty phrase set)', () => {
  const cfg = {
    phrase_sets: { s: [] },
    rules: { R: { phrase_set: 's', replacement: '[X]' } },
  };
  assert.throws(() => buildConfig(cfg, 'test'), /has no valid phrases/);
});

test('rejects case_sensitive when it is not a boolean', () => {
  const cfg = {
    phrase_sets: { s: [{ id: 'a', value: 'A' }] },
    rules: { R: { phrase_set: 's', replacement: '[X]', case_sensitive: 'yes' } },
  };
  assert.throws(() => buildConfig(cfg, 'test'), /case_sensitive must be a boolean/);
});

test('rejects invalid types: phrase_sets entry not an array, rule not an object', () => {
  assert.throws(
    () => buildConfig({ phrase_sets: { s: 'not-an-array' }, rules: {} }, 'test'),
    /phrase_sets\.s must be an array/
  );
  assert.throws(
    () => buildConfig({ phrase_sets: { s: [{ id: 'a', value: 'A' }] }, rules: { R: 'not-an-object' } }, 'test'),
    /rules\["R"\] must be an object/
  );
});

test('rejects two rule keys that are the same once trimmed', () => {
  // A literal duplicate JSON *key* (e.g. `{"R": {...}, "R": {...}}`) is already
  // collapsed to one entry by JSON.parse before this function ever sees it - that
  // case cannot be detected post-parse by any validator. What IS detectable, and
  // what this guards against, is two keys that differ only by surrounding
  // whitespace and would otherwise silently shadow one another.
  const raw = JSON.parse('{"phrase_sets": {"s": [{"id":"a","value":"A"}]}, "rules": {}}');
  raw.rules['Rule One'] = { phrase_set: 's', replacement: '[X]' };
  raw.rules[' Rule One '] = { phrase_set: 's', replacement: '[X]' };
  assert.throws(() => buildConfig(raw, 'test'), /Duplicate rule "Rule One"/);
});

// =====================================================================
// Pattern-based phrases ({id, pattern, validator?} instead of {id, value})
// =====================================================================

test('a valid pattern phrase (with no validator) loads and is usable', () => {
  const cfg = buildConfig(
    {
      phrase_sets: { ids: [{ id: 'any_9_digits', pattern: '\\b\\d{9}\\b' }] },
      rules: { R: { phrase_set: 'ids', replacement: '[REDACTED]' } },
    },
    'test'
  );
  const mapping = cfg.getRuleMapping('R');
  assert.deepEqual(mapping.phrases, [{ id: 'any_9_digits', pattern: '\\b\\d{9}\\b' }]);
});

test('a pattern phrase with a known validator loads and keeps the validator name', () => {
  const cfg = buildConfig(
    {
      phrase_sets: { ids: [{ id: 'israeli_id', pattern: '\\b\\d{9}\\b', validator: 'israeliId' }] },
      rules: { R: { phrase_set: 'ids', replacement: '[REDACTED]' } },
    },
    'test'
  );
  assert.deepEqual(cfg.getRuleMapping('R').phrases, [{ id: 'israeli_id', pattern: '\\b\\d{9}\\b', validator: 'israeliId' }]);
});

test('rejects a phrase entry with neither value nor pattern', () => {
  const cfg = { phrase_sets: { s: [{ id: 'x' }] }, rules: {} };
  assert.throws(() => buildConfig(cfg, 'test'), /must have exactly one of "value" or "pattern", not neither/);
});

test('rejects a phrase entry with both value and pattern', () => {
  const cfg = { phrase_sets: { s: [{ id: 'x', value: 'A', pattern: '\\d+' }] }, rules: {} };
  assert.throws(() => buildConfig(cfg, 'test'), /must have exactly one of "value" or "pattern", not both/);
});

test('rejects an empty pattern string', () => {
  const cfg = { phrase_sets: { s: [{ id: 'x', pattern: '' }] }, rules: {} };
  assert.throws(() => buildConfig(cfg, 'test'), /empty pattern/);
});

test('rejects a pattern that is not valid regex syntax', () => {
  const cfg = { phrase_sets: { s: [{ id: 'x', pattern: '[unterminated' }] }, rules: {} };
  assert.throws(() => buildConfig(cfg, 'test'), /invalid pattern/);
});

test('rejects a pattern phrase naming an unknown validator', () => {
  const cfg = { phrase_sets: { s: [{ id: 'x', pattern: '\\d+', validator: 'not_a_real_one' }] }, rules: {} };
  assert.throws(() => buildConfig(cfg, 'test'), /unknown validator "not_a_real_one"/);
});

test('duplicate phrase ids are still rejected across a mix of value and pattern phrases', () => {
  const cfg = {
    phrase_sets: {
      s1: [{ id: 'dup', value: 'ONE' }],
      s2: [{ id: 'dup', pattern: '\\d+' }],
    },
    rules: {},
  };
  assert.throws(() => buildConfig(cfg, 'test'), /Duplicate phrase id "dup"/);
});

test('collects multiple errors into a single thrown message rather than stopping at the first', () => {
  const cfg = {
    phrase_sets: { s: [{ id: 'a', value: '' }] },
    rules: { R: { phrase_set: 'missing', replacement: '' } },
  };
  try {
    buildConfig(cfg, 'test');
    assert.fail('expected buildConfig to throw');
  } catch (err) {
    assert.match(err.message, /empty phrase value/);
    assert.match(err.message, /nonexistent phrase_set/);
  }
});
