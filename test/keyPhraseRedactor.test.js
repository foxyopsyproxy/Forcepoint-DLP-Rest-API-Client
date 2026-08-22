const { test } = require('node:test');
const assert = require('node:assert/strict');
const { KeyPhraseRedactor } = require('../src/keyPhraseRedactor');

function phrase(id, value, overrides = {}) {
  return { id, value, caseSensitive: false, replacement: '[REDACTED]', ...overrides };
}

test('content with no Key Phrase is returned unchanged', () => {
  const r = new KeyPhraseRedactor([phrase('a', 'SECRET')]);
  const result = r.redact('Nothing interesting here.');
  assert.equal(result.text, 'Nothing interesting here.');
  assert.equal(result.redactionCount, 0);
  assert.deepEqual(result.matchedPhraseIds, []);
});

test('a single Key Phrase is redacted', () => {
  const r = new KeyPhraseRedactor([phrase('a', 'SECRET')]);
  const result = r.redact('The SECRET is out.');
  assert.equal(result.text, 'The [REDACTED] is out.');
  assert.equal(result.redactionCount, 1);
  assert.deepEqual(result.matchedPhraseIds, ['a']);
});

test('multiple distinct Key Phrases are all redacted', () => {
  const r = new KeyPhraseRedactor([phrase('a', 'ALPHA'), phrase('b', 'BRAVO')]);
  const result = r.redact('ALPHA met BRAVO yesterday.');
  assert.equal(result.text, '[REDACTED] met [REDACTED] yesterday.');
  assert.equal(result.redactionCount, 2);
  assert.deepEqual(new Set(result.matchedPhraseIds), new Set(['a', 'b']));
});

test('the same Key Phrase appearing multiple times is redacted every time', () => {
  const r = new KeyPhraseRedactor([phrase('a', 'ALPHA')]);
  const result = r.redact('ALPHA and ALPHA and ALPHA again.');
  assert.equal(result.text, '[REDACTED] and [REDACTED] and [REDACTED] again.');
  assert.equal(result.redactionCount, 3);
  assert.deepEqual(result.matchedPhraseIds, ['a']);
});

test('multiple phrase sets merged into one redactor still redact everything', () => {
  const setA = [phrase('a1', 'PROJECT ALPHA')];
  const setB = [phrase('b1', 'BLUE FOX')];
  const r = new KeyPhraseRedactor([...setA, ...setB]);
  const result = r.redact('PROJECT ALPHA works with BLUE FOX.');
  assert.equal(result.text, '[REDACTED] works with [REDACTED].');
  assert.equal(result.redactionCount, 2);
});

test('case-insensitive matching redacts regardless of case', () => {
  const r = new KeyPhraseRedactor([phrase('a', 'secret', { caseSensitive: false })]);
  const result = r.redact('SECRET, Secret, and secret all count.');
  assert.equal(result.text, '[REDACTED], [REDACTED], and [REDACTED] all count.');
  assert.equal(result.redactionCount, 3);
});

test('case-sensitive matching only redacts an exact-case match', () => {
  const r = new KeyPhraseRedactor([phrase('a', 'SECRET', { caseSensitive: true })]);
  const result = r.redact('SECRET stays hidden but secret and Secret do not match.');
  assert.equal(result.text, '[REDACTED] stays hidden but secret and Secret do not match.');
  assert.equal(result.redactionCount, 1);
});

test('Unicode content (emoji, accents) is preserved outside the match', () => {
  const r = new KeyPhraseRedactor([phrase('a', 'café')]);
  const result = r.redact('Meet at the café 🎉 after PROJECT café closes.');
  assert.equal(result.text, 'Meet at the [REDACTED] 🎉 after PROJECT [REDACTED] closes.');
  assert.equal(result.redactionCount, 2);
});

test('Hebrew content is matched and redacted correctly', () => {
  const r = new KeyPhraseRedactor([phrase('a', 'פרויקט אלפא')]);
  const result = r.redact('העבודה על פרויקט אלפא מתקדמת יפה.');
  assert.equal(result.text, 'העבודה על [REDACTED] מתקדמת יפה.');
  assert.equal(result.redactionCount, 1);
});

test('phrases containing spaces are matched as one literal unit', () => {
  const r = new KeyPhraseRedactor([phrase('a', 'PROJECT ALPHA')]);
  const result = r.redact('PROJECT ALPHA is real but PROJECT BETA is not configured.');
  assert.equal(result.text, '[REDACTED] is real but PROJECT BETA is not configured.');
  assert.equal(result.redactionCount, 1);
});

test('phrases containing punctuation are matched literally, not as regex', () => {
  const r = new KeyPhraseRedactor([phrase('a', 'A.T.&T. (Corp.)')]);
  const result = r.redact('Contact A.T.&T. (Corp.) for details.');
  assert.equal(result.text, 'Contact [REDACTED] for details.');
  assert.equal(result.redactionCount, 1);
});

test('a phrase containing regex metacharacters does not act as a regex', () => {
  // If '.' were treated as "any character" this would also match "PROJECTXALPHA".
  const r = new KeyPhraseRedactor([phrase('a', 'PROJECT.ALPHA')]);
  const result = r.redact('PROJECTXALPHA should not match, but PROJECT.ALPHA should.');
  assert.equal(result.text, 'PROJECTXALPHA should not match, but [REDACTED] should.');
  assert.equal(result.redactionCount, 1);
});

test('overlapping phrases: longer phrase is redacted before the shorter one can consume part of it', () => {
  const r = new KeyPhraseRedactor([phrase('short', 'PROJECT'), phrase('long', 'PROJECT ALPHA')]);
  const result = r.redact('PROJECT ALPHA is classified. A separate PROJECT is not.');
  assert.equal(result.text, '[REDACTED] is classified. A separate [REDACTED] is not.');
  assert.equal(result.redactionCount, 2);
  assert.deepEqual(new Set(result.matchedPhraseIds), new Set(['short', 'long']));
});

test('sorting happens regardless of input order (shorter phrase configured first)', () => {
  // Same scenario as above, but the shorter phrase is listed FIRST in the input array -
  // the constructor's own sort must still try the longer phrase first.
  const r = new KeyPhraseRedactor([phrase('short', 'PROJECT'), phrase('long', 'PROJECT ALPHA')]);
  const result = r.redact('PROJECT ALPHA');
  assert.equal(result.text, '[REDACTED]');
  assert.equal(result.redactionCount, 1);
  assert.deepEqual(result.matchedPhraseIds, ['long']);
});

test('non-matching content is preserved exactly, including whitespace and newlines', () => {
  const r = new KeyPhraseRedactor([phrase('a', 'SECRET')]);
  const input = 'Line one.\nLine two has SECRET in it.\n\tIndented line three.';
  const result = r.redact(input);
  assert.equal(result.text, 'Line one.\nLine two has [REDACTED] in it.\n\tIndented line three.');
});

test('an empty phrase list redacts nothing', () => {
  const r = new KeyPhraseRedactor([]);
  const result = r.redact('Anything at all.');
  assert.equal(result.text, 'Anything at all.');
  assert.equal(result.redactionCount, 0);
});

// =====================================================================
// Pattern-based phrases (regex source, optionally narrowed by a named validator -
// for content that varies per instance, like an id number, rather than a fixed
// project codename)
// =====================================================================

function patternPhrase(id, pattern, overrides = {}) {
  return { id, pattern, caseSensitive: false, replacement: '[REDACTED]', ...overrides };
}

test('a pattern phrase without a validator redacts every regex match', () => {
  const r = new KeyPhraseRedactor([patternPhrase('a', '\\b\\d{9}\\b')]);
  const result = r.redact('The number 123456789 appears once.');
  assert.equal(result.text, 'The number [REDACTED] appears once.');
  assert.equal(result.redactionCount, 1);
  assert.deepEqual(result.matchedPhraseIds, ['a']);
});

test('a pattern phrase with a validator only redacts matches the validator accepts', () => {
  // '123456782' is a real checksum-valid Israeli id; '123456789' matches the same
  // 9-digit pattern but fails the checksum, so it must be left alone.
  const r = new KeyPhraseRedactor([patternPhrase('id', '\\b\\d{9}\\b', { validator: 'israeliId' })]);
  const result = r.redact('Valid: 123456782. Invalid: 123456789.');
  assert.equal(result.text, 'Valid: [REDACTED]. Invalid: 123456789.');
  assert.equal(result.redactionCount, 1);
  assert.deepEqual(result.matchedPhraseIds, ['id']);
});

test('a pattern phrase with a validator that rejects every match redacts nothing and is not counted', () => {
  const r = new KeyPhraseRedactor([patternPhrase('id', '\\b\\d{9}\\b', { validator: 'israeliId' })]);
  const result = r.redact('Only invalid ones here: 123456789 and 000000001.');
  assert.equal(result.text, 'Only invalid ones here: 123456789 and 000000001.');
  assert.equal(result.redactionCount, 0);
  assert.deepEqual(result.matchedPhraseIds, []);
});

test('literal and pattern phrases can be combined and both take effect', () => {
  const r = new KeyPhraseRedactor([
    phrase('codename', 'PROJECT ALPHA'),
    patternPhrase('id', '\\b\\d{9}\\b', { validator: 'israeliId' }),
  ]);
  const result = r.redact('PROJECT ALPHA involves subject 123456782.');
  assert.equal(result.text, '[REDACTED] involves subject [REDACTED].');
  assert.equal(result.redactionCount, 2);
  assert.deepEqual(new Set(result.matchedPhraseIds), new Set(['codename', 'id']));
});

test('an unknown validator name is simply never true, so nothing is ever redacted', () => {
  // KeyPhraseRedactor trusts its caller (SanitizationService, via keyPhraseConfig's
  // validation) to only ever hand it a known validator name - this just documents
  // the fail-safe behavior if that ever somehow did not hold.
  const r = new KeyPhraseRedactor([patternPhrase('id', '\\b\\d{9}\\b', { validator: 'not_a_real_validator' })]);
  const result = r.redact('123456782 is a valid id but the validator name is not real.');
  assert.equal(result.redactionCount, 0);
});
