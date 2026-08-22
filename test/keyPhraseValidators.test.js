const { test } = require('node:test');
const assert = require('node:assert/strict');
const { VALIDATORS } = require('../src/keyPhraseValidators');

// Fixtures found by brute-force search against the real algorithm, not hand-picked -
// see the session that added this file. Deliberately not the app's own real test
// data from elsewhere in the codebase, to keep this test self-contained.
const VALID_IDS = ['123456782', '400638342', '312961840', '195561766'];
const INVALID_IDS = ['123456789', '039512345', '203548539', '111111112'];

test('israeliId: accepts known checksum-valid 9-digit numbers', () => {
  for (const id of VALID_IDS) {
    assert.equal(VALIDATORS.israeliId(id), true, `expected ${id} to be valid`);
  }
});

test('israeliId: rejects 9-digit numbers with a wrong checksum', () => {
  for (const id of INVALID_IDS) {
    assert.equal(VALIDATORS.israeliId(id), false, `expected ${id} to be invalid`);
  }
});

test('israeliId: shorter numbers are left-padded with zeros before checking', () => {
  // A real id is still 9 digits underneath - people commonly drop a leading zero
  // when writing it casually. The 8-digit and full 9-digit forms of the same id
  // must validate the same way.
  assert.equal(VALIDATORS.israeliId('010000008'), true);
  assert.equal(VALIDATORS.israeliId('10000008'), true);
});

test('israeliId: rejects numbers shorter than 5 digits or longer than 9', () => {
  assert.equal(VALIDATORS.israeliId('1234'), false);
  assert.equal(VALIDATORS.israeliId('12345678901'), false);
});

test('israeliId: non-digit characters are stripped before checking', () => {
  // A validator only ever sees what its regex already matched, but it should not
  // fall over if given separators anyway.
  assert.equal(VALIDATORS.israeliId('123-456-782'), true);
});

test('israeliId: an all-zero number is a degenerate but checksum-valid case', () => {
  // The checksum alone cannot know a number was never actually issued - it can only
  // reject numbers that do not conform to the format at all. Documented here so it
  // is a known property, not a surprise.
  assert.equal(VALIDATORS.israeliId('000000000'), true);
});
