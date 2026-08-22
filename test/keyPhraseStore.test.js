const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createKeyPhraseStore } = require('../src/keyPhraseStore');

const VALID = {
  phrase_sets: { terms: [{ id: 'a', value: 'SECRET' }] },
  rules: { 'Rule One': { phrase_set: 'terms', replacement: '[REDACTED]' } },
};

const INVALID = {
  phrase_sets: { terms: [{ id: 'a', value: '' }] }, // empty phrase value
  rules: {},
};

// Each test gets its own temp file rather than sharing one, so tests never
// interfere with each other's cached in-memory state.
function tempConfigFile(initialContent) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kp-store-test-'));
  const file = path.join(dir, 'key-phrases.json');
  if (initialContent !== undefined) fs.writeFileSync(file, JSON.stringify(initialContent, null, 2));
  return file;
}

test('disabled when no configPath is given', () => {
  const store = createKeyPhraseStore({ configPath: '' });
  assert.equal(store.isEnabled(), false);
  assert.equal(store.getCompiled().isEnabled(), false);
  assert.throws(() => store.getRaw(), /not configured/);
  assert.throws(() => store.saveRaw(VALID), /not configured/);
});

test('a valid file loads and is usable via getCompiled() and getRaw()', () => {
  const file = tempConfigFile(VALID);
  const store = createKeyPhraseStore({ configPath: file });
  assert.equal(store.isEnabled(), true);
  assert.equal(store.getCompiled().isEnabled(), true);
  assert.ok(store.getCompiled().getRuleMapping('Rule One'));
  assert.deepEqual(store.getRaw(), VALID);
});

test('getCompiled() throws if the file has never successfully loaded even once', () => {
  const file = tempConfigFile(INVALID);
  const store = createKeyPhraseStore({ configPath: file });
  assert.throws(() => store.getCompiled(), /empty phrase value/);
});

test('saveRaw() validates before writing - an invalid config is rejected and never reaches disk', () => {
  const file = tempConfigFile(VALID);
  const store = createKeyPhraseStore({ configPath: file });
  assert.throws(() => store.saveRaw(INVALID), /empty phrase value/);
  // The file on disk must be completely untouched by the rejected write.
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), VALID);
  // ...and the compiled config already in memory must still be the old, good one.
  assert.ok(store.getCompiled().getRuleMapping('Rule One'));
});

test('saveRaw() with a valid config persists to disk and is visible on the very next getCompiled() call - no restart, no separate reload step', () => {
  const file = tempConfigFile(VALID);
  const store = createKeyPhraseStore({ configPath: file });
  assert.ok(store.getCompiled().getRuleMapping('Rule One'));
  assert.equal(store.getCompiled().getRuleMapping('Rule Two'), undefined);

  const updated = {
    phrase_sets: { terms: [{ id: 'a', value: 'SECRET' }] },
    rules: {
      'Rule One': { phrase_set: 'terms', replacement: '[REDACTED]' },
      'Rule Two': { phrase_set: 'terms', replacement: '[REDACTED]' },
    },
  };
  store.saveRaw(updated);

  assert.ok(store.getCompiled().getRuleMapping('Rule One'));
  assert.ok(store.getCompiled().getRuleMapping('Rule Two'), 'the new rule must be visible without any reload step');
  assert.deepEqual(store.getRaw(), updated);
});

test('a reload failure after a successful load falls back to the last known-good config instead of throwing', () => {
  const file = tempConfigFile(VALID);
  const store = createKeyPhraseStore({ configPath: file });
  assert.ok(store.getCompiled().getRuleMapping('Rule One')); // loads successfully once

  // Simulate the file being hand-edited into a broken state outside saveRaw() -
  // mtime must actually change for the store to even attempt a reload.
  fs.writeFileSync(file, '{ not valid json');
  fs.utimesSync(file, new Date(Date.now() + 5000), new Date(Date.now() + 5000));

  const originalError = console.error;
  const loggedErrors = [];
  console.error = (msg) => loggedErrors.push(msg);
  try {
    const compiled = store.getCompiled();
    assert.ok(compiled.getRuleMapping('Rule One'), 'must keep serving the last good config, not throw or go blank');
    assert.equal(loggedErrors.length, 1);
    assert.match(loggedErrors[0], /reload failed/);
  } finally {
    console.error = originalError;
  }
});
