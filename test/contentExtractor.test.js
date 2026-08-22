const { test } = require('node:test');
const assert = require('node:assert/strict');
const { extractText, EXTRACTION_STATUS } = require('../src/contentExtractor');

test('plain text decodes cleanly as OK', () => {
  const result = extractText(Buffer.from('Hello, this is a normal sentence.', 'utf8'), 'note.txt');
  assert.equal(result.status, EXTRACTION_STATUS.OK);
  assert.equal(result.text, 'Hello, this is a normal sentence.');
});

test('CSV-shaped text decodes cleanly as OK', () => {
  const csv = 'name,age\nAlice,30\nBob,40\n';
  const result = extractText(Buffer.from(csv, 'utf8'), 'data.csv');
  assert.equal(result.status, EXTRACTION_STATUS.OK);
  assert.equal(result.text, csv);
});

test('JSON-shaped text decodes cleanly as OK', () => {
  const json = JSON.stringify({ a: 1, b: 'two' });
  const result = extractText(Buffer.from(json, 'utf8'), 'data.json');
  assert.equal(result.status, EXTRACTION_STATUS.OK);
});

test('genuinely binary content (many control/invalid bytes) is EXTRACTION_FAILED', () => {
  // A handful of raw bytes in the 0x00-0x08 range, well outside valid UTF-8
  // continuation patterns for this length - decodes to mostly U+FFFD.
  const binary = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52]);
  const result = extractText(binary, 'image.png');
  assert.equal(result.status, EXTRACTION_STATUS.EXTRACTION_FAILED);
});

test('empty buffer is EXTRACTION_FAILED', () => {
  const result = extractText(Buffer.alloc(0), 'empty.txt');
  assert.equal(result.status, EXTRACTION_STATUS.EXTRACTION_FAILED);
});

test('non-Buffer input is EXTRACTION_FAILED rather than throwing', () => {
  const result = extractText('not a buffer', 'x.txt');
  assert.equal(result.status, EXTRACTION_STATUS.EXTRACTION_FAILED);
});

test('a large plain-text document still decodes as OK', () => {
  const big = 'The quick brown fox jumps over the lazy dog. '.repeat(2000);
  const result = extractText(Buffer.from(big, 'utf8'), 'big.txt');
  assert.equal(result.status, EXTRACTION_STATUS.OK);
  assert.equal(result.text.length, big.length);
});
