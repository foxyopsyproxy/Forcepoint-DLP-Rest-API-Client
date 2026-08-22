const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createForcepointScanner } = require('../src/forcepointScanner');

test('scan() forwards exactly the given arguments to inspectFileWithFailover, in order', async () => {
  let captured;
  const fakeProtectorClient = {
    inspectFileWithFailover: async (buffer, fileName, clientIp, scanId, protectorId, transport) => {
      captured = { buffer, fileName, clientIp, scanId, protectorId, transport };
      return { httpStatus: 200, body: { resolution: 'UNMATCHED' } };
    },
  };
  const scanner = createForcepointScanner({ protectorClient: fakeProtectorClient });
  const buf = Buffer.from('hello');
  const result = await scanner.scan(
    { buffer: buf, fileName: 'test.txt' },
    { clientIp: '1.2.3.4', scanId: 'scan-1', protectorId: 'p1', transport: 'https' }
  );
  assert.deepEqual(captured, { buffer: buf, fileName: 'test.txt', clientIp: '1.2.3.4', scanId: 'scan-1', protectorId: 'p1', transport: 'https' });
  assert.deepEqual(result, { httpStatus: 200, body: { resolution: 'UNMATCHED' } });
});

test('a resolved (even non-2xx) result passes through completely unchanged', async () => {
  const fakeProtectorClient = {
    inspectFileWithFailover: async () => ({ httpStatus: 502, body: { some: 'error body' }, elapsedMs: 42 }),
  };
  const scanner = createForcepointScanner({ protectorClient: fakeProtectorClient });
  const result = await scanner.scan({ buffer: Buffer.from('x'), fileName: 'f' }, { scanId: 's' });
  assert.deepEqual(result, { httpStatus: 502, body: { some: 'error body' }, elapsedMs: 42 });
});

test('a rejection propagates unchanged, including its error code', async () => {
  const fakeProtectorClient = {
    inspectFileWithFailover: async () => { throw Object.assign(new Error('boom'), { code: 'TIMEOUT', elapsedMs: 99 }); },
  };
  const scanner = createForcepointScanner({ protectorClient: fakeProtectorClient });
  await assert.rejects(
    () => scanner.scan({ buffer: Buffer.from('x'), fileName: 'f' }, { scanId: 's' }),
    (err) => { assert.equal(err.code, 'TIMEOUT'); assert.equal(err.elapsedMs, 99); return true; }
  );
});
