const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createScanOrchestrator } = require('../src/scanOrchestrator');

test('startScan kicks off both scanners immediately, before either is awaited', async () => {
  const calls = [];
  const fakeForcepointScanner = {
    scan: async (content, context) => { calls.push('forcepoint-called'); return { httpStatus: 200, body: {} }; },
  };
  const fakeRunSemanticAnalysis = async () => { calls.push('ai-called'); return { status: 'DISABLED' }; };

  const orchestrator = createScanOrchestrator({ forcepointScanner: fakeForcepointScanner, runSemanticAnalysis: fakeRunSemanticAnalysis });
  const { forcepointPromise, aiAnalysisPromise, scanId } = orchestrator.startScan({
    buffer: Buffer.from('x'), fileName: 'f.txt', scanId: 'scan-123', clientIp: '1.1.1.1',
  });

  // Both calls must already have happened synchronously within startScan, before
  // either promise is awaited - this is the whole point of the orchestrator.
  assert.deepEqual(calls.sort(), ['ai-called', 'forcepoint-called']);
  assert.equal(scanId, 'scan-123');
  await forcepointPromise;
  await aiAnalysisPromise;
});

test('the same scanId is passed to both the Forcepoint scanner and the AI analysis', async () => {
  let fpScanId, aiScanId;
  const fakeForcepointScanner = { scan: async (content, context) => { fpScanId = context.scanId; return { httpStatus: 200, body: {} }; } };
  const fakeRunSemanticAnalysis = async (buffer, fileName, scanId) => { aiScanId = scanId; return null; };

  const orchestrator = createScanOrchestrator({ forcepointScanner: fakeForcepointScanner, runSemanticAnalysis: fakeRunSemanticAnalysis });
  const { forcepointPromise, aiAnalysisPromise } = orchestrator.startScan({ buffer: Buffer.from('x'), fileName: 'f.txt', scanId: 'shared-id' });
  await forcepointPromise;
  await aiAnalysisPromise;
  assert.equal(fpScanId, 'shared-id');
  assert.equal(aiScanId, 'shared-id');
});

test('a Forcepoint rejection does not prevent the AI promise from resolving normally', async () => {
  const fakeForcepointScanner = { scan: async () => { throw Object.assign(new Error('down'), { code: 'ECONNREFUSED' }); } };
  const fakeRunSemanticAnalysis = async () => ({ status: 'COMPLETED', classification: 'PUBLIC' });

  const orchestrator = createScanOrchestrator({ forcepointScanner: fakeForcepointScanner, runSemanticAnalysis: fakeRunSemanticAnalysis });
  const { forcepointPromise, aiAnalysisPromise } = orchestrator.startScan({ buffer: Buffer.from('x'), fileName: 'f.txt', scanId: 's' });

  await assert.rejects(() => forcepointPromise);
  const aiResult = await aiAnalysisPromise;
  assert.equal(aiResult.status, 'COMPLETED');
});
