const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createAiMetrics } = require('../src/aiMetrics');

test('a null result (AI disabled) is not counted at all', () => {
  const metrics = createAiMetrics();
  metrics.recordAiResult(null);
  metrics.recordAiResult({ status: 'DISABLED' });
  assert.equal(metrics.getSnapshot().ai_requests_total, 0);
});

test('a COMPLETED result increments requests, success, and its classification bucket', () => {
  const metrics = createAiMetrics();
  metrics.recordAiResult({ status: 'COMPLETED', classification: 'CONFIDENTIAL', processingTimeMs: 100 });
  const snap = metrics.getSnapshot();
  assert.equal(snap.ai_requests_total, 1);
  assert.equal(snap.ai_success_total, 1);
  assert.equal(snap.ai_failure_total, 0);
  assert.equal(snap.classification_confidential_total, 1);
  assert.equal(snap.classification_public_total, 0);
});

test('a TIMEOUT result increments requests, failure, and timeout - never success', () => {
  const metrics = createAiMetrics();
  metrics.recordAiResult({ status: 'TIMEOUT', processingTimeMs: 240000 });
  const snap = metrics.getSnapshot();
  assert.equal(snap.ai_requests_total, 1);
  assert.equal(snap.ai_failure_total, 1);
  assert.equal(snap.ai_timeout_total, 1);
  assert.equal(snap.ai_success_total, 0);
});

test('average latency and input chars are computed correctly across multiple results', () => {
  const metrics = createAiMetrics();
  metrics.recordAiResult({ status: 'COMPLETED', classification: 'PUBLIC', processingTimeMs: 100 }, { inputChars: 200 });
  metrics.recordAiResult({ status: 'COMPLETED', classification: 'PUBLIC', processingTimeMs: 300 }, { inputChars: 400 });
  const snap = metrics.getSnapshot();
  assert.equal(snap.ai_latency_ms_avg, 200);
  assert.equal(snap.ai_input_chars_avg, 300);
  assert.equal(snap.classification_public_total, 2);
});

test('agreement: Forcepoint matched + AI CONFIDENTIAL/RESTRICTED counts as agreement', () => {
  const metrics = createAiMetrics();
  metrics.recordAgreement(true, 'CONFIDENTIAL');
  metrics.recordAgreement(true, 'RESTRICTED');
  const snap = metrics.getSnapshot();
  assert.equal(snap.forcepoint_ai_agreement_total, 2);
  assert.equal(snap.forcepoint_ai_disagreement_total, 0);
});

test('agreement: Forcepoint clean + AI CONFIDENTIAL/RESTRICTED is disagreement (the "AI caught what Forcepoint missed" case)', () => {
  const metrics = createAiMetrics();
  metrics.recordAgreement(false, 'RESTRICTED');
  const snap = metrics.getSnapshot();
  assert.equal(snap.forcepoint_ai_disagreement_total, 1);
  assert.equal(snap.forcepoint_ai_agreement_total, 0);
});

test('agreement is skipped (not counted either way) when the AI classification is UNCERTAIN or missing', () => {
  const metrics = createAiMetrics();
  metrics.recordAgreement(true, 'UNCERTAIN');
  metrics.recordAgreement(true, undefined);
  const snap = metrics.getSnapshot();
  assert.equal(snap.forcepoint_ai_agreement_total, 0);
  assert.equal(snap.forcepoint_ai_disagreement_total, 0);
});

test('chunk count accumulates across calls', () => {
  const metrics = createAiMetrics();
  metrics.recordChunkCount(3);
  metrics.recordChunkCount(2);
  assert.equal(metrics.getSnapshot().ai_chunks_total, 5);
});
