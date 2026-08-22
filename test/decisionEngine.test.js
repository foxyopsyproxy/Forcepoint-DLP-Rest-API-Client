const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createDecisionEngine } = require('../src/decisionEngine');

test('no AI classification (or UNCERTAIN) yields UNCERTAIN, never a guessed decision', () => {
  const engine = createDecisionEngine();
  assert.equal(engine.decide({}).theoreticalDecision, 'UNCERTAIN');
  assert.equal(engine.decide({ aiClassification: undefined }).theoreticalDecision, 'UNCERTAIN');
  assert.equal(engine.decide({ aiClassification: 'UNCERTAIN' }).theoreticalDecision, 'UNCERTAIN');
});

test('RESTRICTED is always a theoretical BLOCK, regardless of transmission context', () => {
  const engine = createDecisionEngine();
  assert.equal(engine.decide({ aiClassification: 'RESTRICTED' }).theoreticalDecision, 'BLOCK');
  assert.equal(engine.decide({ aiClassification: 'RESTRICTED', transactionContext: { destination: 'internal' } }).theoreticalDecision, 'BLOCK');
});

test('CONFIDENTIAL blocks only when combined with a high-risk transmission context', () => {
  const engine = createDecisionEngine();
  assert.equal(engine.decide({ aiClassification: 'CONFIDENTIAL' }).theoreticalDecision, 'ALLOW');
  assert.equal(engine.decide({ aiClassification: 'CONFIDENTIAL', transactionContext: { destination: 'external' } }).theoreticalDecision, 'BLOCK');
  assert.equal(engine.decide({ aiClassification: 'CONFIDENTIAL', transactionContext: { channel: 'EMAIL' } }).theoreticalDecision, 'BLOCK');
});

test('INTERNAL and PUBLIC are always ALLOW', () => {
  const engine = createDecisionEngine();
  assert.equal(engine.decide({ aiClassification: 'INTERNAL', transactionContext: { destination: 'external' } }).theoreticalDecision, 'ALLOW');
  assert.equal(engine.decide({ aiClassification: 'PUBLIC', transactionContext: { destination: 'external' } }).theoreticalDecision, 'ALLOW');
});

test('an absent transactionContext is never itself treated as risk', () => {
  const engine = createDecisionEngine();
  assert.equal(engine.decide({ aiClassification: 'CONFIDENTIAL', transactionContext: undefined }).theoreticalDecision, 'ALLOW');
});

test('every decision includes a human-readable reason', () => {
  const engine = createDecisionEngine();
  const result = engine.decide({ aiClassification: 'RESTRICTED' });
  assert.equal(typeof result.reason, 'string');
  assert.ok(result.reason.length > 0);
});
