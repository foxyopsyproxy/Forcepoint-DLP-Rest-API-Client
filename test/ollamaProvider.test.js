const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');
const { createOllamaProvider, PROVIDER_ERROR } = require('../src/ollamaProvider');

// Fakes Node's http.request(options, callback) shape exactly (not fetch) - see
// src/ollamaProvider.js's header comment for why it uses http.request directly.
// `onEnd` receives (options, writtenBody) and returns { statusCode, body } | { error } | { timeout: true }.
function fakeTransport(onEnd) {
  return (options, callback) => {
    const req = new EventEmitter();
    let written = '';
    req.write = (chunk) => { written += chunk; };
    req.destroy = (err) => { req.emit('error', err); };
    req.end = () => {
      process.nextTick(() => {
        const outcome = onEnd(options, written);
        if (outcome.timeout) return req.emit('timeout');
        if (outcome.error) return req.emit('error', outcome.error);
        const res = new EventEmitter();
        res.statusCode = outcome.statusCode ?? 200;
        callback(res);
        res.emit('data', Buffer.from(outcome.body));
        res.emit('end');
      });
    };
    return req;
  };
}

test('a successful call returns ok:true with the raw response text', async () => {
  const provider = createOllamaProvider({
    baseUrl: 'http://fake:11434',
    model: 'test-model',
    timeoutMs: 5000,
    requestImpl: fakeTransport(() => ({ body: JSON.stringify({ response: '{"classification":"PUBLIC"}' }) })),
  });
  const result = await provider.classify('prompt text', { type: 'object' });
  assert.equal(result.ok, true);
  assert.equal(result.raw, '{"classification":"PUBLIC"}');
});

test('sends the configured model, keep_alive, and options - never hardcoded', async () => {
  let capturedBody;
  let capturedOptions;
  const provider = createOllamaProvider({
    baseUrl: 'http://fake:11434',
    model: 'my-configured-model',
    timeoutMs: 5000,
    keepAlive: '30m',
    numCtx: 2048,
    numPredict: 150,
    temperature: 0,
    requestImpl: fakeTransport((options, written) => {
      capturedOptions = options;
      capturedBody = JSON.parse(written);
      return { body: JSON.stringify({ response: '{}' }) };
    }),
  });
  await provider.classify('the prompt', { type: 'object', properties: { x: {} } });
  assert.equal(capturedBody.model, 'my-configured-model');
  assert.equal(capturedBody.prompt, 'the prompt');
  assert.equal(capturedBody.stream, false);
  assert.equal(capturedBody.think, false);
  assert.equal(capturedBody.keep_alive, '30m');
  assert.deepEqual(capturedBody.options, { temperature: 0, num_ctx: 2048, num_predict: 150 });
  assert.deepEqual(capturedBody.format, { type: 'object', properties: { x: {} } });
  assert.equal(capturedOptions.method, 'POST');
  assert.equal(capturedOptions.path, '/api/generate');
  assert.equal(capturedOptions.timeout, 5000);
});

test('a non-2xx HTTP status is reported as MODEL_UNAVAILABLE', async () => {
  const provider = createOllamaProvider({
    baseUrl: 'http://fake:11434',
    model: 'm',
    timeoutMs: 5000,
    requestImpl: fakeTransport(() => ({ statusCode: 500, body: '{}' })),
  });
  const result = await provider.classify('p', {});
  assert.equal(result.ok, false);
  assert.equal(result.errorType, PROVIDER_ERROR.MODEL_UNAVAILABLE);
});

test('a connection error is reported as MODEL_UNAVAILABLE, never thrown', async () => {
  const provider = createOllamaProvider({
    baseUrl: 'http://fake:11434',
    model: 'm',
    timeoutMs: 5000,
    requestImpl: fakeTransport(() => ({ error: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }) })),
  });
  const result = await provider.classify('p', {});
  assert.equal(result.ok, false);
  assert.equal(result.errorType, PROVIDER_ERROR.MODEL_UNAVAILABLE);
});

test('a real timeout (no undici hidden timeout involved) is reported as TIMEOUT', async () => {
  const provider = createOllamaProvider({
    baseUrl: 'http://fake:11434',
    model: 'm',
    timeoutMs: 5000,
    requestImpl: fakeTransport(() => ({ timeout: true })),
  });
  const result = await provider.classify('p', {});
  assert.equal(result.ok, false);
  assert.equal(result.errorType, PROVIDER_ERROR.TIMEOUT);
});

test('a response body that is not valid JSON is INVALID_RESPONSE', async () => {
  const provider = createOllamaProvider({
    baseUrl: 'http://fake:11434',
    model: 'm',
    timeoutMs: 5000,
    requestImpl: fakeTransport(() => ({ body: 'not json' })),
  });
  const result = await provider.classify('p', {});
  assert.equal(result.ok, false);
  assert.equal(result.errorType, PROVIDER_ERROR.INVALID_RESPONSE);
});

test('a response with no "response" field is INVALID_RESPONSE', async () => {
  const provider = createOllamaProvider({
    baseUrl: 'http://fake:11434',
    model: 'm',
    timeoutMs: 5000,
    requestImpl: fakeTransport(() => ({ body: JSON.stringify({ done: true }) })),
  });
  const result = await provider.classify('p', {});
  assert.equal(result.ok, false);
  assert.equal(result.errorType, PROVIDER_ERROR.INVALID_RESPONSE);
});
