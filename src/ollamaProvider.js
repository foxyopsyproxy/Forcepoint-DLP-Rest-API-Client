// Thin HTTP client for a local Ollama server. This is the one and only place that
// knows Ollama's request/response shape - src/semanticScanner.js only ever calls
// `provider.classify(prompt, schema)` and gets back a plain result object, never a
// raw Ollama response. A future second provider (a different local runtime, or a
// hosted model) would implement the same `classify()` shape and be swapped in at
// createSemanticScanner({provider}) without semanticScanner.js changing at all.
//
// Uses Node's core `http` module (not `fetch`) - the same convention already used
// elsewhere in this project (src/protectorClient.js, src/webhookNotifier.js), for a
// concrete, measured reason: Node's global `fetch` (backed by undici) enforces its
// own internal headers-timeout independently of any AbortController deadline passed
// to it, and killed a real, healthy-but-slow Ollama response with
// UND_ERR_HEADERS_TIMEOUT during testing - a false failure on exactly the kind of
// legitimately slow CPU-only inference this feature has to tolerate. `http.request`'s
// own `timeout` option is the only timeout in play here. No new npm dependency either
// way - this machine's corporate proxy blocks `npm install`.

const http = require('http');

const PROVIDER_ERROR = {
  MODEL_UNAVAILABLE: 'MODEL_UNAVAILABLE', // Ollama unreachable, or the model isn't pulled
  TIMEOUT: 'TIMEOUT',
  INVALID_RESPONSE: 'INVALID_RESPONSE', // reachable, but the body wasn't usable JSON
};

/**
 * @param {object} opts
 * @param {string} opts.baseUrl - e.g. http://127.0.0.1:11434 (config.semanticAi.ollamaBaseUrl)
 * @param {string} opts.model - e.g. qwen3:8b (config.semanticAi.ollamaModel) - read
 *   fresh from this value on every call, never hardcoded.
 * @param {number} opts.timeoutMs
 * @param {string} [opts.keepAlive] - Ollama's `keep_alive` (e.g. "30m") - how long the
 *   model stays loaded in RAM after this call, so the NEXT scan skips the load cost.
 * @param {number} [opts.numCtx] - Ollama's `options.num_ctx` (context window).
 * @param {number} [opts.numPredict] - Ollama's `options.num_predict` (generation cap).
 *   A real, measured finding: this alone is NOT sufficient to guarantee a valid
 *   response - see src/semanticScanner.js's schema `maxLength`/`maxItems` bounds,
 *   which are what actually force the model to close its JSON inside this budget.
 * @param {number} [opts.temperature] - Ollama's `options.temperature`.
 * @param {typeof http.request} [opts.requestImpl] - override for tests (fake network
 *   calls without a real Ollama server running).
 */
function createOllamaProvider({ baseUrl, model, timeoutMs, keepAlive, numCtx, numPredict, temperature, requestImpl = http.request }) {
  const target = new URL('/api/generate', baseUrl);

  /**
   * @param {string} prompt - full prompt text (already includes policy + content;
   *   see semanticScanner.js's buildPrompt). Never logged by this function.
   * @param {object} schema - JSON Schema object; passed as Ollama's `format` param
   *   so the model is constrained to emit matching JSON (Ollama structured outputs).
   * @returns {Promise<
   *   {ok: true, raw: string}
   *   | {ok: false, errorType: 'MODEL_UNAVAILABLE'|'TIMEOUT'|'INVALID_RESPONSE', message: string}
   * >} `raw` is the model's raw JSON-text response, still unparsed/unvalidated -
   *   schema validation and evidence checking are semanticScanner.js's job, not this
   *   provider's, so every provider implementation is validated identically.
   */
  function classify(prompt, schema) {
    const payload = JSON.stringify({
      model,
      prompt,
      stream: false,
      think: false, // qwen3 is a "thinking" model; shadow-mode classification has no use for reasoning tokens
      ...(keepAlive !== undefined ? { keep_alive: keepAlive } : {}),
      format: schema,
      options: {
        ...(temperature !== undefined ? { temperature } : {}),
        ...(numCtx !== undefined ? { num_ctx: numCtx } : {}),
        ...(numPredict !== undefined ? { num_predict: numPredict } : {}),
      },
    });

    return new Promise((resolve) => {
      const req = requestImpl(
        {
          hostname: target.hostname,
          port: target.port,
          path: target.pathname,
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
          timeout: timeoutMs,
        },
        (res) => {
          const chunks = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () => {
            if (res.statusCode < 200 || res.statusCode >= 300) {
              return resolve({ ok: false, errorType: PROVIDER_ERROR.MODEL_UNAVAILABLE, message: `Ollama returned HTTP ${res.statusCode}` });
            }
            let body;
            try {
              body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            } catch (err) {
              return resolve({ ok: false, errorType: PROVIDER_ERROR.INVALID_RESPONSE, message: 'Ollama response was not valid JSON' });
            }
            if (typeof body.response !== 'string' || !body.response.trim()) {
              return resolve({ ok: false, errorType: PROVIDER_ERROR.INVALID_RESPONSE, message: 'Ollama response had no "response" field' });
            }
            resolve({ ok: true, raw: body.response });
          });
        }
      );

      // A single, explicit deadline covering the whole request (connect through
      // response body) - the only timeout involved, unlike fetch's layered/hidden
      // undici defaults (see this file's header comment).
      req.on('timeout', () => {
        req.destroy(Object.assign(new Error(`Ollama did not respond within ${timeoutMs}ms`), { code: 'TIMEOUT' }));
      });
      req.on('error', (err) => {
        if (err.code === 'TIMEOUT') {
          return resolve({ ok: false, errorType: PROVIDER_ERROR.TIMEOUT, message: err.message });
        }
        // Connection refused / DNS failure / reset mid-response / etc - Ollama isn't
        // reachable, or stopped answering.
        resolve({ ok: false, errorType: PROVIDER_ERROR.MODEL_UNAVAILABLE, message: err.message });
      });

      req.write(payload);
      req.end();
    });
  }

  return { classify };
}

module.exports = { createOllamaProvider, PROVIDER_ERROR };
