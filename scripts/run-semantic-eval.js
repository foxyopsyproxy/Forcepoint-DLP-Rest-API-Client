// Runs the small Semantic AI evaluation dataset (test/fixtures/semantic-eval-dataset.js)
// against a REAL local Ollama instance, using this project's actual config (.env).
// This is NOT part of `npm test` - it requires Ollama to actually be running and can
// take minutes (each case is one real model call on CPU-only hardware). It exists so
// prompt/policy quality can be sanity-checked by eye whenever the prompt or policy
// changes, separate from the deterministic, fast, mocked unit tests.
//
// Usage:
//   node scripts/run-semantic-eval.js

const config = require('../src/config');
const { createOllamaProvider } = require('../src/ollamaProvider');
const { createSemanticPolicyStore } = require('../src/semanticPolicyStore');
const { createSemanticScanner } = require('../src/semanticScanner');
const { CASES } = require('../test/fixtures/semantic-eval-dataset');

const policy = createSemanticPolicyStore();
const provider = createOllamaProvider({
  baseUrl: config.semanticAi.ollamaBaseUrl,
  model: config.semanticAi.ollamaModel,
  timeoutMs: config.semanticAi.ollamaTimeoutMs,
});
const scanner = createSemanticScanner({
  provider,
  policy,
  // Forced on regardless of AI_DLP_ENABLED in .env - this script's whole purpose is
  // to exercise the classifier, so it does not defer to the app's own on/off switch.
  aiConfig: { ...config.semanticAi, enabled: true, mode: 'shadow' },
});

async function main() {
  console.log(`Model: ${config.semanticAi.ollamaModel}  Ollama: ${config.semanticAi.ollamaBaseUrl}`);
  console.log(`Running ${CASES.length} cases - each is a real model call, this can take several minutes.\n`);

  for (const c of CASES) {
    const startedAt = Date.now();
    const result = await scanner.scan(c.text, { scanId: `eval-${c.name}` });
    const elapsedS = ((Date.now() - startedAt) / 1000).toFixed(1);

    console.log(`=== ${c.name} (${elapsedS}s) ===`);
    console.log(`expected: ${c.expect}`);
    if (result.status !== 'COMPLETED') {
      console.log(`status: ${result.status}${result.error ? ` (${result.error})` : ''}`);
    } else {
      console.log(`got:      ${result.classification} [${result.categories.join(', ') || '-'}] confidence=${result.confidence}`);
      console.log(`reason:   ${result.reason}`);
      if (result.evidence.length) {
        result.evidence.forEach((e) => console.log(`evidence: "${e.quote}" - ${e.reason}`));
      }
    }
    console.log('');
  }
}

main().catch((err) => {
  console.error('Eval run failed:', err);
  process.exit(1);
});
