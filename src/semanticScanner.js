const fs = require('fs');
const path = require('path');

// The Semantic AI classification layer (Milestone 1 - shadow mode). Orchestrates
// chunking, prompt assembly, calling an LLMProvider (src/ollamaProvider.js
// implements one), schema-validating the response, validating evidence quotes
// against the source text, and aggregating chunk results into one document-level
// SemanticResult. This function is designed to NEVER throw - every failure mode
// (disabled, extraction failure, model unavailable, timeout, invalid response, an
// unexpected internal error) resolves to a result object with an explicit `status`,
// so a caller can always safely `await scan(...)` alongside the existing Forcepoint
// call without it ever being able to break that path. See
// docs/semantic-dlp-architecture.md for the full flow and the "never depends on
// Forcepoint" requirement this satisfies.

const AI_STATUS = {
  DISABLED: 'DISABLED',
  COMPLETED: 'COMPLETED',
  TIMEOUT: 'TIMEOUT',
  EXTRACTION_FAILED: 'EXTRACTION_FAILED',
  MODEL_UNAVAILABLE: 'MODEL_UNAVAILABLE',
  INVALID_RESPONSE: 'INVALID_RESPONSE',
  ERROR: 'ERROR',
};

const SEVERITY_RANK = { RESTRICTED: 4, CONFIDENTIAL: 3, INTERNAL: 2, PUBLIC: 1, UNCERTAIN: 0 };
const PROMPT_VERSION = 'v1';
const MAX_EVIDENCE_ITEMS = 10;

function loadPromptTemplate() {
  return fs.readFileSync(path.join(__dirname, '..', 'prompts', `semantic-dlp-${PROMPT_VERSION}.txt`), 'utf8');
}

/**
 * Paragraph-boundary-aware chunking: prefers to split on blank lines rather than an
 * arbitrary character offset, per the "bounded large-content processing" requirement.
 * A single paragraph longer than chunkSize is hard-split as a fallback (rare - most
 * real documents don't have one unbroken paragraph longer than a few thousand
 * characters). Overlap is applied by prefixing each chunk after the first with the
 * tail of the previous one, so a fact split across a chunk boundary still has a
 * chance of appearing whole in at least one chunk.
 */
function chunkText(text, { chunkSize, overlap }) {
  if (text.length <= chunkSize) return [text];

  const paragraphs = text.split(/\n\s*\n/);
  const chunks = [];
  let current = '';
  for (const para of paragraphs) {
    if (para.length > chunkSize) {
      if (current) { chunks.push(current); current = ''; }
      for (let i = 0; i < para.length; i += chunkSize) chunks.push(para.slice(i, i + chunkSize));
      continue;
    }
    const candidate = current ? `${current}\n\n${para}` : para;
    if (candidate.length > chunkSize) {
      chunks.push(current);
      current = para;
    } else {
      current = candidate;
    }
  }
  if (current) chunks.push(current);

  if (overlap > 0 && chunks.length > 1) {
    return chunks.map((c, i) => (i === 0 ? c : `${chunks[i - 1].slice(-overlap)}\n\n${c}`));
  }
  return chunks;
}

/**
 * @param {object} deps
 * @param {{classify: Function}} deps.provider - an LLMProvider (e.g. createOllamaProvider())
 * @param {{getSensitivityLevels: Function, getCategoryNames: Function, getPolicy: Function, getVersion: Function}} deps.policy
 * @param {object} deps.aiConfig - config.semanticAi shape (see src/config.js)
 * @param {Console} [deps.logger] - override for tests
 */
function createSemanticScanner({ provider, policy, aiConfig, logger = console }) {
  let promptTemplate = null;
  let responseSchema = null;

  function getPromptTemplate() {
    if (!promptTemplate) promptTemplate = loadPromptTemplate();
    return promptTemplate;
  }

  // Built once from the policy's own levels/categories, not duplicated by hand -
  // if the policy file gains a category, both the prompt and the schema pick it up
  // automatically.
  //
  // maxLength on `reason`/evidence.reason and maxItems on `categories`/`evidence`
  // are the actual, measured fix for a real reliability problem (see
  // config.semanticAi.ollamaNumPredict's comment in src/config.js): qwen3:4b at
  // temperature 0 is naturally verbose in free-text fields and, left unbounded,
  // will spend its entire generation budget on a long "reason" without ever
  // reaching the JSON's closing punctuation - producing a timeout or an
  // unparseable truncated response no matter how generous num_predict is made.
  // Ollama's grammar-constrained structured-output decoder enforces these bounds
  // directly, forcing the model to close the string/array - and therefore the
  // whole JSON object - well inside the token budget, instead of hoping the model
  // chooses to stop on its own. Verified live: the same cases that previously
  // timed out at 240s completed correctly in 66-95s once these bounds were added.
  function getResponseSchema() {
    if (responseSchema) return responseSchema;
    responseSchema = {
      type: 'object',
      properties: {
        classification: { type: 'string', enum: policy.getSensitivityLevels() },
        categories: { type: 'array', items: { type: 'string', enum: policy.getCategoryNames() }, maxItems: 5 },
        confidence: { type: 'number' },
        reason: { type: 'string', maxLength: 220 },
        evidence: {
          type: 'array',
          items: {
            type: 'object',
            properties: { quote: { type: 'string' }, reason: { type: 'string', maxLength: 150 } },
            required: ['quote', 'reason'],
          },
          maxItems: MAX_EVIDENCE_ITEMS,
        },
      },
      required: ['classification', 'categories', 'confidence', 'reason', 'evidence'],
    };
    return responseSchema;
  }

  function buildPrompt(content) {
    const levels = policy.getSensitivityLevels().map((l) => `- ${l}`).join('\n');
    const categoriesObj = policy.getPolicy().categories;
    const categories = policy
      .getCategoryNames()
      .map((name) => `- ${name}: ${categoriesObj[name].description}`)
      .join('\n');
    return getPromptTemplate()
      .replace('{{SENSITIVITY_LEVELS}}', levels)
      .replace('{{CATEGORIES}}', categories)
      .replace('{{CONTENT}}', content);
  }

  // Never trusts the model's JSON blindly: classification/confidence must be
  // structurally valid or the whole response is rejected (INVALID_RESPONSE);
  // categories are filtered to known names rather than rejecting the whole response
  // over one hallucinated category name; evidence quotes are checked against
  // `sourceText` one by one and silently dropped if they don't appear verbatim -
  // this app must never display evidence as though it came from the document when
  // it didn't (see docs/semantic-dlp-architecture.md, "Evidence Validation").
  function validateAndSanitize(parsed, sourceText) {
    if (!parsed || typeof parsed !== 'object') return null;
    const { classification, categories, confidence, reason, evidence } = parsed;

    if (typeof classification !== 'string' || !policy.getSensitivityLevels().includes(classification)) return null;
    if (typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence < 0 || confidence > 1) return null;

    const knownCategories = new Set(policy.getCategoryNames());
    const safeCategories = Array.isArray(categories)
      ? categories.filter((c) => typeof c === 'string' && knownCategories.has(c))
      : [];

    const rawEvidence = Array.isArray(evidence) ? evidence : [];
    const safeEvidence = rawEvidence
      .filter((e) => e && typeof e.quote === 'string' && e.quote.length > 0 && sourceText.includes(e.quote))
      .slice(0, MAX_EVIDENCE_ITEMS)
      .map((e) => ({ quote: e.quote, reason: typeof e.reason === 'string' ? e.reason : '' }));

    return {
      classification,
      categories: safeCategories,
      confidence,
      reason: typeof reason === 'string' ? reason : '',
      evidence: safeEvidence,
    };
  }

  async function classifyChunk(chunk) {
    let providerResult;
    try {
      providerResult = await provider.classify(buildPrompt(chunk), getResponseSchema());
    } catch (err) {
      // Providers are documented not to throw, but this call site never trusts that
      // guarantee blindly - the whole point of this module is that nothing it does
      // can ever propagate as an unhandled rejection into the caller.
      return { ok: false, errorType: AI_STATUS.ERROR, message: err.message };
    }
    if (!providerResult.ok) {
      return { ok: false, errorType: providerResult.errorType, message: providerResult.message };
    }

    let parsed;
    try {
      parsed = JSON.parse(providerResult.raw);
    } catch (err) {
      return { ok: false, errorType: AI_STATUS.INVALID_RESPONSE, message: 'Model response was not valid JSON' };
    }

    const validated = validateAndSanitize(parsed, chunk);
    if (!validated) {
      return { ok: false, errorType: AI_STATUS.INVALID_RESPONSE, message: 'Model response failed schema validation' };
    }
    return { ok: true, ...validated };
  }

  // Highest severity wins across successfully-classified chunks. A partial failure
  // (some chunks classified, others didn't) makes the aggregate unsafe to trust as
  // a specific level - per the spec, that resolves to UNCERTAIN, not to whatever the
  // successful chunks happened to say, since the parts that failed were never
  // actually assessed.
  function aggregate(succeeded, hadPartialFailure) {
    let best = succeeded[0];
    for (const r of succeeded) {
      if (SEVERITY_RANK[r.classification] > SEVERITY_RANK[best.classification]) best = r;
    }
    const categories = Array.from(new Set(succeeded.flatMap((r) => r.categories)));
    const evidence = succeeded.flatMap((r) => r.evidence).slice(0, MAX_EVIDENCE_ITEMS);

    if (hadPartialFailure) {
      return {
        classification: 'UNCERTAIN',
        categories,
        confidence: 0,
        reason: `Not all of this document could be analyzed, so its overall sensitivity is uncertain. The highest classification among the parts that were successfully analyzed was ${best.classification}.`,
        evidence,
      };
    }
    if (succeeded.length === 1) return succeeded[0];
    return {
      classification: best.classification,
      categories,
      confidence: succeeded.reduce((sum, r) => sum + r.confidence, 0) / succeeded.length,
      reason: `Highest-sensitivity finding across ${succeeded.length} analyzed sections of this document: ${best.reason}`,
      evidence,
    };
  }

  function safeLog(entry) {
    // SECURITY: mirrors sanitizationService.js's emitLog() - this object must never
    // gain a field holding the original content, the full prompt, or an evidence
    // quote. Only the metadata listed in docs/semantic-dlp-architecture.md /
    // the Milestone 1 spec: scan_id, timestamp, file metadata, model/prompt/policy
    // version, the final classification + category names, processing time, and an
    // error type on failure.
    logger.log(JSON.stringify(entry));
  }

  /**
   * @param {string} text - normalized text already extracted from the original
   *   file (see src/contentExtractor.js) - this function never sees raw bytes.
   * @param {object} [context]
   * @param {string} [context.scanId] - reuse the caller's existing correlation id
   *   (e.g. the same value sent to Forcepoint as global_message_id) - see
   *   docs/semantic-dlp-architecture.md section 3 (Scan Correlation).
   * @param {string} [context.fileName]
   * @param {number} [context.fileSizeBytes]
   * @param {string} [context.sha256] - caller-computed hash of the original file
   *   bytes, for the log line only - never computed from or compared against text.
   * @returns {Promise<object>} always has a `status` field; see AI_STATUS. Never throws.
   */
  async function scan(text, context = {}) {
    const scanId = context.scanId;
    const startedAt = Date.now();
    const baseLog = {
      scan_id: scanId,
      timestamp: new Date().toISOString(),
      file_name: context.fileName,
      file_size: context.fileSizeBytes,
      sha256: context.sha256,
      model: aiConfig.ollamaModel,
      prompt_version: PROMPT_VERSION,
    };

    try {
      if (!aiConfig.enabled) {
        return { status: AI_STATUS.DISABLED, scanId };
      }
      // Only shadow mode is implemented in this milestone - see
      // docs/semantic-dlp-architecture.md section 8. An unrecognized/unsupported
      // mode must never be treated as "enabled with unknown behavior".
      if (aiConfig.mode !== 'shadow') {
        return { status: AI_STATUS.DISABLED, scanId, mode: aiConfig.mode };
      }
      if (typeof text !== 'string' || text.length === 0) {
        safeLog({ ...baseLog, policy_version: policy.getVersion(), status: AI_STATUS.EXTRACTION_FAILED });
        return { status: AI_STATUS.EXTRACTION_FAILED, scanId };
      }

      let workingText = text;
      let truncated = false;
      if (workingText.length > aiConfig.maxContentSize) {
        workingText = workingText.slice(0, aiConfig.maxContentSize);
        truncated = true;
      }

      const chunks = chunkText(workingText, { chunkSize: aiConfig.chunkSize, overlap: aiConfig.chunkOverlap });

      // AI concurrency = 1 (the safe default for this milestone's target hardware -
      // see docs/semantic-dlp-architecture.md) - chunks are classified strictly
      // sequentially, never in parallel.
      const chunkResults = [];
      for (const chunk of chunks) {
        chunkResults.push(await classifyChunk(chunk));
      }

      const succeeded = chunkResults.filter((r) => r.ok);
      const failed = chunkResults.filter((r) => !r.ok);
      const processingTimeMs = Date.now() - startedAt;

      if (!succeeded.length) {
        const errorType = failed[0].errorType;
        safeLog({ ...baseLog, policy_version: policy.getVersion(), status: errorType, processing_time: processingTimeMs, error_type: errorType });
        return { status: errorType, scanId, model: aiConfig.ollamaModel, promptVersion: PROMPT_VERSION, processingTimeMs, error: failed[0].message };
      }

      const aggregated = aggregate(succeeded, failed.length > 0);
      const result = {
        status: AI_STATUS.COMPLETED,
        scanId,
        classification: aggregated.classification,
        categories: aggregated.categories,
        confidence: aggregated.confidence,
        reason: aggregated.reason,
        evidence: aggregated.evidence,
        model: aiConfig.ollamaModel,
        promptVersion: PROMPT_VERSION,
        policyVersion: policy.getVersion(),
        processingTimeMs,
        ...(truncated ? { truncated: true } : {}),
        ...(failed.length ? { partialFailure: true, chunksFailed: failed.length, chunksTotal: chunkResults.length } : {}),
      };
      safeLog({
        ...baseLog,
        policy_version: policy.getVersion(),
        classification: result.classification,
        categories: result.categories,
        processing_time: processingTimeMs,
        status: AI_STATUS.COMPLETED,
      });
      return result;
    } catch (err) {
      // Absolute last resort - guarantees scan() truly never throws, no matter what
      // goes wrong internally (a bug in aggregation, an unexpected policy shape,
      // etc). Failure must never be reported as PUBLIC/safe (see AI_STATUS.ERROR).
      safeLog({ ...baseLog, status: AI_STATUS.ERROR, error_type: 'INTERNAL', processing_time: Date.now() - startedAt });
      return { status: AI_STATUS.ERROR, scanId, error: err.message };
    }
  }

  return { scan };
}

module.exports = { createSemanticScanner, AI_STATUS, chunkText, PROMPT_VERSION };
