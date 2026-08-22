// In-process observability counters for the Semantic AI layer - see
// docs/semantic-dlp-architecture.md, Observability. Deliberately in-memory only
// (resets on restart, not persisted) - this is a shadow-mode visibility aid, not a
// durable metrics system, and adding one (Prometheus, a time-series DB, ...) is
// exactly the kind of infrastructure this feature does not need yet.
//
// Never records content, prompts, or evidence - only counts and a classification
// label, matching every other logging path in this project.

const CLASSIFICATION_COUNTER_KEY = {
  PUBLIC: 'classification_public_total',
  INTERNAL: 'classification_internal_total',
  CONFIDENTIAL: 'classification_confidential_total',
  RESTRICTED: 'classification_restricted_total',
  UNCERTAIN: 'classification_uncertain_total',
};

function createAiMetrics() {
  const counters = {
    ai_requests_total: 0,
    ai_success_total: 0,
    ai_failure_total: 0,
    ai_timeout_total: 0,
    ai_chunks_total: 0,
    classification_public_total: 0,
    classification_internal_total: 0,
    classification_confidential_total: 0,
    classification_restricted_total: 0,
    classification_uncertain_total: 0,
    forcepoint_ai_agreement_total: 0,
    forcepoint_ai_disagreement_total: 0,
  };
  let latencySumMs = 0;
  let latencyCount = 0;
  let inputCharsSum = 0;
  let inputCharsCount = 0;

  /**
   * @param {object|null} result - a SemanticResult (src/semanticScanner.js's
   *   scan() return value), or null (AI disabled - not counted at all, since it
   *   never actually ran).
   * @param {object} [meta]
   * @param {number} [meta.inputChars] - length of the normalized text that was
   *   analyzed - a count, never the text itself.
   */
  function recordAiResult(result, meta = {}) {
    if (!result || result.status === 'DISABLED') return;
    counters.ai_requests_total++;
    if (typeof result.processingTimeMs === 'number') {
      latencySumMs += result.processingTimeMs;
      latencyCount++;
    }
    if (typeof meta.inputChars === 'number') {
      inputCharsSum += meta.inputChars;
      inputCharsCount++;
    }
    if (result.status === 'COMPLETED') {
      counters.ai_success_total++;
      const key = CLASSIFICATION_COUNTER_KEY[result.classification];
      if (key) counters[key]++;
    } else {
      counters.ai_failure_total++;
      if (result.status === 'TIMEOUT') counters.ai_timeout_total++;
    }
  }

  function recordChunkCount(chunkCount) {
    if (typeof chunkCount === 'number') counters.ai_chunks_total += chunkCount;
  }

  // "Agreement" is a heuristic, not a precise measure: Forcepoint flagging
  // something and the AI rating it CONFIDENTIAL/RESTRICTED counts as agreement,
  // as does Forcepoint finding nothing and the AI rating it PUBLIC/INTERNAL.
  // Forcepoint-clean + AI-CONFIDENTIAL/RESTRICTED (disagreement) is exactly the
  // "traditional DLP missed this" signal this whole feature exists to surface.
  function recordAgreement(forcepointMatched, aiClassification) {
    if (typeof forcepointMatched !== 'boolean' || !aiClassification || aiClassification === 'UNCERTAIN') return;
    const aiFlagged = aiClassification === 'CONFIDENTIAL' || aiClassification === 'RESTRICTED';
    if (forcepointMatched === aiFlagged) counters.forcepoint_ai_agreement_total++;
    else counters.forcepoint_ai_disagreement_total++;
  }

  function getSnapshot() {
    return {
      ...counters,
      ai_latency_ms_avg: latencyCount ? Math.round(latencySumMs / latencyCount) : 0,
      ai_input_chars_avg: inputCharsCount ? Math.round(inputCharsSum / inputCharsCount) : 0,
    };
  }

  return { recordAiResult, recordChunkCount, recordAgreement, getSnapshot };
}

module.exports = { createAiMetrics };
