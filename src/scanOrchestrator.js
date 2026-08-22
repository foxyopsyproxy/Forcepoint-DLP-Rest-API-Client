// Coordinates the two independent scan engines (ForcepointScanner, SemanticScanner)
// under one correlation id - see docs/semantic-dlp-architecture.md's
// ScanOrchestrator / ForcepointScanner / SemanticScanner shape.
//
// Deliberately does NOT await or catch either scanner's promise itself: it only
// starts both at the same moment and hands both promises back. server.js's
// existing try/catch and httpStatus branching around the Forcepoint call already
// does exactly the right thing (record history, pick an HTTP status, attach
// aiAnalysis to whichever response path is taken) and needed zero changes to work
// with this in place - this module's only job is to make "start both scanners in
// parallel, same scan_id" a named, reusable, testable operation instead of two
// inline statements repeated at every call site.

/**
 * @param {object} deps
 * @param {{scan: Function}} deps.forcepointScanner - src/forcepointScanner.js
 * @param {(buffer: Buffer, fileName: string, scanId: string) => Promise<object|null>} deps.runSemanticAnalysis
 *   - server.js's existing helper: returns null when AI is disabled (cheap,
 *   skips extraction/hashing entirely), otherwise a SemanticResult. Never rejects.
 */
function createScanOrchestrator({ forcepointScanner, runSemanticAnalysis }) {
  /**
   * @param {object} params
   * @param {Buffer} params.buffer
   * @param {string} params.fileName
   * @param {string} params.scanId - the one correlation id shared by Forcepoint
   *   (as global_message_id), the AI classification, and the final response.
   * @param {string} [params.clientIp]
   * @param {string} [params.protectorId]
   * @param {'http'|'https'} [params.transport]
   * @returns {{scanId: string, forcepointPromise: Promise<object>, aiAnalysisPromise: Promise<object|null>}}
   *   Both promises are already in flight when this returns. forcepointPromise
   *   resolves/rejects exactly as protectorClient.inspectFileWithFailover does -
   *   callers must handle it the same way they always have. aiAnalysisPromise
   *   never rejects.
   */
  function startScan({ buffer, fileName, scanId, clientIp, protectorId, transport }) {
    // Kicked off before the Forcepoint call, not after - Semantic AI must never
    // depend on Forcepoint detecting something first (see
    // docs/semantic-dlp-architecture.md, Critical Architecture Principle).
    const aiAnalysisPromise = runSemanticAnalysis(buffer, fileName, scanId);
    const forcepointPromise = forcepointScanner.scan({ buffer, fileName }, { clientIp, scanId, protectorId, transport });
    return { scanId, forcepointPromise, aiAnalysisPromise };
  }

  return { startScan };
}

module.exports = { createScanOrchestrator };
