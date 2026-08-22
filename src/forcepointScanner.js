// Thin adapter around the existing, working Forcepoint client
// (src/protectorClient.js's inspectFileWithFailover) so it can be referred to as a
// named "Scanner" alongside src/semanticScanner.js, matching the
// ScanOrchestrator/ForcepointScanner/SemanticScanner shape in
// docs/semantic-dlp-architecture.md.
//
// Deliberately a pure pass-through, not a reshape: it forwards the exact same
// arguments to inspectFileWithFailover and returns/throws exactly what that
// function returns/throws (resolve shape, httpStatus, error .code values on
// rejection - all unchanged). server.js's existing, carefully-tuned branching on
// httpStatus/error.code around this call needed zero changes to work with this
// wrapper in place - that was the point. No new behavior, no new risk to a path
// that has stayed stable through every other change this project has made.

/**
 * @param {object} deps
 * @param {{inspectFileWithFailover: Function}} deps.protectorClient - the real
 *   src/protectorClient.js module (or a fake with the same shape, for tests).
 */
function createForcepointScanner({ protectorClient }) {
  /**
   * @param {object} content
   * @param {Buffer} content.buffer - raw file bytes, exactly as uploaded.
   * @param {string} content.fileName
   * @param {object} context
   * @param {string} context.scanId - the platform-wide correlation id; forwarded
   *   as-is to inspectFileWithFailover, which sends it to Forcepoint as
   *   global_message_id (see docs/semantic-dlp-architecture.md, Scan Correlation).
   * @param {string} [context.clientIp]
   * @param {string} [context.protectorId]
   * @param {'http'|'https'} [context.transport]
   * @returns {Promise<object>} exactly protectorClient.inspectFileWithFailover's
   *   own resolve shape; throws exactly what it throws.
   */
  function scan(content, context) {
    return protectorClient.inspectFileWithFailover(
      content.buffer,
      content.fileName,
      context.clientIp,
      context.scanId,
      context.protectorId,
      context.transport
    );
  }

  return { scan };
}

module.exports = { createForcepointScanner };
