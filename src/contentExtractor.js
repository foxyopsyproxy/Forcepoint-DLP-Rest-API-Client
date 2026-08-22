// Bytes -> normalized text for the Semantic AI classifier (src/semanticScanner.js).
// Deliberately narrow for Milestone 1: this app has no existing binary-document
// parser (no PDF/DOCX/XLSX/PPTX library in package.json, and none is added here -
// see docs/semantic-dlp-architecture.md, section 8). Anything that decodes as clean
// UTF-8 text (plain text, CSV, JSON, and similar) is supported; genuine binary
// formats resolve to EXTRACTION_FAILED, which never affects the existing Forcepoint
// scan of the same file.

const EXTRACTION_STATUS = { OK: 'OK', EXTRACTION_FAILED: 'EXTRACTION_FAILED' };

// A UTF-8 decode of arbitrary binary data never throws in Node - invalid byte
// sequences just become U+FFFD replacement characters - so "did this decode
// cleanly" has to be judged after the fact rather than caught as an error. A real
// binary file (image, PDF, docx zip, ...) produces either a lot of replacement
// characters or a lot of raw control bytes; genuine text essentially never does.
const MAX_SUSPICIOUS_RATIO = 0.01;

function looksLikeBinary(text) {
  if (!text.length) return false;
  let suspicious = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    // U+FFFD (invalid UTF-8), or a C0 control character other than tab/LF/CR.
    if (code === 0xfffd || (code < 32 && code !== 9 && code !== 10 && code !== 13)) {
      suspicious++;
    }
  }
  return suspicious / text.length > MAX_SUSPICIOUS_RATIO;
}

/**
 * @param {Buffer} buffer - raw file bytes, exactly what was uploaded (never mutated).
 * @param {string} [fileName] - for a future format-aware dispatch; unused today
 *   since every supported format is handled identically (decode as UTF-8, sanity
 *   check the result).
 * @returns {{status: 'OK', text: string} | {status: 'EXTRACTION_FAILED'}}
 */
function extractText(buffer, fileName) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return { status: EXTRACTION_STATUS.EXTRACTION_FAILED };
  }
  const text = buffer.toString('utf8');
  if (looksLikeBinary(text)) {
    return { status: EXTRACTION_STATUS.EXTRACTION_FAILED };
  }
  return { status: EXTRACTION_STATUS.OK, text };
}

module.exports = { extractText, EXTRACTION_STATUS };
