const fs = require('fs');
const path = require('path');

// Parses config/semantic-dlp-policy.yaml. This is intentionally NOT a general YAML
// parser - it understands exactly the one fixed shape that file uses:
//
//   sensitivity_levels:
//     - NAME
//     - NAME
//   categories:
//     CATEGORY_NAME:
//       description: >-
//         folded block scalar text,
//         possibly wrapped over several lines
//
// No new npm dependency is added for this (this project cannot currently run
// `npm install` at all - see docs/semantic-dlp-architecture.md, section 8), and a
// real YAML parser would be over-scoped for one small, fixed-shape config file.
// Anything outside this shape is a validation error, not silently ignored.

function isBlankOrComment(line) {
  const trimmed = line.trim();
  return trimmed === '' || trimmed.startsWith('#');
}

function indentOf(line) {
  const match = line.match(/^ */);
  return match[0].length;
}

/**
 * @param {string} raw - file contents
 * @returns {{sensitivityLevels: string[], categories: Record<string, {description: string}>}}
 * @throws {Error} with every structural problem found, if the file doesn't match
 *   the expected shape (collects all problems rather than stopping at the first).
 */
function parsePolicyYaml(raw, sourceLabel = 'semantic-dlp-policy.yaml') {
  const lines = raw.split('\n').filter((l) => !isBlankOrComment(l));
  const errors = [];

  let sensitivityLevels = [];
  const categories = {};

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const indent = indentOf(line);
    const trimmed = line.trim();

    if (indent === 0 && trimmed === 'sensitivity_levels:') {
      i++;
      while (i < lines.length && indentOf(lines[i]) > 0 && lines[i].trim().startsWith('- ')) {
        sensitivityLevels.push(lines[i].trim().slice(2).trim());
        i++;
      }
      continue;
    }

    if (indent === 0 && trimmed === 'categories:') {
      i++;
      while (i < lines.length && indentOf(lines[i]) > 0) {
        const catIndent = indentOf(lines[i]);
        const catLine = lines[i].trim();
        if (!catLine.endsWith(':')) {
          errors.push(`Expected a category name ending in ":" at line ${i + 1}, got: "${catLine}"`);
          i++;
          continue;
        }
        const categoryName = catLine.slice(0, -1).trim();
        i++;

        let description = null;
        while (i < lines.length && indentOf(lines[i]) > catIndent) {
          const fieldLine = lines[i].trim();
          if (fieldLine.startsWith('description:')) {
            const marker = fieldLine.slice('description:'.length).trim();
            if (marker !== '>-' && marker !== '>') {
              errors.push(`categories.${categoryName}.description must use a ">-" or ">" block scalar, got: "${marker || '(empty)'}"`);
              i++;
              continue;
            }
            const descIndent = indentOf(lines[i]);
            i++;
            const parts = [];
            while (i < lines.length && indentOf(lines[i]) > descIndent) {
              parts.push(lines[i].trim());
              i++;
            }
            description = parts.join(' ').trim();
          } else {
            errors.push(`Unrecognized field under categories.${categoryName}: "${fieldLine}" at line ${i + 1}`);
            i++;
          }
        }

        if (!description) {
          errors.push(`categories.${categoryName} has no non-empty description`);
        } else {
          categories[categoryName] = { description };
        }
      }
      continue;
    }

    errors.push(`Unrecognized top-level line ${i + 1}: "${trimmed}"`);
    i++;
  }

  if (!sensitivityLevels.length) errors.push('sensitivity_levels must be a non-empty list');
  if (!Object.keys(categories).length) errors.push('categories must define at least one category');

  if (errors.length) {
    throw Object.assign(new Error(`Invalid semantic DLP policy (${sourceLabel}):\n  - ${errors.join('\n  - ')}`), { details: errors });
  }

  return { sensitivityLevels, categories };
}

/**
 * @param {object} [opts]
 * @param {string} [opts.policyPath] - defaults to config/semantic-dlp-policy.yaml
 *   relative to the repo root.
 */
function createSemanticPolicyStore({ policyPath = path.join(__dirname, '..', 'config', 'semantic-dlp-policy.yaml') } = {}) {
  let cached = null;
  let version = null;

  // Loaded once and cached, unlike keyPhraseStore's live mtime-based reload - there
  // is no UI for editing this file in Milestone 1 (unlike the Key Phrase dictionary),
  // so "restart to pick up a policy change" is an acceptable, honest limitation
  // rather than speculative infrastructure for an editor that doesn't exist yet.
  function getPolicy() {
    if (cached) return cached;
    const raw = fs.readFileSync(policyPath, 'utf8');
    cached = parsePolicyYaml(raw, policyPath);
    // Short content hash, not a manually-maintained version number - it changes
    // automatically whenever the policy file's actual content changes, which is
    // exactly what a "policy_version" log field is for (spotting that a scan ran
    // under a different policy than another one did).
    version = require('crypto').createHash('sha256').update(raw).digest('hex').slice(0, 12);
    return cached;
  }

  function getCategoryNames() {
    return Object.keys(getPolicy().categories);
  }

  function getSensitivityLevels() {
    return getPolicy().sensitivityLevels.slice();
  }

  function getVersion() {
    getPolicy();
    return version;
  }

  return { getPolicy, getCategoryNames, getSensitivityLevels, getVersion };
}

module.exports = { createSemanticPolicyStore, parsePolicyYaml };
