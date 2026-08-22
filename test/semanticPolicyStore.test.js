const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createSemanticPolicyStore, parsePolicyYaml } = require('../src/semanticPolicyStore');

const VALID_YAML = `
sensitivity_levels:
  - PUBLIC
  - RESTRICTED

categories:
  ONE_THING:
    description: >-
      A description that wraps
      over two lines.
  ANOTHER_THING:
    description: >-
      A single line description.
`;

function tempPolicyFile(content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'semantic-policy-test-'));
  const file = path.join(dir, 'policy.yaml');
  fs.writeFileSync(file, content);
  return file;
}

test('parses the real config/semantic-dlp-policy.yaml shipped with this project', () => {
  const store = createSemanticPolicyStore();
  const policy = store.getPolicy();
  assert.ok(policy.sensitivityLevels.includes('PUBLIC'));
  assert.ok(policy.sensitivityLevels.includes('RESTRICTED'));
  assert.ok(policy.sensitivityLevels.includes('UNCERTAIN'));
  assert.ok(Object.keys(policy.categories).length >= 10);
  assert.ok(policy.categories.CREDENTIALS_AND_SECRETS.description.length > 0);
  assert.match(store.getVersion(), /^[0-9a-f]{12}$/);
});

test('a valid minimal policy parses correctly, with folded block scalars joined by spaces', () => {
  const parsed = parsePolicyYaml(VALID_YAML);
  assert.deepEqual(parsed.sensitivityLevels, ['PUBLIC', 'RESTRICTED']);
  assert.equal(parsed.categories.ONE_THING.description, 'A description that wraps over two lines.');
  assert.equal(parsed.categories.ANOTHER_THING.description, 'A single line description.');
});

test('createSemanticPolicyStore reads from a given path and caches the result', () => {
  const file = tempPolicyFile(VALID_YAML);
  const store = createSemanticPolicyStore({ policyPath: file });
  assert.deepEqual(store.getCategoryNames(), ['ONE_THING', 'ANOTHER_THING']);
  assert.deepEqual(store.getSensitivityLevels(), ['PUBLIC', 'RESTRICTED']);
});

test('an empty sensitivity_levels list is rejected', () => {
  const bad = `
sensitivity_levels:
categories:
  X:
    description: >-
      Something.
`;
  assert.throws(() => parsePolicyYaml(bad), /sensitivity_levels must be a non-empty list/);
});

test('a category with no description is rejected', () => {
  const bad = `
sensitivity_levels:
  - PUBLIC
categories:
  X:
    notdescription: foo
`;
  assert.throws(() => parsePolicyYaml(bad), (err) => {
    assert.ok(Array.isArray(err.details));
    assert.ok(err.details.some((d) => d.includes('X')));
    return true;
  });
});

test('a description missing the ">-" block scalar marker is rejected', () => {
  const bad = `
sensitivity_levels:
  - PUBLIC
categories:
  X:
    description: not a block scalar
`;
  assert.throws(() => parsePolicyYaml(bad), /block scalar/);
});

test('an unrecognized top-level key is rejected', () => {
  const bad = `
sensitivity_levels:
  - PUBLIC
categories:
  X:
    description: >-
      Something.
made_up_section:
  - whatever
`;
  assert.throws(() => parsePolicyYaml(bad), /Unrecognized top-level line/);
});
