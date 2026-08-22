const { test, mock } = require('node:test');
const assert = require('node:assert/strict');
const { createSanitizationService, RESULT_STATUS, BLOCK_REASONS } = require('../src/sanitizationService');
const { buildConfig } = require('../src/keyPhraseConfig');

// Mirrors src/protectorClient.js's real isConnectionClassError/isTlsError closely
// enough for these tests: same error-code sets, same behaviour, no network/config
// dependency. sanitizationService only ever calls these two as pure classifiers.
const CONNECTION_CODES = new Set(['ECONNREFUSED', 'ETIMEDOUT', 'ECONNRESET']);
const TLS_CODES = new Set(['SELF_SIGNED_CERT_IN_CHAIN']);

function fakeProtectorClient(inspectFileImpl) {
  return {
    inspectFile: mock.fn(inspectFileImpl),
    isConnectionClassError: (err) => CONNECTION_CODES.has(err.code),
    isTlsError: (err) => TLS_CODES.has(err.code),
  };
}

function forcepointResponse({ resolution, violations = [], httpStatus = 200 }) {
  return { httpStatus, body: { resolution, violations, max_number_of_matches: 0 }, elapsedMs: 5 };
}

function violation(policyName, rules) {
  return {
    policy_name: policyName,
    policy_id: 'p1',
    violated_rules: rules.map((r) => ({ rule_id: 'r1', rule_name: r.name, rule_number_of_matches: r.matches })),
  };
}

const SINGLE_RULE_CONFIG = buildConfig(
  {
    phrase_sets: {
      sensitive_projects: [
        { id: 'project_alpha', value: 'PROJECT ALPHA' },
        { id: 'blue_fox', value: 'BLUE FOX' },
      ],
    },
    rules: {
      'Project Names': { phrase_set: 'sensitive_projects', replacement: '[REDACTED]', case_sensitive: false },
    },
  },
  'test'
);

function silentLogger() {
  const lines = [];
  return { logger: { log: (msg) => lines.push(msg) }, lines };
}

// =====================================================================
// CLEAN
// =====================================================================

test('CLEAN: an UNMATCHED first inspection returns the original content unchanged, with 0 redactions', async () => {
  const protectorClient = fakeProtectorClient(async () => forcepointResponse({ resolution: 'UNMATCHED' }));
  const { logger, lines } = silentLogger();
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG, logger });

  const result = await service.sanitize('Nothing sensitive here.');

  assert.deepEqual(result, { status: RESULT_STATUS.CLEAN, content: 'Nothing sensitive here.', redactions: 0 });
  assert.equal(protectorClient.inspectFile.mock.callCount(), 1, 'must not call Forcepoint a second time when already clean');
  assert.ok(lines.length >= 1);
});

test('empty string content is CLEAN without ever calling Forcepoint', async () => {
  const protectorClient = fakeProtectorClient(async () => forcepointResponse({ resolution: 'UNMATCHED' }));
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG });

  const result = await service.sanitize('');

  assert.deepEqual(result, { status: RESULT_STATUS.CLEAN, content: '', redactions: 0 });
  assert.equal(protectorClient.inspectFile.mock.callCount(), 0);
});

test('non-string content is BLOCKED (INVALID_INPUT) without calling Forcepoint', async () => {
  const protectorClient = fakeProtectorClient(async () => forcepointResponse({ resolution: 'UNMATCHED' }));
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG });

  const result = await service.sanitize(null);

  assert.deepEqual(result, { status: RESULT_STATUS.BLOCKED, reason: BLOCK_REASONS.INVALID_INPUT });
  assert.equal(protectorClient.inspectFile.mock.callCount(), 0);
});

test('BLOCKED (FEATURE_NOT_CONFIGURED) when the Key Phrase feature is disabled', async () => {
  const protectorClient = fakeProtectorClient(async () => forcepointResponse({ resolution: 'MATCHED' }));
  const disabled = { isEnabled: () => false, getRuleMapping: () => undefined };
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: disabled });

  const result = await service.sanitize('some content');

  assert.deepEqual(result, { status: RESULT_STATUS.BLOCKED, reason: BLOCK_REASONS.FEATURE_NOT_CONFIGURED });
  assert.equal(protectorClient.inspectFile.mock.callCount(), 0);
});

// =====================================================================
// SANITIZED
// =====================================================================

test('SANITIZED: MATCHED -> redact -> second inspection UNMATCHED -> sanitized content returned', async () => {
  let call = 0;
  const protectorClient = fakeProtectorClient(async () => {
    call += 1;
    if (call === 1) {
      return forcepointResponse({
        resolution: 'MATCHED',
        violations: [violation('Sensitive Projects', [{ name: 'Project Names', matches: 2 }])],
      });
    }
    return forcepointResponse({ resolution: 'UNMATCHED' });
  });
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG });

  const result = await service.sanitize('PROJECT ALPHA is working together with BLUE FOX.');

  assert.deepEqual(result, {
    status: RESULT_STATUS.SANITIZED,
    content: '[REDACTED] is working together with [REDACTED].',
    redactions: 2,
    // What Forcepoint's first inspection found, before redaction - lets the caller
    // record this as a real (flagged) history entry. Names/severity only, never content.
    violations: [{
      policyId: 'p1',
      policyName: 'Sensitive Projects',
      rules: [{ ruleId: 'r1', ruleName: 'Project Names', severity: undefined, matches: 2 }],
    }],
    maxNumberOfMatches: 0,
  });
  assert.equal(protectorClient.inspectFile.mock.callCount(), 2);
  // The second call must inspect the REDACTED text, not the original.
  const secondCallArgs = protectorClient.inspectFile.mock.calls[1].arguments;
  assert.equal(secondCallArgs[0].toString('utf8'), '[REDACTED] is working together with [REDACTED].');
});

test('SANITIZED: a pattern-based (regex + validator) rule is redacted through the real merge step, not just a literal value', async () => {
  // Regression test for a real bug: sanitize()'s merge step originally only ever
  // copied a phrase's `value` field, so a pattern-based phrase (no `value` at all)
  // silently ended up with neither `value` nor `pattern` set and KeyPhraseRedactor
  // never matched it - Forcepoint would inspect the UNREDACTED text on the "second"
  // call and this would incorrectly end up BLOCKED (ZERO_REDACTIONS) instead of
  // SANITIZED. This exercises the full path end to end, not just KeyPhraseRedactor
  // in isolation, so a regression here would be caught even if the merge step broke
  // again in some other way.
  const cfg = buildConfig(
    {
      phrase_sets: { ids: [{ id: 'israeli_id', pattern: '\\b\\d{9}\\b', validator: 'israeliId' }] },
      rules: { 'Israel PII: Identity Number (Wide)': { phrase_set: 'ids', replacement: '[ID-REDACTED]' } },
    },
    'test'
  );
  let call = 0;
  const protectorClient = fakeProtectorClient(async () => {
    call += 1;
    if (call === 1) {
      // '123456782' is a real checksum-valid Israeli id (see keyPhraseValidators.test.js).
      return forcepointResponse({
        resolution: 'MATCHED',
        violations: [violation('Israel PII', [{ name: 'Israel PII: Identity Number (Wide)', matches: 1 }])],
      });
    }
    return forcepointResponse({ resolution: 'UNMATCHED' });
  });
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: cfg });

  const result = await service.sanitize('Identity number 123456782 belongs to a test subject.');
  assert.equal(result.status, RESULT_STATUS.SANITIZED);
  assert.equal(result.content, 'Identity number [ID-REDACTED] belongs to a test subject.');
  assert.equal(result.redactions, 1);
});

test('multiple Forcepoint rules across multiple phrase sets are all resolved and redacted', async () => {
  const cfg = buildConfig(
    {
      phrase_sets: {
        projects: [{ id: 'alpha', value: 'PROJECT ALPHA' }],
        codenames: [{ id: 'fox', value: 'BLUE FOX' }],
      },
      rules: {
        'Rule A': { phrase_set: 'projects', replacement: '[REDACTED]' },
        'Rule B': { phrase_set: 'codenames', replacement: '[REDACTED]' },
      },
    },
    'test'
  );
  let call = 0;
  const protectorClient = fakeProtectorClient(async () => {
    call += 1;
    if (call === 1) {
      return forcepointResponse({
        resolution: 'MATCHED',
        violations: [violation('Policy X', [{ name: 'Rule A', matches: 1 }, { name: 'Rule B', matches: 1 }])],
      });
    }
    return forcepointResponse({ resolution: 'UNMATCHED' });
  });
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: cfg });

  const result = await service.sanitize('PROJECT ALPHA and BLUE FOX are both classified.');

  assert.equal(result.status, RESULT_STATUS.SANITIZED);
  assert.equal(result.content, '[REDACTED] and [REDACTED] are both classified.');
  assert.equal(result.redactions, 2);
});

test('overlapping phrase sets are deduped - a shared phrase id is only redacted once', async () => {
  // Both rules point at the SAME phrase set, so the exact same phrase entries are
  // encountered twice while merging - the redaction pass itself must still only run
  // once per phrase, not once per rule that references it.
  const cfg = buildConfig(
    {
      phrase_sets: { shared: [{ id: 'alpha', value: 'PROJECT ALPHA' }] },
      rules: {
        'Rule A': { phrase_set: 'shared', replacement: '[REDACTED]' },
        'Rule B': { phrase_set: 'shared', replacement: '[REDACTED]' },
      },
    },
    'test'
  );
  let call = 0;
  const protectorClient = fakeProtectorClient(async () => {
    call += 1;
    if (call === 1) {
      return forcepointResponse({
        resolution: 'MATCHED',
        violations: [violation('Policy X', [{ name: 'Rule A', matches: 1 }, { name: 'Rule B', matches: 1 }])],
      });
    }
    return forcepointResponse({ resolution: 'UNMATCHED' });
  });
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: cfg });

  const result = await service.sanitize('PROJECT ALPHA is mentioned once.');

  assert.equal(result.redactions, 1, 'one physical occurrence must count as one redaction, not two');
});

// =====================================================================
// BLOCKED
// =====================================================================

test('BLOCKED (POST_REDACTION_DLP_MATCH): second inspection still MATCHED - content is never returned', async () => {
  let call = 0;
  const protectorClient = fakeProtectorClient(async () => {
    call += 1;
    return forcepointResponse({
      resolution: 'MATCHED',
      violations: [violation('Sensitive Projects', [{ name: 'Project Names', matches: 1 }])],
    });
  });
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG });

  const result = await service.sanitize('PROJECT ALPHA leaks elsewhere in ways redaction cannot fix.');

  assert.deepEqual(result, {
    status: RESULT_STATUS.BLOCKED,
    reason: BLOCK_REASONS.POST_REDACTION_DLP_MATCH,
    // What the SECOND (post-redaction) inspection still found - the operative
    // reason for this block, which can legitimately differ from the first
    // inspection's matches (redaction may have cleared some rules but not all).
    violations: [{
      policyId: 'p1',
      policyName: 'Sensitive Projects',
      rules: [{ ruleId: 'r1', ruleName: 'Project Names', severity: undefined, matches: 1 }],
    }],
    maxNumberOfMatches: 0,
  });
  assert.equal(Object.prototype.hasOwnProperty.call(result, 'content'), false);
  assert.equal(protectorClient.inspectFile.mock.callCount(), 2);
});

test('BLOCKED (UNMAPPED_RULE): a matched Forcepoint rule has no local Key Phrase mapping', async () => {
  const protectorClient = fakeProtectorClient(async () =>
    forcepointResponse({
      resolution: 'MATCHED',
      violations: [violation('Some Policy', [{ name: 'Totally Unmapped Rule', matches: 1 }])],
    })
  );
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG });

  const result = await service.sanitize('content');

  assert.deepEqual(result, {
    status: RESULT_STATUS.BLOCKED,
    reason: BLOCK_REASONS.UNMAPPED_RULE,
    violations: [{
      policyId: 'p1',
      policyName: 'Some Policy',
      rules: [{ ruleId: 'r1', ruleName: 'Totally Unmapped Rule', severity: undefined, matches: 1 }],
    }],
    maxNumberOfMatches: 0,
  });
  assert.equal(protectorClient.inspectFile.mock.callCount(), 1, 'must not proceed to a second inspection');
});

test('BLOCKED (NO_IDENTIFIABLE_RULES): MATCHED with the documented violations:[null] fallback shape', async () => {
  const protectorClient = fakeProtectorClient(async () => ({
    httpStatus: 200,
    body: { resolution: 'MATCHED', violations: [null], max_number_of_matches: 0 },
    elapsedMs: 5,
  }));
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG });

  const result = await service.sanitize('content');

  assert.deepEqual(result, { status: RESULT_STATUS.BLOCKED, reason: BLOCK_REASONS.NO_IDENTIFIABLE_RULES });
});

test('BLOCKED (ZERO_REDACTIONS): MATCHED and mapped, but the phrase never actually occurs in the content', async () => {
  const protectorClient = fakeProtectorClient(async () =>
    forcepointResponse({
      resolution: 'MATCHED',
      violations: [violation('Sensitive Projects', [{ name: 'Project Names', matches: 1 }])],
    })
  );
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG });

  // Forcepoint says MATCHED, but none of "Project Names"'s configured phrases
  // ("PROJECT ALPHA", "BLUE FOX") actually appear here - config and Forcepoint policy
  // have drifted apart.
  const result = await service.sanitize('This mentions neither of the configured phrases.');

  assert.deepEqual(result, {
    status: RESULT_STATUS.BLOCKED,
    reason: BLOCK_REASONS.ZERO_REDACTIONS,
    violations: [{
      policyId: 'p1',
      policyName: 'Sensitive Projects',
      rules: [{ ruleId: 'r1', ruleName: 'Project Names', severity: undefined, matches: 1 }],
    }],
    maxNumberOfMatches: 0,
  });
  assert.equal(protectorClient.inspectFile.mock.callCount(), 1, 'must not proceed to a second inspection with nothing changed');
});

test('BLOCKED (INVALID_RESPONSE): resolution is missing/unexpected', async () => {
  const protectorClient = fakeProtectorClient(async () => ({ httpStatus: 200, body: { resolution: 'SOMETHING_ELSE' }, elapsedMs: 5 }));
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG });

  const result = await service.sanitize('content');

  assert.deepEqual(result, { status: RESULT_STATUS.BLOCKED, reason: BLOCK_REASONS.INVALID_RESPONSE });
});

test('BLOCKED (INSPECTION_FAILED): first Forcepoint request fails outright (non-retryable) - no retry attempted', async () => {
  const protectorClient = fakeProtectorClient(async () => {
    throw Object.assign(new Error('unknown protector'), { code: 'UNKNOWN_PROTECTOR' });
  });
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG });

  const result = await service.sanitize('content');

  assert.deepEqual(result, { status: RESULT_STATUS.BLOCKED, reason: BLOCK_REASONS.INSPECTION_FAILED });
  assert.equal(protectorClient.inspectFile.mock.callCount(), 1, 'a non-transient error must not be retried');
});

test('a transient failure on the first attempt is retried once and can still succeed', async () => {
  let call = 0;
  const protectorClient = fakeProtectorClient(async () => {
    call += 1;
    if (call === 1) throw Object.assign(new Error('connection refused'), { code: 'ECONNREFUSED' });
    return forcepointResponse({ resolution: 'UNMATCHED' });
  });
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG });

  const result = await service.sanitize('content');

  assert.deepEqual(result, { status: RESULT_STATUS.CLEAN, content: 'content', redactions: 0 });
  assert.equal(protectorClient.inspectFile.mock.callCount(), 2);
});

test('Forcepoint timeout on the first inspection: retried once, then BLOCKED if still failing', async () => {
  const protectorClient = fakeProtectorClient(async () => {
    throw Object.assign(new Error('timed out'), { code: 'TIMEOUT' });
  });
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG });

  const result = await service.sanitize('content');

  assert.deepEqual(result, { status: RESULT_STATUS.BLOCKED, reason: BLOCK_REASONS.INSPECTION_FAILED });
  assert.equal(protectorClient.inspectFile.mock.callCount(), 2, 'exactly one retry - no more');
});

test('BLOCKED (INSPECTION_FAILED): first request fails permanently after using its one retry', async () => {
  const protectorClient = fakeProtectorClient(async () => {
    throw Object.assign(new Error('connection refused'), { code: 'ECONNREFUSED' });
  });
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG });

  const result = await service.sanitize('content');

  assert.deepEqual(result, { status: RESULT_STATUS.BLOCKED, reason: BLOCK_REASONS.INSPECTION_FAILED });
  assert.equal(protectorClient.inspectFile.mock.callCount(), 2);
});

test('BLOCKED (INSPECTION_FAILED): the SECOND (post-redaction) request fails - content is never returned', async () => {
  let call = 0;
  const protectorClient = fakeProtectorClient(async () => {
    call += 1;
    if (call === 1) {
      return forcepointResponse({
        resolution: 'MATCHED',
        violations: [violation('Sensitive Projects', [{ name: 'Project Names', matches: 1 }])],
      });
    }
    throw Object.assign(new Error('connection reset'), { code: 'ECONNRESET' });
  });
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG });

  const result = await service.sanitize('PROJECT ALPHA is mentioned here.');

  assert.deepEqual(result, { status: RESULT_STATUS.BLOCKED, reason: BLOCK_REASONS.INSPECTION_FAILED });
  assert.equal(Object.prototype.hasOwnProperty.call(result, 'content'), false);
  // 1 (first) + up to 2 (second, with its own retry) = 3
  assert.equal(protectorClient.inspectFile.mock.callCount(), 3);
});

test('BLOCKED when Forcepoint returns a non-2xx HTTP status even with a parsed body', async () => {
  const protectorClient = fakeProtectorClient(async () => forcepointResponse({ resolution: 'MATCHED', httpStatus: 500 }));
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG });

  const result = await service.sanitize('content');

  assert.deepEqual(result, { status: RESULT_STATUS.BLOCKED, reason: BLOCK_REASONS.INSPECTION_FAILED });
});

// =====================================================================
// Logging must never contain sensitive content or phrase values
// =====================================================================

test('structured logs never contain the original content, sanitized content, or a phrase VALUE', async () => {
  let call = 0;
  const protectorClient = fakeProtectorClient(async () => {
    call += 1;
    if (call === 1) {
      return forcepointResponse({
        resolution: 'MATCHED',
        violations: [violation('Sensitive Projects', [{ name: 'Project Names', matches: 2 }])],
      });
    }
    return forcepointResponse({ resolution: 'UNMATCHED' });
  });
  const { logger, lines } = silentLogger();
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG, logger });

  const secretContent = 'PROJECT ALPHA is working together with BLUE FOX.';
  await service.sanitize(secretContent);

  assert.ok(lines.length > 0);
  for (const line of lines) {
    assert.doesNotMatch(line, /PROJECT ALPHA/, 'phrase value must never be logged');
    assert.doesNotMatch(line, /BLUE FOX/, 'phrase value must never be logged');
    assert.doesNotMatch(line, /working together/, 'original content must never be logged');
    // Phrase IDs are explicitly allowed - confirm the log is still USEFUL, not just safe.
    assert.match(lines.join(' '), /project_alpha|blue_fox/, 'phrase ids are fine to log and expected here');
  }
});

test('structured logs never contain content even on a BLOCKED outcome', async () => {
  const protectorClient = fakeProtectorClient(async () =>
    forcepointResponse({
      resolution: 'MATCHED',
      violations: [violation('Sensitive Projects', [{ name: 'Project Names', matches: 1 }])],
    })
  );
  const { logger, lines } = silentLogger();
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG, logger });

  await service.sanitize('PROJECT ALPHA must never appear in a log line.');

  for (const line of lines) {
    assert.doesNotMatch(line, /PROJECT ALPHA/);
    assert.doesNotMatch(line, /must never appear/);
  }
});

test('the same correlation id is used for both Forcepoint calls and appears in the log', async () => {
  let capturedIds = [];
  const protectorClient = fakeProtectorClient(async (buffer, name, clientIp, requestId) => {
    capturedIds.push(requestId);
    if (capturedIds.length === 1) {
      return forcepointResponse({
        resolution: 'MATCHED',
        violations: [violation('Sensitive Projects', [{ name: 'Project Names', matches: 1 }])],
      });
    }
    return forcepointResponse({ resolution: 'UNMATCHED' });
  });
  const { logger, lines } = silentLogger();
  const service = createSanitizationService({ protectorClient, keyPhraseConfig: SINGLE_RULE_CONFIG, logger });

  const result = await service.sanitize('PROJECT ALPHA appears once.', { correlationId: 'fixed-id-123' });

  assert.equal(result.status, RESULT_STATUS.SANITIZED);
  assert.equal(capturedIds.length, 2);
  assert.ok(capturedIds[0].startsWith('fixed-id-123'));
  assert.ok(capturedIds[1].startsWith('fixed-id-123'));
  assert.notEqual(capturedIds[0], capturedIds[1], 'each Forcepoint call still gets its own distinct id');
  const parsedLog = JSON.parse(lines[lines.length - 1]);
  assert.equal(parsedLog.correlation_id, 'fixed-id-123');
});
