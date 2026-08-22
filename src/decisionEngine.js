// Keeps CONTENT SENSITIVITY (the AI's classification of the material itself)
// separate from TRANSMISSION RISK (the context the content is moving through) -
// see docs/semantic-dlp-architecture.md, DecisionEngine. Deliberately a plain
// decision table, not a second model call: enforcement policy belongs in
// application logic that can be read, reviewed, and changed without touching a
// prompt, not inside the LLM.
//
// SHADOW MODE ONLY: decide() returns what the decision WOULD be. Nothing in this
// module calls anything, blocks anything, or is wired into the actual scan
// response's resolution/actions. server.js only ever logs this value alongside
// the real (Forcepoint-driven) outcome - see docs/semantic-dlp-architecture.md,
// Decision Engine / Shadow Mode.

const THEORETICAL_DECISION = { BLOCK: 'BLOCK', ALLOW: 'ALLOW', UNCERTAIN: 'UNCERTAIN' };

// This application does not model a real destination/user/device pipeline today
// (it is a scan-a-file tool, not a network DLP gateway) - the one real signal
// available is the data channel a scan was made under (context.dataChannel, the
// same value already sent to Forcepoint). Everything else in transactionContext
// is accepted but optional, and its absence is never treated as risk on its own -
// only EXPLICIT signals (e.g. an external destination) raise transmission risk.
function isHighRiskTransmission(transactionContext) {
  if (!transactionContext) return false;
  const destination = (transactionContext.destination || '').toLowerCase();
  const channel = (transactionContext.channel || '').toLowerCase();
  return destination === 'external' || channel.includes('email') || channel.includes('casb');
}

function createDecisionEngine() {
  /**
   * @param {object} params
   * @param {string} [params.aiClassification] - PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED|UNCERTAIN,
   *   or undefined if no AI result was available (e.g. AI disabled/failed).
   * @param {object} [params.transactionContext] - { channel, destination, source, user, device }, all optional.
   * @returns {{theoreticalDecision: 'BLOCK'|'ALLOW'|'UNCERTAIN', reason: string}}
   */
  function decide({ aiClassification, transactionContext } = {}) {
    if (!aiClassification || aiClassification === 'UNCERTAIN') {
      return { theoreticalDecision: THEORETICAL_DECISION.UNCERTAIN, reason: 'No confident AI content-sensitivity classification is available for this scan.' };
    }

    const highRisk = isHighRiskTransmission(transactionContext);

    if (aiClassification === 'RESTRICTED') {
      return { theoreticalDecision: THEORETICAL_DECISION.BLOCK, reason: 'RESTRICTED content is blocked regardless of transmission context.' };
    }
    if (aiClassification === 'CONFIDENTIAL' && highRisk) {
      return { theoreticalDecision: THEORETICAL_DECISION.BLOCK, reason: 'CONFIDENTIAL content combined with a high-risk transmission context (e.g. external destination).' };
    }
    if (aiClassification === 'CONFIDENTIAL') {
      return { theoreticalDecision: THEORETICAL_DECISION.ALLOW, reason: 'CONFIDENTIAL content, but no high-risk transmission context was present.' };
    }
    // INTERNAL / PUBLIC
    return { theoreticalDecision: THEORETICAL_DECISION.ALLOW, reason: `${aiClassification} content does not warrant blocking.` };
  }

  return { decide };
}

module.exports = { createDecisionEngine, THEORETICAL_DECISION };
