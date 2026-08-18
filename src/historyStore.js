const fs = require('fs');
const path = require('path');
const config = require('./config');

const resolvedLogPath = path.resolve(config.logFilePath);

function readAllEntries() {
  if (!fs.existsSync(resolvedLogPath)) return [];
  const raw = fs.readFileSync(resolvedLogPath, 'utf8');
  const entries = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      entries.push(JSON.parse(trimmed));
    } catch (err) {
      // Skip malformed lines rather than failing the whole read.
    }
  }
  return entries;
}

function isBlockingAction(actions) {
  return Array.isArray(actions) && actions.some((a) => /block|quarantine|drop/i.test(a || ''));
}

function median(values) {
  if (!values.length) return 0;
  const sorted = values.slice().sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? Math.round((sorted[mid - 1] + sorted[mid]) / 2) : sorted[mid];
}

function computeStats(entries) {
  const startOfToday = new Date();
  startOfToday.setHours(0, 0, 0, 0);
  const todays = entries.filter((e) => e.timestamp && new Date(e.timestamp) >= startOfToday);

  return {
    scansToday: todays.length,
    blockedToday: todays.filter((e) => isBlockingAction(e.actions)).length,
    medianElapsedMsToday: median(todays.filter((e) => typeof e.elapsedMs === 'number').map((e) => e.elapsedMs)),
    timeoutsToday: todays.filter((e) => e.errorCode === 'TIMEOUT').length,
  };
}

/**
 * @param {number} limit - max entries to return, most recent first
 * @returns {{entries: object[], stats: {scansToday: number, blockedToday: number, medianElapsedMsToday: number, timeoutsToday: number}}}
 */
function getHistory(limit = 50) {
  const entries = readAllEntries();
  const sorted = entries.slice().sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  return {
    entries: sorted.slice(0, limit),
    stats: computeStats(entries),
  };
}

/**
 * @param {string} id - globalMessageId to look up
 * @returns {object|null}
 */
function getHistoryEntry(id) {
  const entries = readAllEntries();
  return entries.find((e) => e.globalMessageId === id) || null;
}

module.exports = { getHistory, getHistoryEntry };
