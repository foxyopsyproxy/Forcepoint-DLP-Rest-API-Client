const fs = require('fs');
const path = require('path');
const config = require('./config');

const resolvedLogPath = path.resolve(config.logFilePath);
const logDir = path.dirname(resolvedLogPath);
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

function logScanEvent(entry) {
  const line = JSON.stringify({ timestamp: new Date().toISOString(), ...entry }) + '\n';
  fs.appendFile(resolvedLogPath, line, (err) => {
    if (err) {
      console.error('Failed to write log entry:', err.message);
    }
  });
}

module.exports = { logScanEvent };
