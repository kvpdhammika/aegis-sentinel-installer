import fs from 'fs';
import path from 'path';

const LOG_PATH = path.resolve('forensics_log.json');

/**
 * Load all forensic logs from disk
 * @returns {Array<object>} chronological event logs (newest first)
 */
export function loadForensicsLog() {
  if (!fs.existsSync(LOG_PATH)) {
    return [];
  }
  try {
    const raw = fs.readFileSync(LOG_PATH, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    console.error('[Forensics] Failed to read logs, starting clean:', err.message);
    return [];
  }
}

/**
 * Write a new security event to the audit trail
 * @param {string} type - Event classification (e.g. Shield Watcher, Scanner, Process Sentry, USB Monitor, System)
 * @param {string} severity - Severity level (info, success, warning, error)
 * @param {string} description - Descriptive summary
 * @param {object} metadata - Optional additional variables (file paths, hashes, PIDs, etc.)
 * @returns {object} logged event
 */
export function recordEvent(type, severity, description, metadata = {}) {
  const logs = loadForensicsLog();
  const event = {
    id: `EV_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    timestamp: new Date().toISOString(),
    type,
    severity,
    description,
    metadata
  };
  
  logs.unshift(event); // Newest first

  // Enforce a maximum cap of 500 records to prevent storage leaks
  if (logs.length > 500) {
    logs.length = 500;
  }

  try {
    fs.writeFileSync(LOG_PATH, JSON.stringify(logs, null, 2), 'utf8');
    return event;
  } catch (err) {
    console.error('[Forensics] Failed to write event:', err.message);
    return event;
  }
}
