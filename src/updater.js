import axios from 'axios';
import { addSignatures } from './db.js';

const MALWAREBAZAAR_RECENT_FEED = 'https://bazaar.abuse.ch/export/txt/sha256/recent/';

let updateInProgress = false;
let lastUpdateStatus = {
  success: null,
  timestamp: null,
  message: 'Never updated',
  addedCount: 0
};

/**
 * Fetch and parse the latest malware signatures from MalwareBazaar
 * @param {Function} logCallback - Optional function to pipe progress messages (message, level)
 */
export async function updateDatabase(config = {}, logCallback = () => {}) {
  if (updateInProgress) {
    logCallback('Update already in progress. Skipping.', 'warning');
    return lastUpdateStatus;
  }

  updateInProgress = true;
  lastUpdateStatus.message = 'Downloading threat signature feed...';
  logCallback('Initiating database signature update...', 'info');
  logCallback(`Downloading signature feed from: ${MALWAREBAZAAR_RECENT_FEED}`, 'info');

  const combinedHashes = [];

  try {
    // 1. Fetch MalwareBazaar Recent Feed
    const mbResponse = await axios.get(MALWAREBAZAAR_RECENT_FEED, {
      timeout: 30000,
      headers: {
        'User-Agent': 'AegisSentinel-Antivirus/1.0.0'
      }
    });

    if (mbResponse.status === 200 && mbResponse.data) {
      logCallback('Downloaded MalwareBazaar feed. Parsing...', 'info');
      const lines = mbResponse.data.split(/\r?\n/);
      let mbCount = 0;
      
      for (let line of lines) {
        line = line.trim();
        if (!line || line.startsWith('#')) continue;
        
        const cleaned = line.replace(/['"'\s]/g, '').toLowerCase();
        if (cleaned.length === 64 && /^[0-9a-f]{64}$/.test(cleaned)) {
          combinedHashes.push(cleaned);
          mbCount++;
        }
      }
      logCallback(`Parsed ${mbCount} signatures from MalwareBazaar recent feed.`, 'info');
    } else {
      logCallback('MalwareBazaar download failed or returned empty data.', 'warning');
    }

    // 2. Fetch ThreatFox API Feed if API Key is configured
    if (config.threatFoxApiKey) {
      logCallback('ThreatFox API Key detected. Querying ThreatFox recent IOCs API...', 'info');
      try {
        const tfResponse = await axios.post('https://threatfox-api.abuse.ch/v2/', {
          query: 'get_iocs',
          days: 1
        }, {
          headers: {
            'Auth-Key': config.threatFoxApiKey,
            'Content-Type': 'application/json'
          },
          timeout: 20000
        });

        if (tfResponse.data && tfResponse.data.query_status === 'ok' && Array.isArray(tfResponse.data.data)) {
          let tfCount = 0;
          for (const item of tfResponse.data.data) {
            if (item.ioc_type === 'sha256_hash' && item.ioc) {
              const cleaned = item.ioc.trim().toLowerCase();
              if (cleaned.length === 64 && /^[0-9a-f]{64}$/.test(cleaned)) {
                combinedHashes.push(cleaned);
                tfCount++;
              }
            }
          }
          logCallback(`Parsed ${tfCount} signatures from ThreatFox recent API.`, 'info');
        } else {
          const status = tfResponse.data ? tfResponse.data.query_status : 'unknown';
          logCallback(`ThreatFox API returned query status: ${status}`, 'warning');
        }
      } catch (tfErr) {
        logCallback(`ThreatFox sync failed: ${tfErr.message}. Continuing with other feeds.`, 'warning');
        console.error('[Updater] ThreatFox API error:', tfErr);
      }
    } else {
      logCallback('ThreatFox API key not configured. Skipping ThreatFox sync.', 'info');
    }

    // 3. Save combined hashes to local signature database
    logCallback(`Saving combined signatures to database...`, 'info');

    if (combinedHashes.length > 0) {
      const dbBefore = getDatabaseSize();
      const success = addSignatures(combinedHashes);
      if (success) {
        const dbAfter = getDatabaseSize();
        const added = dbAfter - dbBefore;
        
        lastUpdateStatus = {
          success: true,
          timestamp: new Date().toISOString(),
          message: `Database updated successfully. Added ${added} new signatures. Total: ${dbAfter}.`,
          addedCount: added
        };
        logCallback(lastUpdateStatus.message, 'success');
      } else {
        throw new Error('Failed to write signatures to local database file');
      }
    } else {
      lastUpdateStatus = {
        success: true,
        timestamp: new Date().toISOString(),
        message: 'Database is up to date (no new signatures found in feeds).',
        addedCount: 0
      };
      logCallback(lastUpdateStatus.message, 'info');
    }

  } catch (err) {
    const errorMsg = err.message || err;
    lastUpdateStatus = {
      success: false,
      timestamp: new Date().toISOString(),
      message: `Update failed: ${errorMsg}`,
      addedCount: 0
    };
    logCallback(`Database update failed: ${errorMsg}`, 'error');
    console.error('[Updater] Error during signature database update:', err);
  } finally {
    updateInProgress = false;
  }

  return lastUpdateStatus;
}

/**
 * Get internal database count by importing db stats
 */
import { getStats } from './db.js';
function getDatabaseSize() {
  return getStats().count;
}

/**
 * Get the current updater status
 */
export function getUpdaterStatus() {
  return {
    inProgress: updateInProgress,
    ...lastUpdateStatus
  };
}
