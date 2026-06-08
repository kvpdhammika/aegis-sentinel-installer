import fs from 'fs';
import path from 'path';
import axios from 'axios';

const LOCAL_BLOCKLIST_PATH = path.resolve('hosts_blocklist.txt');
const SYSTEM_HOSTS_PATH = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
const URLHAUS_HOSTS_URL = 'https://urlhaus.abuse.ch/downloads/hostfile/';

let hostsMetadata = {
  domainCount: 0,
  lastUpdated: null,
  appliedToSystem: false
};

const STATS_PATH = path.resolve('hosts_metadata.json');

// Load metadata from disk
if (fs.existsSync(STATS_PATH)) {
  try {
    hostsMetadata = JSON.parse(fs.readFileSync(STATS_PATH, 'utf8'));
  } catch (e) {
    // Ignore
  }
}

/**
 * Fetch the latest blocklist from URLhaus
 * @param {Function} logCallback 
 */
export async function downloadHostsBlocklist(logCallback = () => {}) {
  logCallback('Downloading malicious hosts feed from URLhaus...', 'info');
  
  try {
    const response = await axios.get(URLHAUS_HOSTS_URL, {
      timeout: 30000
    });

    if (response.status !== 200 || !response.data) {
      throw new Error(`Invalid URLhaus response code: ${response.status}`);
    }

    logCallback('Successfully downloaded hosts blocklist. Parsing...', 'info');
    
    const lines = response.data.split(/\r?\n/);
    let domainCount = 0;
    
    // Validate domain counts (lines that don't start with '#' and map to 127.0.0.1)
    for (const line of lines) {
      if (line.trim() && !line.startsWith('#') && line.includes('127.0.0.1')) {
        domainCount++;
      }
    }

    fs.writeFileSync(LOCAL_BLOCKLIST_PATH, response.data, 'utf8');
    
    hostsMetadata.domainCount = domainCount;
    hostsMetadata.lastUpdated = new Date().toISOString();
    hostsMetadata.appliedToSystem = checkSystemHostsApplied();
    
    fs.writeFileSync(STATS_PATH, JSON.stringify(hostsMetadata, null, 2), 'utf8');

    logCallback(`Hosts blocklist saved locally. Found ${domainCount} active malicious domains.`, 'success');
    return hostsMetadata;

  } catch (err) {
    logCallback(`Failed to update hosts blocklist: ${err.message}`, 'error');
    console.error('[Hosts Sentry] Error downloading blocklist:', err);
    throw err;
  }
}

/**
 * Checks if the system hosts file already contains the Aegis Sentinel block
 */
function checkSystemHostsApplied() {
  try {
    if (fs.existsSync(SYSTEM_HOSTS_PATH)) {
      const content = fs.readFileSync(SYSTEM_HOSTS_PATH, 'utf8');
      return content.includes('# === AEGIS SENTINEL BLOCKLIST START ===');
    }
  } catch (err) {
    // Ignore
  }
  return false;
}

/**
 * Apply the downloaded hosts blocklist directly to the Windows hosts file.
 * Requires administrator privileges.
 */
export function applyHostsToSystem() {
  try {
    if (!fs.existsSync(LOCAL_BLOCKLIST_PATH)) {
      throw new Error('Local blocklist file not found. Please sync the blocklist first.');
    }

    const blocklistContent = fs.readFileSync(LOCAL_BLOCKLIST_PATH, 'utf8');
    
    // Filter out comments from downloaded hosts file to keep system hosts clean
    const blocklistLines = blocklistContent.split(/\r?\n/)
      .filter(line => line.trim() && !line.startsWith('#') && line.includes('127.0.0.1'));
    
    const blockString = [
      '\n# === AEGIS SENTINEL BLOCKLIST START ===',
      `# Added on: ${new Date().toLocaleString()}`,
      `# Count: ${blocklistLines.length} blocked malware distribution sites`,
      blocklistLines.join('\n'),
      '# === AEGIS SENTINEL BLOCKLIST END ===\n'
    ].join('\n');

    let systemHostsContent = '';
    if (fs.existsSync(SYSTEM_HOSTS_PATH)) {
      systemHostsContent = fs.readFileSync(SYSTEM_HOSTS_PATH, 'utf8');
    }

    // Remove old block if exists
    const regex = /# === AEGIS SENTINEL BLOCKLIST START ===[\s\S]*?# === AEGIS SENTINEL BLOCKLIST END ===/g;
    systemHostsContent = systemHostsContent.replace(regex, '').trim() + '\n';

    // Append new block
    fs.writeFileSync(SYSTEM_HOSTS_PATH, systemHostsContent + blockString, 'utf8');
    
    hostsMetadata.appliedToSystem = true;
    fs.writeFileSync(STATS_PATH, JSON.stringify(hostsMetadata, null, 2), 'utf8');
    
    console.log('[Hosts Sentry] Successfully applied URLhaus sinkhole to system hosts file.');
    return { success: true, count: blocklistLines.length };

  } catch (err) {
    console.error('[Hosts Sentry] Failed to write hosts file:', err.message);
    
    if (err.code === 'EACCES' || err.code === 'EPERM') {
      throw new Error('Permission Denied. Please restart the Aegis Sentinel server as an Administrator.');
    }
    throw err;
  }
}

/**
 * Remove the hosts blocklist from the system hosts file.
 */
export function removeHostsFromSystem() {
  try {
    if (!fs.existsSync(SYSTEM_HOSTS_PATH)) {
      return { success: true };
    }

    let systemHostsContent = fs.readFileSync(SYSTEM_HOSTS_PATH, 'utf8');
    const regex = /# === AEGIS SENTINEL BLOCKLIST START ===[\s\S]*?# === AEGIS SENTINEL BLOCKLIST END ===/g;
    systemHostsContent = systemHostsContent.replace(regex, '').trim() + '\n';

    fs.writeFileSync(SYSTEM_HOSTS_PATH, systemHostsContent, 'utf8');
    
    hostsMetadata.appliedToSystem = false;
    fs.writeFileSync(STATS_PATH, JSON.stringify(hostsMetadata, null, 2), 'utf8');
    
    console.log('[Hosts Sentry] Removed URLhaus sinkhole from hosts file.');
    return { success: true };

  } catch (err) {
    console.error('[Hosts Sentry] Failed to restore hosts file:', err.message);
    if (err.code === 'EACCES' || err.code === 'EPERM') {
      throw new Error('Permission Denied. Please run the server as Administrator.');
    }
    throw err;
  }
}

/**
 * Get current hosts status metadata
 */
export function getHostsStatus() {
  hostsMetadata.appliedToSystem = checkSystemHostsApplied();
  return {
    ...hostsMetadata,
    localExists: fs.existsSync(LOCAL_BLOCKLIST_PATH)
  };
}
