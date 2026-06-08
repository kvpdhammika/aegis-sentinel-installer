import express from 'express';
import axios from 'axios';
import path from 'path';
import fs from 'fs';
import { loadDatabase, getStats, clearDatabase } from './src/db.js';
import { updateDatabase, getUpdaterStatus } from './src/updater.js';
import { 
  startDirectoryScan, 
  controlScan, 
  getActiveScanStatus, 
  restoreFile 
} from './src/scanner.js';
import { startWatching, stopWatching, getWatcherStatus } from './src/watcher.js';
import { loadRules, getActiveRules, parseYaraText, mergeRules } from './src/yara.js';
import { scanProcesses, killProcess } from './src/processes.js';
import { downloadHostsBlocklist, applyHostsToSystem, removeHostsFromSystem, getHostsStatus } from './src/hosts.js';
import { startUSBMonitor, stopUSBMonitor } from './src/usb.js';
import { recordEvent, loadForensicsLog } from './src/forensics.js';
import { getBackupList, restoreBackup } from './src/rollback.js';

const app = express();
const PORT = process.env.PORT || 3000;
const CONFIG_PATH = path.resolve('config.json');

app.use(express.json());
app.use(express.static('public'));

// Global configurations
let appConfig = {
  virusTotalApiKey: '',
  threatFoxApiKey: '',
  onlineLookupEnabled: true,
  virusTotalEnabled: false,
  autoQuarantine: true,
  monitoredFolder: path.resolve('monitored'),
  quarantineFolder: path.resolve('quarantine'),
  shieldActive: true,
  usbAutoScan: true
};

// SSE Client list
let sseClients = [];

/**
 * Send Server-Sent Events to all connected clients
 */
function broadcastSSE(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(client => {
    try {
      client.write(payload);
    } catch (err) {
      // Ignore
    }
  });
}

/**
 * Send a log message directly to the UI's real-time console
 */
function logToUI(message, level = 'info') {
  const timestamp = new Date().toLocaleTimeString();
  console.log(`[UI LOG] [${level.toUpperCase()}] ${message}`);
  broadcastSSE('log', { message, level, timestamp });
}

/**
 * Load application configuration
 */
function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
      appConfig = { ...appConfig, ...JSON.parse(raw) };
      console.log('[Config] Loaded config from disk.');
    } else {
      saveConfig();
      console.log('[Config] Created default config.json.');
    }

    // Ensure folders exist
    if (!fs.existsSync(appConfig.monitoredFolder)) {
      fs.mkdirSync(appConfig.monitoredFolder, { recursive: true });
    }
    if (!fs.existsSync(appConfig.quarantineFolder)) {
      fs.mkdirSync(appConfig.quarantineFolder, { recursive: true });
    }
  } catch (err) {
    console.error('[Config] Error loading/creating config:', err);
  }
}

/**
 * Save configuration to disk
 */
function saveConfig() {
  try {
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(appConfig, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error('[Config] Error saving config:', err);
    return false;
  }
}

// ==========================================
// REST API ENDPOINTS
// ==========================================

// Get system overview status
app.get('/api/status', (req, res) => {
  res.json({
    config: {
      onlineLookupEnabled: appConfig.onlineLookupEnabled,
      virusTotalEnabled: appConfig.virusTotalEnabled,
      hasVTKey: !!appConfig.virusTotalApiKey,
      hasTFKey: !!appConfig.threatFoxApiKey,
      autoQuarantine: appConfig.autoQuarantine,
      monitoredFolder: appConfig.monitoredFolder,
      quarantineFolder: appConfig.quarantineFolder,
      shieldActive: appConfig.shieldActive,
      usbAutoScan: appConfig.usbAutoScan
    },
    database: getStats(),
    scanner: getActiveScanStatus(),
    watcher: getWatcherStatus(),
    updater: getUpdaterStatus()
  });
});

// Update configuration settings
app.post('/api/config', (req, res) => {
  const oldFolder = appConfig.monitoredFolder;
  const oldShieldState = appConfig.shieldActive;

  // Update properties
  if (req.body.virusTotalApiKey !== undefined) appConfig.virusTotalApiKey = req.body.virusTotalApiKey;
  if (req.body.threatFoxApiKey !== undefined) appConfig.threatFoxApiKey = req.body.threatFoxApiKey;
  if (req.body.onlineLookupEnabled !== undefined) appConfig.onlineLookupEnabled = !!req.body.onlineLookupEnabled;
  if (req.body.virusTotalEnabled !== undefined) appConfig.virusTotalEnabled = !!req.body.virusTotalEnabled;
  if (req.body.autoQuarantine !== undefined) appConfig.autoQuarantine = !!req.body.autoQuarantine;
  if (req.body.monitoredFolder !== undefined) appConfig.monitoredFolder = path.resolve(req.body.monitoredFolder);
  if (req.body.quarantineFolder !== undefined) appConfig.quarantineFolder = path.resolve(req.body.quarantineFolder);
  if (req.body.shieldActive !== undefined) appConfig.shieldActive = !!req.body.shieldActive;
  if (req.body.usbAutoScan !== undefined) appConfig.usbAutoScan = !!req.body.usbAutoScan;

  saveConfig();
  logToUI('Configuration settings updated.', 'success');

  // Trigger folder creation if needed
  if (!fs.existsSync(appConfig.monitoredFolder)) fs.mkdirSync(appConfig.monitoredFolder, { recursive: true });
  if (!fs.existsSync(appConfig.quarantineFolder)) fs.mkdirSync(appConfig.quarantineFolder, { recursive: true });

  // Update watcher based on changes
  const folderChanged = oldFolder !== appConfig.monitoredFolder;
  const shieldStateChanged = oldShieldState !== appConfig.shieldActive;

  if (appConfig.shieldActive) {
    if (shieldStateChanged || folderChanged) {
      logToUI(`Restarting Real-time Shield monitor on: ${appConfig.monitoredFolder}`, 'info');
      initWatcher();
    }
  } else {
    if (shieldStateChanged) {
      logToUI('Deactivating Real-time Shield monitor.', 'warning');
      stopWatching();
      broadcastSSE('watcher_status', { active: false, path: null });
    }
  }

  res.json({ success: true, config: appConfig });
});

// Trigger signature database update
app.post('/api/update-db', async (req, res) => {
  if (getUpdaterStatus().inProgress) {
    return res.status(400).json({ success: false, message: 'Update already in progress' });
  }

  // Run in background and stream logs
  updateDatabase(appConfig, (message, level) => {
    logToUI(`[Updater] ${message}`, level);
    broadcastSSE('db_status', { updater: getUpdaterStatus(), db: getStats() });
  }).then(status => {
    broadcastSSE('db_status', { updater: getUpdaterStatus(), db: getStats() });
  });

  res.json({ success: true, message: 'Signature update started' });
});

// Clear signature database
app.post('/api/clear-db', (req, res) => {
  const success = clearDatabase();
  if (success) {
    logToUI('Local malware signature database cleared.', 'warning');
    res.json({ success: true, db: getStats() });
  } else {
    res.status(500).json({ success: false, message: 'Failed to clear database' });
  }
});

// Start folder scan
app.post('/api/scan', (req, res) => {
  let scanPath;
  if (req.body.path === 'ALL_DRIVES') {
    scanPath = [];
    // Discovers drive letters C:\ to Z:\
    for (let i = 67; i <= 90; i++) {
      const drive = String.fromCharCode(i) + ':\\';
      if (fs.existsSync(drive)) {
        scanPath.push(drive);
      }
    }
    logToUI(`Starting Full System Scan on all active drives: ${scanPath.join(', ')}`, 'info');
    recordEvent('Scanner', 'info', `Full system scan started on drives: ${scanPath.join(', ')}`);
  } else {
    scanPath = req.body.path ? path.resolve(req.body.path) : appConfig.monitoredFolder;
    if (!fs.existsSync(scanPath)) {
      return res.status(400).json({ success: false, message: 'Target scan path does not exist' });
    }
    logToUI(`Starting folder scan on: ${scanPath}`, 'info');
    recordEvent('Scanner', 'info', `Folder scan started on: ${scanPath}`, { path: scanPath });
  }

  startDirectoryScan(scanPath, appConfig, {
    onProgress: (progressData) => {
      broadcastSSE('scan_progress', progressData);
    },
    onComplete: (summary) => {
      const targetMsg = Array.isArray(scanPath) ? 'All Drives' : scanPath;
      logToUI(`Scan complete on ${targetMsg}. Scanned: ${summary.filesScanned} files. Threats found: ${summary.threatsFound}. Duration: ${summary.duration}s.`, summary.threatsFound > 0 ? 'warning' : 'success');
      recordEvent(
        'Scanner', 
        summary.threatsFound > 0 ? 'warning' : 'success', 
        `Scan completed on ${targetMsg}. Files scanned: ${summary.filesScanned}, Threats found: ${summary.threatsFound}`, 
        { ...summary, path: targetMsg }
      );
      broadcastSSE('scan_complete', summary);
    },
    onError: (err) => {
      logToUI(`Scan error: ${err}`, 'error');
      recordEvent('Scanner', 'error', `Scan error on ${scanPath}: ${err}`, { error: err });
      broadcastSSE('scan_error', { message: err });
    }
  });

  res.json({ success: true, path: Array.isArray(scanPath) ? 'ALL_DRIVES' : scanPath });
});

// Control scan status (pause/resume/cancel)
app.post('/api/scan/control', (req, res) => {
  const action = req.body.action; // 'pause', 'resume', 'cancel'
  const success = controlScan(action);
  if (success) {
    logToUI(`Scan status action executed: ${action}`, 'info');
    res.json({ success: true });
  } else {
    res.status(400).json({ success: false, message: 'No active scan or invalid action' });
  }
});

// Get Quarantine registry list
app.get('/api/quarantine', (req, res) => {
  const registryPath = path.join(appConfig.quarantineFolder, 'quarantine_registry.json');
  let registry = [];
  if (fs.existsSync(registryPath)) {
    try {
      registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
    } catch (err) {
      // Ignore
    }
  }
  res.json(registry);
});

// Restore file from quarantine
app.post('/api/quarantine/restore', async (req, res) => {
  const id = req.body.id;
  try {
    const originalPath = await restoreFile(id, appConfig.quarantineFolder);
    logToUI(`Quarantined file restored successfully to: ${originalPath}`, 'success');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Permanently delete file from quarantine
app.post('/api/quarantine/delete', (req, res) => {
  const id = req.body.id;
  try {
    const registryPath = path.join(appConfig.quarantineFolder, 'quarantine_registry.json');
    if (!fs.existsSync(registryPath)) {
      throw new Error('Quarantine registry not found');
    }

    let registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
    const idx = registry.findIndex(item => item.id === id);
    if (idx === -1) {
      throw new Error('Quarantine record not found');
    }

    const item = registry[idx];
    if (fs.existsSync(item.quarantinePath)) {
      fs.unlinkSync(item.quarantinePath);
    }

    registry.splice(idx, 1);
    fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2), 'utf8');

    logToUI(`Permanently deleted quarantined file: ${item.originalName}`, 'warning');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ==========================================
// PROCESS MEMORY ROUTER
// ==========================================

// Get Windows running processes threat status
app.get('/api/processes', async (req, res) => {
  logToUI('Initiating running process memory check...', 'info');
  try {
    const list = await scanProcesses(appConfig);
    const maliciousCount = list.filter(p => p.status === 'malicious').length;
    const suspiciousCount = list.filter(p => p.status === 'suspicious').length;
    const threats = maliciousCount + suspiciousCount;
    logToUI(`Process scan completed. Active processes checked: ${list.length}. Threats found in memory: ${maliciousCount} malicious, ${suspiciousCount} suspicious`, threats > 0 ? 'error' : 'success');
    
    // Log threats to forensics
    const threatList = list.filter(p => p.status === 'malicious' || p.status === 'suspicious');
    threatList.forEach(p => {
      recordEvent('Process Sentry', p.status === 'malicious' ? 'error' : 'warning', `Threat process detected: ${p.name} (PID: ${p.pid})`, {
        pid: p.pid,
        name: p.name,
        commandLine: p.commandLine,
        details: p.details
      });
    });
    
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Terminate process by PID
app.post('/api/processes/kill', async (req, res) => {
  const pid = parseInt(req.body.pid);
  const name = req.body.name || 'Unknown';
  try {
    await killProcess(pid);
    logToUI(`Terminated process PID: ${pid} (${name}) successfully.`, 'warning');
    recordEvent('Process Sentry', 'warning', `Terminated suspicious process: ${name} (PID: ${pid})`, { pid, name });
    res.json({ success: true });
  } catch (err) {
    logToUI(`Failed to terminate process PID: ${pid}: ${err.message}`, 'error');
    res.status(500).json({ success: false, message: err.message });
  }
});

// ==========================================
// YARA SIGNATURE RULES ROUTER
// ==========================================
app.get('/api/rules', (req, res) => {
  res.json(getActiveRules());
});

// Sync APT YARA rules from community repository
app.post('/api/rules/sync', async (req, res) => {
  logToUI('Initiating online APT YARA rules synchronization...', 'info');
  
  const sources = [
    { name: 'APT1', url: 'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_APT1.yar' },
    { name: 'APT15', url: 'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_APT15.yar' },
    { name: 'Stuxnet', url: 'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_Stuxnet.yar' },
    { name: 'BlackEnergy', url: 'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_Blackenergy.yar' }
  ];

  let totalParsed = 0;
  let totalAdded = 0;

  try {
    for (const source of sources) {
      logToUI(`Downloading rules for ${source.name}...`, 'info');
      try {
        const response = await axios.get(source.url, { timeout: 15000 });
        if (response.status === 200 && response.data) {
          const rules = parseYaraText(response.data);
          totalParsed += rules.length;
          const added = mergeRules(rules);
          totalAdded += added;
          logToUI(`Successfully imported ${rules.length} rules from ${source.name} (Added/Updated: ${added}).`, 'success');
        } else {
          logToUI(`Failed to download ${source.name}: Invalid response status ${response.status}`, 'warning');
        }
      } catch (sourceErr) {
        logToUI(`Failed to sync ${source.name}: ${sourceErr.message}`, 'warning');
        console.error(`[Rules Sync] Error syncing ${source.name}:`, sourceErr.message);
      }
    }

    logToUI(`APT YARA rules sync completed. Total parsed: ${totalParsed}. Total new rules added: ${totalAdded}.`, 'success');
    res.json({ success: true, parsedCount: totalParsed, addedCount: totalAdded });
  } catch (err) {
    logToUI(`APT YARA rules sync failed: ${err.message}`, 'error');
    res.status(500).json({ success: false, message: err.message });
  }
});

// ==========================================
// HOSTS BLOCKLIST / DNS SINKHOLE ROUTER
// ==========================================

// Get URLhaus blocklist status
app.get('/api/hosts/status', (req, res) => {
  res.json(getHostsStatus());
});

// Download latest hosts blocklist from URLhaus
app.post('/api/hosts/sync', async (req, res) => {
  try {
    const meta = await downloadHostsBlocklist((msg, level) => {
      logToUI(`[Hosts Sinkhole] ${msg}`, level);
      broadcastSSE('hosts_status', getHostsStatus());
    });
    broadcastSSE('hosts_status', getHostsStatus());
    res.json({ success: true, metadata: meta });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Apply hosts blocklist to system hosts file (requires Admin)
app.post('/api/hosts/apply', (req, res) => {
  try {
    const result = applyHostsToSystem();
    logToUI(`Applied URLhaus host blocks to Windows hosts file. Blocked: ${result.count} domains.`, 'success');
    res.json({ success: true, count: result.count });
  } catch (err) {
    logToUI(`Failed to write system hosts file: ${err.message}`, 'error');
    res.status(500).json({ success: false, message: err.message });
  }
});

// Remove hosts blocklist from system hosts file
app.post('/api/hosts/remove', (req, res) => {
  try {
    removeHostsFromSystem();
    logToUI('Removed URLhaus hosts blocklist from Windows system hosts file.', 'warning');
    res.json({ success: true });
  } catch (err) {
    logToUI(`Failed to clean system hosts file: ${err.message}`, 'error');
    res.status(500).json({ success: false, message: err.message });
  }
});

// ==========================================
// EDR CORE SERVICES ROUTER
// ==========================================

// Get forensics timeline logs
app.get('/api/forensics', (req, res) => {
  try {
    const logs = loadForensicsLog();
    res.json(logs);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Get rollback backup registry records
app.get('/api/rollback', (req, res) => {
  try {
    const backups = getBackupList();
    res.json(backups);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Revert a target file to its clean backup state
app.post('/api/rollback/revert', (req, res) => {
  const { filePath } = req.body;
  if (!filePath) {
    return res.status(400).json({ success: false, message: 'Missing filePath parameter' });
  }
  try {
    const success = restoreBackup(filePath);
    if (success) {
      logToUI(`Rollback restored successfully: ${filePath}`, 'success');
      recordEvent('Rollback Engine', 'success', `Restored file from rollback vault: ${filePath}`, { filePath });
      res.json({ success: true, message: `Successfully reverted ${filePath}` });
    } else {
      res.status(500).json({ success: false, message: 'Restore operation failed' });
    }
  } catch (err) {
    logToUI(`Rollback restore failed on ${filePath}: ${err.message}`, 'error');
    res.status(500).json({ success: false, message: err.message });
  }
});

// ==========================================
// SSE EVENT ROUTE
// ==========================================
app.get('/api/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });

  // Write initial connection success
  res.write('retry: 10000\n\n');
  sseClients.push(res);
  console.log(`[SSE] Client connected. Total clients: ${sseClients.length}`);

  req.on('close', () => {
    sseClients = sseClients.filter(client => client !== res);
    console.log(`[SSE] Client disconnected. Remaining: ${sseClients.length}`);
  });
});

// ==========================================
// MONITOR LOOPS / INITIALIZATION
// ==========================================

function initWatcher() {
  if (appConfig.shieldActive) {
    startWatching(appConfig.monitoredFolder, appConfig, (event, data) => {
      if (event === 'status') {
        broadcastSSE('watcher_status', data);
        logToUI(data.message, 'success');
      } else if (event === 'activity') {
        let msg = `File ${data.action}: ${data.file}`;
        logToUI(`[Shield Watcher] ${msg}`, 'info');
      } else if (event === 'scan_start') {
        logToUI(`[Shield Watcher] Scanning new/modified file: ${data.file}`, 'info');
      } else if (event === 'scan_clean') {
        logToUI(`[Shield Watcher] File is clean: ${data.file}`, 'success');
      } else if (event === 'threat') {
        const severity = data.type === 'malicious' ? 'error' : 'warning';
        logToUI(`[SHIELD ALERT] Threat detected! File: ${data.file}. Location: ${data.path}. Source: ${data.source}. Details: ${data.details}`, severity);
        recordEvent('Shield Watcher', data.type === 'malicious' ? 'error' : 'warning', `Threat detected: ${data.file} (${data.details})`, { filePath: data.path, source: data.source });
        broadcastSSE('watcher_threat', data);
      } else if (event === 'quarantine') {
        logToUI(`[Shield Watcher] Auto-Quarantined malicious file: ${data.file} to ${data.quarantinePath}`, 'warning');
        recordEvent('Shield Watcher', 'warning', `Auto-Quarantined malicious file: ${data.file}`, { originalPath: data.originalPath, quarantinePath: data.quarantinePath });
        broadcastSSE('watcher_quarantine', data);
      } else if (event === 'error') {
        logToUI(`[Shield Watcher Error] ${data.message}`, 'error');
        recordEvent('Shield Watcher', 'error', `Shield watcher error: ${data.message}`, { error: data.message });
      }
    });
  }
}

function initUSBMonitor() {
  startUSBMonitor(appConfig, (msg, level) => {
    logToUI(`[USB Monitor] ${msg}`, level);
    if (msg.includes('Detected USB device connected')) {
      const drive = msg.split('drive letter:')[1]?.trim() || '';
      recordEvent('USB Monitor', 'info', msg, { drive });
    }
  }, (driveLetterPath) => {
    const scanStatus = getActiveScanStatus();
    if (scanStatus.running) {
      logToUI(`[USB Monitor] Warning: Cannot start auto-scan on ${driveLetterPath} because another scan is currently running.`, 'warning');
      recordEvent('USB Monitor', 'warning', `USB connected at ${driveLetterPath} but scan skipped (another scan running)`);
      return;
    }
    
    recordEvent('USB Monitor', 'info', `Starting USB Auto-Scan on drive: ${driveLetterPath}`);
    startDirectoryScan(driveLetterPath, appConfig, {
      onProgress: (progressData) => {
        broadcastSSE('scan_progress', progressData);
      },
      onComplete: (summary) => {
        logToUI(`USB Auto-Scan completed on ${driveLetterPath}. Scanned: ${summary.filesScanned} files. Threats found: ${summary.threatsFound}. Duration: ${summary.duration}s.`, summary.threatsFound > 0 ? 'warning' : 'success');
        recordEvent('USB Monitor', summary.threatsFound > 0 ? 'warning' : 'success', `USB Auto-Scan completed on ${driveLetterPath}. Threats found: ${summary.threatsFound}`, { drive: driveLetterPath, ...summary });
        broadcastSSE('scan_complete', summary);
      },
      onError: (err) => {
        logToUI(`USB Auto-Scan error on ${driveLetterPath}: ${err}`, 'error');
        recordEvent('USB Monitor', 'error', `USB Auto-Scan failed on ${driveLetterPath}: ${err}`, { drive: driveLetterPath, error: err });
        broadcastSSE('scan_error', { message: err });
      }
    });
  });
}

// Start application
loadConfig();
loadDatabase();
loadRules();

app.listen(PORT, () => {
  console.log(`[Aegis Sentinel] Web server active at http://localhost:${PORT}`);
  
  // Start directory monitor after server starts
  setTimeout(() => {
    initWatcher();
    initUSBMonitor();
  }, 1000);
});

// Exit clean up
process.on('SIGINT', () => {
  stopUSBMonitor();
  process.exit(0);
});
process.on('SIGTERM', () => {
  stopUSBMonitor();
  process.exit(0);
});
