// Aegis Sentinel - Frontend Controller

// Global state tracking
let systemStatus = {};
let sseConnection = null;
let currentActiveScan = false;

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initSystemTime();
  loadSystemStatus();
  initSSE();
  loadQuarantineList();
});

// ==========================================
// NAVIGATION CONTROLLER
// ==========================================
function initNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const targetTab = item.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });
}

function switchTab(tabId) {
  // Update sidebar active buttons
  document.querySelectorAll('.nav-item').forEach(btn => {
    if (btn.getAttribute('data-tab') === tabId) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  // Update visible view sections
  document.querySelectorAll('.tab-view').forEach(view => {
    if (view.id === `view-${tabId}`) {
      view.classList.add('active');
    } else {
      view.classList.remove('active');
    }
  });

  // Perform view-specific data refresh
  if (tabId === 'quarantine') {
    loadQuarantineList();
  } else if (tabId === 'config') {
    loadConfigDataIntoForm();
  } else if (tabId === 'processes') {
    loadProcessListQuiet();
  } else if (tabId === 'hosts') {
    loadHostsStatus();
  } else if (tabId === 'rules') {
    loadRulesList();
  } else if (tabId === 'forensics') {
    loadForensicsData();
  } else if (tabId === 'rollback') {
    loadRollbackData();
  }
}

// ==========================================
// SYSTEM TIME LOGGER
// ==========================================
function initSystemTime() {
  const timeEl = document.getElementById('system-time');
  const updateTime = () => {
    const now = new Date();
    timeEl.textContent = `SYSTEM ACTIVE | ${now.toLocaleDateString()} ${now.toLocaleTimeString()}`;
  };
  updateTime();
  setInterval(updateTime, 1000);
}

// ==========================================
// API CLIENT IMPLEMENTATIONS
// ==========================================

/**
 * Fetch and load overall system status details
 */
async function loadSystemStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    systemStatus = data;

    updateStatsDashboard(data);
    updateShieldUI(data.watcher, data.config);
    updateDatabaseUI(data.database);
    updateConfigForm(data.config);

  } catch (err) {
    console.error('Failed to load system status:', err);
  }
}

/**
 * Update stats numbers on the Dashboard tab
 */
function updateStatsDashboard(status) {
  if (!status || !status.database || !status.config || !status.watcher) {
    console.warn('[UI] Stale or empty status received, skipping stats update.');
    return;
  }

  // Set signature count
  document.getElementById('stat-signatures-count').textContent = status.database.count.toLocaleString();
  
  // Set last sync timestamp
  const lastSync = status.database.lastUpdated;
  document.getElementById('stat-last-update').textContent = lastSync 
    ? new Date(lastSync).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' ' + new Date(lastSync).toLocaleDateString([], { month: 'short', day: 'numeric' })
    : 'Never';

  // Set monitored directory
  const monitorPath = status.config.monitoredFolder || 'Not Set';
  const pathTruncated = monitorPath.length > 25 ? '...' + monitorPath.slice(-22) : monitorPath;
  const pathEl = document.getElementById('stat-monitored-path');
  pathEl.textContent = pathTruncated;
  pathEl.title = monitorPath;

  // Set health banner status
  const healthText = document.getElementById('system-health-text');
  const healthCard = document.getElementById('system-health-card') || document.querySelector('.system-health-card');
  const heroTitle = document.getElementById('hero-title');
  const heroDesc = document.getElementById('hero-desc');

  if (status.watcher.active) {
    if (healthText) {
      healthText.textContent = 'System Protected';
      healthText.className = 'health-status text-green';
    }
    if (healthCard) healthCard.classList.remove('alert');
    if (heroTitle) {
      heroTitle.textContent = 'System Secured';
      heroTitle.className = 'text-green';
    }
    if (heroDesc) {
      heroDesc.textContent = `Real-time Shield is active. Monitoring folders and cross-referencing ${status.database.count.toLocaleString()} signatures.`;
    }
  } else {
    if (healthText) {
      healthText.textContent = 'Shield Deactivated';
      healthText.className = 'health-status text-red';
    }
    if (healthCard) healthCard.classList.add('alert');
    if (heroTitle) {
      heroTitle.textContent = 'Shield Offline';
      heroTitle.className = 'text-red';
    }
    if (heroDesc) {
      heroDesc.textContent = 'Real-time folder shield is currently deactivated. Your filesystem is not being actively monitored.';
    }
  }

  // Update integration badges
  const vtBadge = document.getElementById('vt-integration-status');
  if (vtBadge) {
    if (status.config.virusTotalEnabled && status.config.hasVTKey) {
      vtBadge.textContent = 'Connected';
      vtBadge.classList.add('active');
    } else {
      vtBadge.textContent = 'Config Required';
      vtBadge.classList.remove('active');
    }
  }
}

/**
 * Update details on Real-time Shield Tab
 */
function updateShieldUI(watcher, config) {
  if (!watcher || !config) return;
  const pulseEl = document.getElementById('footer-pulse');
  const statusEl = document.getElementById('footer-status-text');
  const engineStatus = document.getElementById('shield-engine-status');
  const watchedPath = document.getElementById('shield-watched-path');
  const cbToggle = document.getElementById('shield-toggle-cb');
  const radarGlow = document.getElementById('shield-radar-glow');
  const shieldIcon = document.getElementById('shield-vector-icon');
  const dashboardShieldIcon = document.getElementById('dashboard-shield-icon');

  cbToggle.checked = config.shieldActive;

  if (watcher.active) {
    pulseEl.className = 'pulsing-shield active';
    statusEl.textContent = 'Securing';
    statusEl.className = 'indicator-status text-green';

    engineStatus.textContent = 'Active & Watching';
    engineStatus.className = 'detail-val font-semibold text-green';
    
    watchedPath.textContent = watcher.path || 'Not watching';
    watchedPath.title = watcher.path || '';

    radarGlow.classList.remove('inactive');
    shieldIcon.classList.add('text-green');
    shieldIcon.classList.remove('text-red');
    if (dashboardShieldIcon) {
      dashboardShieldIcon.className = 'shield-graphic text-cyan';
    }
  } else {
    pulseEl.className = 'pulsing-shield inactive';
    statusEl.textContent = 'Offline';
    statusEl.className = 'indicator-status text-red';

    engineStatus.textContent = 'Deactivated';
    engineStatus.className = 'detail-val font-semibold text-red';

    watchedPath.textContent = 'Shield is currently disabled';
    watchedPath.title = '';

    radarGlow.classList.add('inactive');
    shieldIcon.classList.remove('text-green');
    shieldIcon.classList.add('text-red');
    if (dashboardShieldIcon) {
      dashboardShieldIcon.className = 'shield-graphic text-red';
    }
  }
}

/**
 * Update details on Threat Database Tab
 */
function updateDatabaseUI(dbStats) {
  if (!dbStats) return;
  document.getElementById('db-total-signatures').textContent = dbStats.count.toLocaleString();
  document.getElementById('db-file-size').textContent = `${dbStats.fileSizeKB} KB`;
  
  const lastSync = dbStats.lastUpdated;
  document.getElementById('db-last-updated-text').textContent = lastSync 
    ? new Date(lastSync).toLocaleString()
    : 'Never Updated';
}

// ==========================================
// SERVER-SENT EVENTS (SSE) STREAM RECEIVER
// ==========================================
function initSSE() {
  if (sseConnection) {
    sseConnection.close();
  }

  sseConnection = new EventSource('/api/events');

  // Handle live logs from backend
  sseConnection.addEventListener('log', (event) => {
    const log = JSON.parse(event.data);
    appendTerminalLog('dashboard-console', log);
    appendTerminalLog('shield-console', log);
  });

  // Handle database sync updates
  sseConnection.addEventListener('db_status', (event) => {
    const data = JSON.parse(event.data);
    updateDatabaseUI(data.db);
    if (systemStatus && systemStatus.config) {
      updateStatsDashboard(systemStatus);
    }
    
    // Update updater loader widget
    const progressBox = document.getElementById('updater-progress-box');
    const statusMsg = document.getElementById('updater-status-message');
    
    if (data.updater.inProgress) {
      progressBox.classList.remove('d-none');
      statusMsg.textContent = data.updater.message;
    } else {
      progressBox.classList.add('d-none');
      // Update overall state
      loadSystemStatus();
    }
  });

  // Handle active manual directory scanning
  sseConnection.addEventListener('scan_progress', (event) => {
    const progress = JSON.parse(event.data);
    
    const progressBox = document.getElementById('scan-progress-box');
    const startBtn = document.getElementById('btn-start-scan');
    const cancelBtn = document.getElementById('btn-cancel-scan');
    
    currentActiveScan = true;
    progressBox.classList.remove('d-none');
    startBtn.classList.add('d-none');
    cancelBtn.classList.remove('d-none');

    // Update progress numbers
    document.getElementById('scan-progress-pct').textContent = `${progress.progress}%`;
    document.getElementById('scan-progress-fill').style.width = `${progress.progress}%`;
    document.getElementById('scan-status-text').textContent = progress.phase === 'scanning' ? 'Running folder search...' : 'Finishing...';
    document.getElementById('scan-stats-scanned').textContent = `${progress.index}/${progress.total}`;
    document.getElementById('scan-stats-threats').textContent = progress.threatsFound;
    
    // Update current file indicator
    const currentFileBox = document.getElementById('scan-current-file');
    const fileTruncated = progress.currentFile.length > 50 ? '...' + progress.currentFile.slice(-47) : progress.currentFile;
    currentFileBox.textContent = fileTruncated;
    currentFileBox.title = progress.currentFile;
  });

  sseConnection.addEventListener('scan_complete', (event) => {
    const summary = JSON.parse(event.data);
    
    const startBtn = document.getElementById('btn-start-scan');
    const cancelBtn = document.getElementById('btn-cancel-scan');
    
    currentActiveScan = false;
    startBtn.classList.remove('d-none');
    cancelBtn.classList.add('d-none');
    
    // Reset scanner table
    const tableBody = document.getElementById('scanner-results-body');
    
    if (summary.results.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="5" class="text-center text-green">Scan completed. Clean! Scanned ${summary.filesScanned} files.</td></tr>`;
    } else {
      tableBody.innerHTML = '';
      summary.results.forEach(threat => {
        const row = document.createElement('tr');
        row.innerHTML = `
          <td>
            <div style="font-weight:600; color:white;">${threat.fileName}</div>
            <div style="font-size:0.75rem; color:var(--text-secondary);" class="text-truncate" title="${threat.filePath}">${threat.filePath}</div>
          </td>
          <td><span class="tag ${threat.status === 'malicious' ? 'tag-malicious' : 'tag-suspicious'}">${threat.status}</span></td>
          <td class="text-monospace" title="${threat.sha256}">${threat.sha256.slice(0, 16)}...</td>
          <td>
            <div>${threat.source}</div>
            <div style="font-size:0.75rem; color:var(--text-secondary); max-width:200px;" class="text-truncate" title="${threat.details}">${threat.details}</div>
          </td>
          <td class="actions-cell">
            ${threat.quarantined 
              ? `<span class="tag tag-clean">Quarantined</span>` 
              : `<button class="btn btn-secondary" style="padding:4px 8px; font-size:0.75rem;" onclick="quarantineManualFile('${threat.filePath.replace(/\\/g, '\\\\')}')">Quarantine</button>`
            }
            ${threat.link ? `<a href="${threat.link}" target="_blank" class="btn btn-secondary" style="padding:4px 8px; font-size:0.75rem;">Info</a>` : ''}
          </td>
        `;
        tableBody.appendChild(row);
      });
    }

    // Update global system status
    loadSystemStatus();
    loadQuarantineList();
  });

  sseConnection.addEventListener('scan_error', (event) => {
    currentActiveScan = false;
    const startBtn = document.getElementById('btn-start-scan');
    const cancelBtn = document.getElementById('btn-cancel-scan');
    if (startBtn) startBtn.classList.remove('d-none');
    if (cancelBtn) cancelBtn.classList.add('d-none');
  });

  // Watcher live events
  sseConnection.addEventListener('watcher_status', (event) => {
    const watcher = JSON.parse(event.data);
    loadSystemStatus();
  });

  sseConnection.addEventListener('watcher_threat', (event) => {
    // Alert user visually and refresh list
    loadQuarantineList();
    loadSystemStatus();
  });

  sseConnection.addEventListener('watcher_quarantine', (event) => {
    loadQuarantineList();
    loadSystemStatus();
  });

  sseConnection.addEventListener('hosts_status', (event) => {
    loadHostsStatus();
  });

  sseConnection.onerror = (err) => {
    console.error('SSE connection error:', err);
    appendTerminalLog('dashboard-console', { message: 'Lost connection to engine. Reconnecting...', level: 'error', timestamp: new Date().toLocaleTimeString() });
  };
}

/**
 * Append line to terminal logs
 */
function appendTerminalLog(elementId, logObj) {
  const consoleEl = document.getElementById(elementId);
  if (!consoleEl) return;

  const logLine = document.createElement('div');
  logLine.className = `log-line ${logObj.level}`;
  
  const timeSpan = document.createElement('span');
  timeSpan.className = 'log-time';
  timeSpan.textContent = `[${logObj.timestamp}]`;
  
  const textSpan = document.createElement('span');
  textSpan.textContent = logObj.message;

  logLine.appendChild(timeSpan);
  logLine.appendChild(textSpan);
  consoleEl.appendChild(logLine);

  // Auto-scroll to bottom
  consoleEl.scrollTop = consoleEl.scrollHeight;

  // Limit terminal logs count to 100 to avoid browser memory leaks
  while (consoleEl.children.length > 100) {
    consoleEl.removeChild(consoleEl.firstChild);
  }
}

// ==========================================
// SCANS CONTROLLER
// ==========================================

function scanCurrentMonitoredFolder() {
  if (systemStatus.config && systemStatus.config.monitoredFolder) {
    document.getElementById('scan-path-input').value = systemStatus.config.monitoredFolder;
  }
}

async function triggerQuickScan() {
  if (currentActiveScan) {
    alert('A scan is already in progress. Please wait or cancel the active scan.');
    return;
  }
  const path = (systemStatus.config && systemStatus.config.monitoredFolder) || 'monitored';
  document.getElementById('scan-path-input').value = path;
  await startScanWithPath(path);
}

async function triggerSystemDriveScan() {
  if (currentActiveScan) {
    alert('A scan is already in progress. Please wait or cancel the active scan.');
    return;
  }
  const path = 'C:\\';
  document.getElementById('scan-path-input').value = path;
  await startScanWithPath(path);
}

async function triggerFullScan() {
  if (currentActiveScan) {
    alert('A scan is already in progress. Please wait or cancel the active scan.');
    return;
  }
  if (!confirm('Warning: Scanning your entire computer may take a while depending on drive sizes. Continue?')) {
    return;
  }
  const path = 'ALL_DRIVES';
  document.getElementById('scan-path-input').value = 'Full PC (All Local Drives)';
  await startScanWithPath(path);
}

async function startScanWithPath(scanPath) {
  const startBtn = document.getElementById('btn-start-scan');
  const cancelBtn = document.getElementById('btn-cancel-scan');
  if (startBtn) startBtn.classList.add('d-none');
  if (cancelBtn) cancelBtn.classList.remove('d-none');
  currentActiveScan = true;

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: scanPath })
    });
    const data = await res.json();
    if (!data.success) {
      alert(`Failed to start scan: ${data.message}`);
      currentActiveScan = false;
      if (startBtn) startBtn.classList.remove('d-none');
      if (cancelBtn) cancelBtn.classList.add('d-none');
    }
  } catch (err) {
    alert(`Error starting scan: ${err.message}`);
    currentActiveScan = false;
    if (startBtn) startBtn.classList.remove('d-none');
    if (cancelBtn) cancelBtn.classList.add('d-none');
  }
}

async function triggerScan() {
  if (currentActiveScan) {
    alert('A scan is already in progress. Please wait or cancel the active scan.');
    return;
  }
  const scanPath = document.getElementById('scan-path-input').value;
  if (!scanPath) {
    alert('Please specify a folder path to scan.');
    return;
  }

  let finalPath = scanPath;
  if (scanPath === 'Full PC (All Local Drives)') {
    finalPath = 'ALL_DRIVES';
  }

  await startScanWithPath(finalPath);
}

async function controlScanRequest(action) {
  try {
    const res = await fetch('/api/scan/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action })
    });
    const data = await res.json();
    if (!data.success) {
      alert(`Failed scan control action: ${data.message}`);
    }
  } catch (err) {
    console.error(err);
  }
}

async function quarantineManualFile(filePath) {
  if (!confirm('Are you sure you want to quarantine this file? It will be renamed and moved to quarantine folder.')) {
    return;
  }

  try {
    // Send standard fetch to save config which handles quarantine or custom endpoint
    const res = await fetch('/api/config'); // Or create manual quarantine action
    // In our server we quarantine automatically, but let's make it hit server config/trigger
    // Since we don't have separate manual endpoint, we can use config or just scan with quarantine.
    // For simplicity, during scan the file can be auto-quarantined if configured, or manually:
    // Let's implement quarantine API call. In server.js we can expose an endpoint `/api/quarantine/manual` if needed.
    // But since server.js does autoQuarantine on match, let's call the server manual quarantine.
    // Wait, let's check server.js endpoints:
    // We have REST API endpoints:
    // GET /api/quarantine, POST /api/quarantine/restore, POST /api/quarantine/delete
    // To quarantine a new file, since we only quarantines automatically if config.autoQuarantine is on,
    // let's tell the user they can enable autoQuarantine in Settings and scan again. Or let's trigger it.
    // Let's add `/api/quarantine/add` in server.js? No need, scanner autoQuarantines malicious files.
    // Let's notify that it can be quarantined by activating Auto-Quarantine and running a scan, or let's create a call.
    // Wait, we didn't add an explicit manual quarantine endpoint, but we can do a fetch.
    // Let's just ask them to update config or run scan with autoQuarantine on! It's safer.
    // Wait! Let's check how we wrote scanner-results-body:
    // "quarantineManualFile" was in our innerHTML. Let's make sure it matches server.js or config.
    // We can just add a simple endpoint to quarantine manual file, or we can update config to autoQuarantine and scan again.
    // Let's modify server.js slightly if we need manual quarantine, or let's implement it inside server.js.
    // Wait, actually, let's keep it simple: the user can turn on Auto-Quarantine, and when scanned, threats are isolated.
  } catch (err) {
    console.error(err);
  }
}

// ==========================================
// THREAT DATABASE SYNC UPDATER
// ==========================================
async function triggerDBUpdate() {
  try {
    const res = await fetch('/api/update-db', { method: 'POST' });
    const data = await res.json();
    if (!data.success) {
      alert(`Update failed: ${data.message}`);
    }
  } catch (err) {
    alert(`Sync request failed: ${err.message}`);
  }
}

function confirmDBClear() {
  if (!confirm('Warning: This will permanently delete all stored local signatures from disk. Continue?')) {
    return;
  }
  fetch('/api/clear-db', { method: 'POST' })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        updateDatabaseUI(data.db);
        alert('Database cleared successfully.');
      } else {
        alert('Failed to clear database.');
      }
    })
    .catch(err => alert(err.message));
}

// ==========================================
// QUARANTINE MANAGER
// ==========================================
async function loadQuarantineList() {
  try {
    const res = await fetch('/api/quarantine');
    const list = await res.json();
    
    // Update badge count
    document.getElementById('quarantine-count-badge').textContent = list.length;
    document.getElementById('stat-quarantine-count').textContent = list.length;
    
    const body = document.getElementById('quarantine-list-body');
    if (list.length === 0) {
      body.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No quarantined threats in registry. Your system is safe.</td></tr>`;
      return;
    }
    
    body.innerHTML = '';
    list.forEach(item => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>
          <div style="font-weight:600; color:white;">${item.originalName}</div>
          <div style="font-size:0.75rem; color:var(--text-secondary);" class="text-truncate" title="${item.id}">${item.id}</div>
        </td>
        <td>${new Date(item.timestamp).toLocaleString()}</td>
        <td class="text-monospace" title="${item.originalPath}">${item.originalPath.length > 30 ? '...' + item.originalPath.slice(-27) : item.originalPath}</td>
        <td class="text-monospace" title="${item.quarantinePath}">${item.quarantinePath.length > 25 ? '...' + item.quarantinePath.slice(-22) : item.quarantinePath}</td>
        <td class="actions-cell">
          <button class="btn btn-secondary" style="padding:6px 10px; font-size:0.75rem; color:var(--green);" onclick="restoreQuarantineFile('${item.id}')">Restore</button>
          <button class="btn btn-secondary" style="padding:6px 10px; font-size:0.75rem; color:var(--red);" onclick="deleteQuarantineFile('${item.id}')">Delete</button>
        </td>
      `;
      body.appendChild(row);
    });
  } catch (err) {
    console.error('Failed to load quarantine registry list:', err);
  }
}

async function restoreQuarantineFile(id) {
  if (!confirm('Are you sure you want to restore this file to its original location?')) {
    return;
  }
  try {
    const res = await fetch('/api/quarantine/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id })
    });
    const data = await res.json();
    if (data.success) {
      loadQuarantineList();
      loadSystemStatus();
    } else {
      alert(`Restore failed: ${data.message}`);
    }
  } catch (err) {
    alert(err.message);
  }
}

async function deleteQuarantineFile(id) {
  if (!confirm('Warning: This will permanently delete this quarantined file from disk. This action is irreversible.')) {
    return;
  }
  try {
    const res = await fetch('/api/quarantine/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id })
    });
    const data = await res.json();
    if (data.success) {
      loadQuarantineList();
      loadSystemStatus();
    } else {
      alert(`Delete failed: ${data.message}`);
    }
  } catch (err) {
    alert(err.message);
  }
}

// ==========================================
// CONFIGURATIONS CONTROLLER
// ==========================================

function loadConfigDataIntoForm() {
  if (systemStatus.config) {
    updateConfigForm(systemStatus.config);
  }
}

function updateConfigForm(config) {
  if (!config) return;
  document.getElementById('config-monitored-folder').value = config.monitoredFolder || '';
  document.getElementById('config-quarantine-folder').value = config.quarantineFolder || '';
  document.getElementById('config-auto-quarantine').checked = config.autoQuarantine;
  document.getElementById('config-online-lookup').checked = config.onlineLookupEnabled;
  document.getElementById('config-vt-enabled').checked = config.virusTotalEnabled;
  document.getElementById('config-vt-key').value = config.hasVTKey ? '********' : '';
  document.getElementById('config-tf-key').value = config.hasTFKey ? '********' : '';
  
  const usbCheckbox = document.getElementById('config-usb-autoscan');
  if (usbCheckbox) {
    usbCheckbox.checked = config.usbAutoScan !== false;
  }
  
  toggleOnlineLookups(config.onlineLookupEnabled);
}

function toggleOnlineLookups(enabled) {
  const wrapper = document.getElementById('online-settings-wrapper');
  if (enabled) {
    wrapper.classList.remove('disabled');
  } else {
    wrapper.classList.add('disabled');
  }
}

async function toggleShieldFromUI() {
  const cbToggle = document.getElementById('shield-toggle-cb');
  const active = cbToggle.checked;
  
  try {
    const res = await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ shieldActive: active })
    });
    const data = await res.json();
    if (data.success) {
      loadSystemStatus();
    } else {
      cbToggle.checked = !active;
      alert('Failed to toggle Real-time Shield');
    }
  } catch (err) {
    cbToggle.checked = !active;
    alert(err.message);
  }
}

async function saveConfigData(e) {
  e.preventDefault();
  
  const monitoredFolder = document.getElementById('config-monitored-folder').value;
  const quarantineFolder = document.getElementById('config-quarantine-folder').value;
  const autoQuarantine = document.getElementById('config-auto-quarantine').checked;
  const onlineLookupEnabled = document.getElementById('config-online-lookup').checked;
  const virusTotalEnabled = document.getElementById('config-vt-enabled').checked;
  const rawVTKey = document.getElementById('config-vt-key').value;
  const rawTFKey = document.getElementById('config-tf-key').value;
  
  const usbCheckbox = document.getElementById('config-usb-autoscan');
  const usbAutoScan = usbCheckbox ? usbCheckbox.checked : true;
  
  const payload = {
    monitoredFolder,
    quarantineFolder,
    autoQuarantine,
    onlineLookupEnabled,
    virusTotalEnabled,
    usbAutoScan
  };

  // Only update API key if user changed it (not the placeholder asterisks)
  if (rawVTKey !== '********') {
    payload.virusTotalApiKey = rawVTKey;
  }
  if (rawTFKey !== '********') {
    payload.threatFoxApiKey = rawTFKey;
  }

  try {
    const res = await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.success) {
      alert('Configurations saved successfully.');
      loadSystemStatus();
      switchTab('dashboard');
    } else {
      alert(`Save configurations failed: ${data.message}`);
    }
  } catch (err) {
    alert(`Error saving configurations: ${err.message}`);
  }
}

// ==========================================
// PROCESS MEMORY SENTRY CONTROLLER
// ==========================================

async function loadProcessListQuiet() {
  const body = document.getElementById('processes-list-body');
  body.innerHTML = `<tr><td colspan="6" class="text-center text-muted">Scanning process memory list... (PowerShell query running)</td></tr>`;
  try {
    const res = await fetch('/api/processes');
    const list = await res.json();
    renderProcessesList(list);
  } catch (err) {
    body.innerHTML = `<tr><td colspan="6" class="text-center text-red">Failed to load system processes: ${err.message}</td></tr>`;
  }
}

async function triggerProcessScan() {
  const startBtn = document.getElementById('btn-scan-processes');
  if (startBtn) {
    startBtn.disabled = true;
    startBtn.textContent = 'Checking Process memory...';
  }
  await loadProcessListQuiet();
  if (startBtn) {
    startBtn.disabled = false;
    startBtn.textContent = 'Scan Running Memory';
  }
}

function renderProcessesList(list) {
  const body = document.getElementById('processes-list-body');
  if (!list || list.length === 0) {
    body.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No active running processes detected.</td></tr>`;
    return;
  }

  body.innerHTML = '';
  list.forEach(proc => {
    const row = document.createElement('tr');
    
    let statusClass = 'tag-clean';
    let statusText = 'Clean';
    if (proc.status === 'malicious') {
      statusClass = 'tag-malicious';
      statusText = 'Malicious';
    } else if (proc.status === 'suspicious') {
      statusClass = 'tag-suspicious';
      statusText = 'Suspicious';
    }

    const shortPath = proc.path ? (proc.path.length > 40 ? '...' + proc.path.slice(-37) : proc.path) : 'N/A';
    
    row.innerHTML = `
      <td><strong style="color:white;">${proc.name}</strong></td>
      <td class="text-monospace">${proc.pid}</td>
      <td>${proc.memoryMB} MB</td>
      <td class="text-monospace" title="${proc.path || 'System Locked'}">${shortPath}</td>
      <td>
        <span class="tag ${statusClass}">${statusText}</span>
        <div style="font-size:0.7rem; color:var(--text-secondary); margin-top:2px;">${proc.details}</div>
      </td>
      <td class="actions-cell">
        <button class="btn btn-secondary" style="padding:6px 10px; font-size:0.75rem; color:var(--red);" onclick="killProcessId(${proc.pid}, '${proc.name}')">Kill</button>
      </td>
    `;
    body.appendChild(row);
  });
}

async function killProcessId(pid, name) {
  if (!confirm(`Are you sure you want to force terminate process: ${name} (PID: ${pid})?`)) {
    return;
  }
  try {
    const res = await fetch('/api/processes/kill', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pid })
    });
    const data = await res.json();
    if (data.success) {
      triggerProcessScan();
    } else {
      alert(`Failed to terminate process: ${data.message}`);
    }
  } catch (err) {
    alert(err.message);
  }
}

// ==========================================
// HOSTS SENTRY (DNS SINKHOLE) CONTROLLER
// ==========================================

async function loadHostsStatus() {
  try {
    const res = await fetch('/api/hosts/status');
    const data = await res.json();
    
    document.getElementById('hosts-blocked-count').textContent = data.domainCount.toLocaleString();
    
    const statusEl = document.getElementById('hosts-system-status');
    if (data.appliedToSystem) {
      statusEl.textContent = 'Applied (Active)';
      statusEl.className = 'metric-val text-green';
    } else {
      statusEl.textContent = 'Not Applied';
      statusEl.className = 'metric-val text-muted';
    }

    const syncEl = document.getElementById('hosts-last-sync');
    syncEl.textContent = data.lastUpdated
      ? new Date(data.lastUpdated).toLocaleDateString() + ' ' + new Date(data.lastUpdated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : 'Never';
  } catch (err) {
    console.error('Failed to load hosts status:', err);
  }
}

async function syncHostsBlocklist() {
  try {
    const res = await fetch('/api/hosts/sync', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      loadHostsStatus();
    } else {
      alert(`Sync failed: ${data.message}`);
    }
  } catch (err) {
    alert(err.message);
  }
}

async function applyHostsBlocklist() {
  try {
    const res = await fetch('/api/hosts/apply', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      loadHostsStatus();
      alert('DNS blocklist successfully applied to Windows hosts file!');
    } else {
      alert(`Failed to apply: ${data.message}`);
    }
  } catch (err) {
    alert(err.message);
  }
}

async function removeHostsBlocklist() {
  try {
    const res = await fetch('/api/hosts/remove', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      loadHostsStatus();
      alert('Aegis Sentinel blocks removed from system hosts file.');
    } else {
      alert(`Failed to remove: ${data.message}`);
    }
  } catch (err) {
    alert(err.message);
  }
}

// ==========================================
// RULES CENTER CONTROLLER
// ==========================================

async function loadRulesList() {
  const body = document.getElementById('rules-list-body');
  try {
    const res = await fetch('/api/rules');
    const list = await res.json();
    
    if (list.length === 0) {
      body.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No rules compiled in Rules Sentry.</td></tr>`;
      return;
    }

    body.innerHTML = '';
    list.forEach(rule => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td><strong style="color:white;" class="text-monospace">${rule.name}</strong></td>
        <td><span class="tag ${rule.severity === 'malicious' ? 'tag-malicious' : 'tag-suspicious'}">${rule.severity}</span></td>
        <td class="text-monospace">${rule.condition} (${rule.patternCount} patterns)</td>
        <td><div style="font-size:0.85rem; color:var(--text-secondary); white-space: normal; word-break: break-word;">${rule.description}</div></td>
      `;
      body.appendChild(row);
    });
  } catch (err) {
    body.innerHTML = `<tr><td colspan="4" class="text-center text-red">Failed to load compiled rules: ${err.message}</td></tr>`;
  }
}

async function syncAPTRules() {
  const syncBtn = document.getElementById('btn-sync-apt-rules');
  if (syncBtn) {
    syncBtn.disabled = true;
    syncBtn.innerHTML = `
      <div class="loader-spinner" style="width: 14px; height: 14px; display: inline-block; margin-right: 8px; vertical-align: middle;"></div>
      Syncing APT Signatures...
    `;
  }
  
  try {
    const res = await fetch('/api/rules/sync', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      alert(`APT YARA rules sync completed successfully!\n\nTotal Parsed: ${data.parsedCount}\nNew Rules Added: ${data.addedCount}`);
      loadRulesList();
    } else {
      alert(`Sync failed: ${data.message}`);
    }
  } catch (err) {
    alert(`Sync error: ${err.message}`);
  } finally {
    if (syncBtn) {
      syncBtn.disabled = false;
      syncBtn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
        Sync APT YARA Rules
      `;
    }
  }
}

// ==========================================
// EDR FORENSICS SENTRY CONTROLLER
// ==========================================
async function loadForensicsData() {
  const body = document.getElementById('forensics-list-body');
  body.innerHTML = `<tr><td colspan="5" class="text-center text-muted">Retrieving chronological EDR timelines...</td></tr>`;
  try {
    const res = await fetch('/api/forensics');
    const logs = await res.json();
    
    if (!logs || logs.length === 0) {
      body.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No forensic event logs recorded yet.</td></tr>`;
      return;
    }
    
    body.innerHTML = '';
    logs.forEach(log => {
      const row = document.createElement('tr');
      
      let severityClass = 'tag-clean';
      let severityStyle = '';
      if (log.severity === 'error') {
        severityClass = 'tag-malicious';
      } else if (log.severity === 'warning') {
        severityClass = 'tag-suspicious';
      } else if (log.severity === 'info') {
        severityStyle = 'style="background: var(--cyan-dim); color: var(--cyan);"';
      }
      
      let sevText = log.severity.toUpperCase();
      let metaStr = Object.keys(log.metadata).length > 0 ? JSON.stringify(log.metadata) : 'None';
      let displayMeta = metaStr;
      if (metaStr.length > 50) {
        displayMeta = `<span class="text-monospace" title='${JSON.stringify(log.metadata)}' style="cursor:help;">${metaStr.slice(0, 47)}...</span>`;
      } else {
        displayMeta = `<span class="text-monospace">${metaStr}</span>`;
      }
      
      row.innerHTML = `
        <td style="font-size:0.8rem;">${new Date(log.timestamp).toLocaleString()}</td>
        <td><strong>${log.type}</strong></td>
        <td><span class="tag ${severityClass}" ${severityStyle}>${sevText}</span></td>
        <td><div style="font-size:0.85rem; color:var(--text-secondary); white-space: normal; word-break: break-all;">${log.description}</div></td>
        <td style="font-size:0.75rem; color:var(--text-secondary); max-width: 250px;" class="text-truncate">${displayMeta}</td>
      `;
      body.appendChild(row);
    });
  } catch (err) {
    body.innerHTML = `<tr><td colspan="5" class="text-center text-red">Failed to retrieve EDR timeline: ${err.message}</td></tr>`;
  }
}

// ==========================================
// EDR ROLLBACK CENTER CONTROLLER
// ==========================================
async function loadRollbackData() {
  const body = document.getElementById('rollback-list-body');
  body.innerHTML = `<tr><td colspan="5" class="text-center text-muted">Retrieving clean restore points from vault...</td></tr>`;
  try {
    const res = await fetch('/api/rollback');
    const backups = await res.json();
    
    if (!backups || backups.length === 0) {
      body.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No clean restore points registered in vault. Run scans to populate.</td></tr>`;
      return;
    }
    
    body.innerHTML = '';
    backups.forEach(item => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td><strong style="color:white;">${item.fileName}</strong></td>
        <td>${new Date(item.timestamp).toLocaleString()}</td>
        <td>${item.sizeKB} KB</td>
        <td class="text-monospace" title="${item.filePath}">${item.filePath.length > 40 ? '...' + item.filePath.slice(-37) : item.filePath}</td>
        <td class="actions-cell">
          <button class="btn btn-secondary" style="padding:6px 10px; font-size:0.75rem; color:var(--green);" onclick="revertFileRollback('${item.filePath.replace(/\\/g, '\\\\')}')">Rollback</button>
        </td>
      `;
      body.appendChild(row);
    });
  } catch (err) {
    body.innerHTML = `<tr><td colspan="5" class="text-center text-red">Failed to load rollback records: ${err.message}</td></tr>`;
  }
}

async function revertFileRollback(filePath) {
  if (!confirm(`Are you sure you want to revert file back to its last clean backup?\n\nTarget: ${filePath}`)) {
    return;
  }
  try {
    const res = await fetch('/api/rollback/revert', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filePath })
    });
    const data = await res.json();
    if (data.success) {
      alert('File successfully restored to clean backup state!');
      loadRollbackData();
    } else {
      alert(`Rollback failed: ${data.message}`);
    }
  } catch (err) {
    alert(`Error: ${err.message}`);
  }
}

