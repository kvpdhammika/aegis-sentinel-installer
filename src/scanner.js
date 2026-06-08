import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import axios from 'axios';
import { hasSignature, addSignatures } from './db.js';
import { analyzeHeuristics } from './heuristics.js';
import { scanBuffer } from './yara.js';
import { backupFile } from './rollback.js';

// Global scan control state
let activeScan = null;

/**
 * Computes the SHA-256 hash of a file on disk in a memory-efficient stream.
 * @param {string} filePath 
 * @returns {Promise<string>}
 */
export function getFileSHA256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', err => reject(err));
  });
}

/**
 * Query MalwareBazaar API for file hash information
 * @param {string} sha256 
 * @returns {Promise<object|null>}
 */
async function queryMalwareBazaar(sha256) {
  try {
    const params = new URLSearchParams();
    params.append('query', 'get_info');
    params.append('hash', sha256);

    const response = await axios.post('https://mb-api.abuse.ch/api/v1/', params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 10000
    });

    if (response.data && response.data.query_status === 'ok' && response.data.data && response.data.data.length > 0) {
      const data = response.data.data[0];
      return {
        found: true,
        source: 'MalwareBazaar',
        signature: data.signature || data.malware_family || 'Generic Malware',
        fileType: data.file_type || 'Unknown',
        tags: data.tags || [],
        firstSeen: data.first_seen || 'Unknown',
        intelligenceLink: `https://bazaar.abuse.ch/sample/${sha256}/`
      };
    }
  } catch (err) {
    console.error('[Scanner] MalwareBazaar query failed:', err.message);
  }
  return null;
}

/**
 * Query VirusTotal API v3 for file hash information
 * @param {string} sha256 
 * @param {string} apiKey 
 * @returns {Promise<object|null>}
 */
async function queryVirusTotal(sha256, apiKey) {
  if (!apiKey) return null;
  try {
    const response = await axios.get(`https://www.virustotal.com/api/v3/files/${sha256}`, {
      headers: { 'x-apikey': apiKey },
      timeout: 10000
    });

    if (response.data && response.data.data && response.data.data.attributes) {
      const attrs = response.data.data.attributes;
      const stats = attrs.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0);

      return {
        found: true,
        source: 'VirusTotal',
        maliciousCount: malicious,
        suspiciousCount: suspicious,
        totalEngines: totalEngines,
        names: attrs.names || [],
        suggestedThreat: attrs.suggested_threat_label || null,
        intelligenceLink: `https://www.virustotal.com/gui/file/${sha256}`
      };
    }
  } catch (err) {
    // 404 means file not found in VirusTotal database, which is expected for clean files.
    if (err.response && err.response.status === 404) {
      return { found: false, source: 'VirusTotal', message: 'Not found in VirusTotal database' };
    }
    console.error('[Scanner] VirusTotal API query failed:', err.message);
  }
  return null;
}

/**
 * Scan a single file and return threat status
 * @param {string} filePath 
 * @param {object} config - Application settings (API keys, online scan preferences)
 * @returns {Promise<object>} scan result
 */
export async function scanFile(filePath, config = {}, isSingleFileScan = false) {
  try {
    if (!fs.existsSync(filePath)) {
      return { status: 'error', message: 'File does not exist' };
    }

    const stat = fs.statSync(filePath);
    if (!stat.isFile()) {
      return { status: 'error', message: 'Target is not a file' };
    }

    const fileName = path.basename(filePath);
    
    // Step 1: Compute hash
    const sha256 = await getFileSHA256(filePath);
    
    // Step 2: Check Local Database
    if (hasSignature(sha256)) {
      return {
        status: 'malicious',
        filePath,
        fileName,
        fileSizeKB: Math.round(stat.size / 1024 * 100) / 100,
        sha256,
        source: 'Local Signature Database',
        details: 'Identified matching signature in local known-threat database.'
      };
    }

    // Step 3: Check MalwareBazaar (if online query is enabled and this is a single/shield scan)
    if (config.onlineLookupEnabled && isSingleFileScan) {
      const mbInfo = await queryMalwareBazaar(sha256);
      if (mbInfo) {
        // Cache this threat in our local database so we don't hit the API again
        addSignatures([sha256]);
        return {
          status: 'malicious',
          filePath,
          fileName,
          fileSizeKB: Math.round(stat.size / 1024 * 100) / 100,
          sha256,
          source: mbInfo.source,
          details: `Detected as threat: ${mbInfo.signature}. Category: ${mbInfo.fileType}. Tags: ${mbInfo.tags.join(', ')}.`,
          link: mbInfo.intelligenceLink
        };
      }
    }

    // Step 4: Check VirusTotal (if online query, VT enabled, API key provided, and this is a single/shield scan)
    if (config.onlineLookupEnabled && config.virusTotalEnabled && config.virusTotalApiKey && isSingleFileScan) {
      const vtInfo = await queryVirusTotal(sha256, config.virusTotalApiKey);
      if (vtInfo && vtInfo.found) {
        const isMalicious = vtInfo.maliciousCount > 0;
        const isSuspicious = vtInfo.suspiciousCount > 0;

        if (isMalicious || isSuspicious) {
          // Cache in local database
          addSignatures([sha256]);
          
          return {
            status: isMalicious ? 'malicious' : 'suspicious',
            filePath,
            fileName,
            fileSizeKB: Math.round(stat.size / 1024 * 100) / 100,
            sha256,
            source: vtInfo.source,
            details: `Detected by VirusTotal (${vtInfo.maliciousCount}/${vtInfo.totalEngines} engines flagged as malicious).${vtInfo.suggestedThreat ? ' Threat Type: ' + vtInfo.suggestedThreat : ''}`,
            link: vtInfo.intelligenceLink
          };
        }
      }
    }

    // Step 5: Heuristics & Custom Signature checks (only for files under 15MB to prevent memory overhead)
    if (stat.size < 15 * 1024 * 1024) {
      try {
        const fileBuffer = fs.readFileSync(filePath);
        if (fileBuffer) {
          // A. Custom YARA Pattern Rules scan
          const ruleMatches = scanBuffer(fileBuffer);
          if (ruleMatches && ruleMatches.length > 0) {
            const match = ruleMatches[0];
            return {
              status: match.severity === 'malicious' ? 'malicious' : 'suspicious',
              filePath,
              fileName,
              fileSizeKB: Math.round(stat.size / 1024 * 100) / 100,
              sha256,
              source: `Rules Sentry (${match.name})`,
              details: `Matched heuristic signature: ${match.description}.`,
              matchedRule: match.name
            };
          }

          // B. Shannon Entropy analysis (detects ransomware or crypted payloads)
          const heuristics = analyzeHeuristics(fileBuffer, fileName);
          if (heuristics && heuristics.suspicious) {
            return {
              status: 'suspicious',
              filePath,
              fileName,
              fileSizeKB: Math.round(stat.size / 1024 * 100) / 100,
              sha256,
              source: 'Heuristics Engine',
              details: heuristics.details,
              entropy: heuristics.entropy
            };
          }
        }
      } catch (readErr) {
        // Skip inaccessible file read logs
        console.warn(`[Scanner] Buffer analysis skipped on ${fileName}: ${readErr.message}`);
      }
    }

    // File is clean
    backupFile(filePath);
    return {
      status: 'clean',
      filePath,
      fileName,
      fileSizeKB: Math.round(stat.size / 1024 * 100) / 100,
      sha256,
      details: 'No threats detected'
    };

  } catch (err) {
    console.error(`[Scanner] Error scanning file ${filePath}:`, err);
    return {
      status: 'error',
      filePath,
      fileName: path.basename(filePath),
      message: err.message || err
    };
  }
}

/**
 * Perform recursive folder scanning.
 * Runs in the background and reports progress.
 * @param {string} scanDir 
 * @param {object} config 
 * @param {object} callbacks - { onProgress, onComplete, onError }
 */
export function startDirectoryScan(scanDir, config, { onProgress, onComplete, onError }) {
  if (activeScan && activeScan.running) {
    if (onError) onError('A scan is already in progress');
    return;
  }

  activeScan = {
    running: true,
    paused: false,
    cancelled: false,
    filesScanned: 0,
    threatsFound: 0,
    startTime: Date.now()
  };

  const results = [];
  const filesToScan = [];

  // Helper to recursively collect all files
  function collectFiles(dir) {
    if (activeScan.cancelled) return;
    try {
      if (!fs.existsSync(dir)) return;
      const stat = fs.statSync(dir);
      if (stat.isFile()) {
        filesToScan.push(dir);
        return;
      }

      const items = fs.readdirSync(dir);
      for (const item of items) {
        const fullPath = path.join(dir, item);
        try {
          const itemStat = fs.statSync(fullPath);
          
          if (itemStat.isDirectory()) {
            // Skip quarantine folder to avoid self-scanning loops
            if (config.quarantineFolder && fullPath === path.resolve(config.quarantineFolder)) {
              continue;
            }
            collectFiles(fullPath);
          } else if (itemStat.isFile()) {
            filesToScan.push(fullPath);
          }
        } catch (itemErr) {
          // Skip individual inaccessible files/folders without aborting the rest of the directory walk
          console.warn(`[Scanner] Skipping inaccessible path: ${fullPath} - ${itemErr.message}`);
        }
      }
    } catch (err) {
      console.error(`[Scanner] Error reading directory ${dir}:`, err.message);
    }
  }

  // Gather files asynchronously
  setTimeout(async () => {
    try {
      if (Array.isArray(scanDir)) {
        for (const dir of scanDir) {
          collectFiles(dir);
        }
      } else {
        collectFiles(scanDir);
      }
      
      const totalFiles = filesToScan.length;
      if (totalFiles === 0) {
        activeScan.running = false;
        if (onComplete) onComplete({ results: [], filesScanned: 0, threatsFound: 0, duration: 0 });
        return;
      }

      for (let i = 0; i < totalFiles; i++) {
        // Handle cancel
        if (activeScan.cancelled) {
          break;
        }

        // Handle pause
        while (activeScan.paused && !activeScan.cancelled) {
          await new Promise(resolve => setTimeout(resolve, 200));
        }

        const file = filesToScan[i];
        
        // Notify progress before scan
        if (onProgress) {
          onProgress({
            phase: 'scanning',
            currentFile: file,
            index: i + 1,
            total: totalFiles,
            progress: Math.round(((i + 1) / totalFiles) * 100),
            threatsFound: activeScan.threatsFound
          });
        }

        // Scan file
        const result = await scanFile(file, config);
        
        activeScan.filesScanned++;
        if (result.status === 'malicious' || result.status === 'suspicious') {
          activeScan.threatsFound++;
          results.push(result);
          
          // Execute auto-quarantine if enabled and malicious
          if (config.autoQuarantine && result.status === 'malicious') {
            await quarantineFile(file, config.quarantineFolder);
            result.quarantined = true;
          }
        }

        // Slight delay to keep event loop free and show UI progress smoothly
        await new Promise(resolve => setTimeout(resolve, 50));
      }

      activeScan.running = false;
      const duration = Math.round((Date.now() - activeScan.startTime) / 1000 * 10) / 10;
      
      if (onComplete) {
        onComplete({
          cancelled: activeScan.cancelled,
          results,
          filesScanned: activeScan.filesScanned,
          threatsFound: activeScan.threatsFound,
          duration
        });
      }

    } catch (err) {
      activeScan.running = false;
      if (onError) onError(err.message || err);
    }
  }, 10);
}

/**
 * Move a malicious file to quarantine folder and rename it (append .quarantine) to neutralize it.
 * @param {string} filePath 
 * @param {string} quarantineDir 
 * @returns {Promise<string>} final quarantined file path
 */
export function quarantineFile(filePath, quarantineDir = './quarantine') {
  return new Promise((resolve, reject) => {
    try {
      if (!fs.existsSync(filePath)) {
        return reject(new Error('File to quarantine does not exist'));
      }

      // Create quarantine dir if not exists
      if (!fs.existsSync(quarantineDir)) {
        fs.mkdirSync(quarantineDir, { recursive: true });
      }

      const fileName = path.basename(filePath);
      const uniqueName = `${Date.now()}_${fileName}.quarantined`;
      const targetPath = path.join(quarantineDir, uniqueName);

      // Read then write and unlink to support cross-device moves if necessary
      fs.copyFileSync(filePath, targetPath);
      fs.unlinkSync(filePath);

      console.log(`[Quarantine] Moved ${filePath} to ${targetPath}`);
      
      // Save info in quarantine registry
      const registryPath = path.join(quarantineDir, 'quarantine_registry.json');
      let registry = [];
      if (fs.existsSync(registryPath)) {
        try {
          registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
        } catch (err) {
          // Ignore
        }
      }

      registry.push({
        id: uniqueName,
        originalName: fileName,
        originalPath: filePath,
        quarantinePath: targetPath,
        timestamp: new Date().toISOString()
      });

      fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2), 'utf8');
      
      resolve(targetPath);
    } catch (err) {
      console.error('[Quarantine] Failed to quarantine file:', err);
      reject(err);
    }
  });
}

/**
 * Restore a quarantined file back to its original path.
 * @param {string} id - The quarantined file identifier
 * @param {string} quarantineDir 
 */
export function restoreFile(id, quarantineDir = './quarantine') {
  return new Promise((resolve, reject) => {
    try {
      const registryPath = path.join(quarantineDir, 'quarantine_registry.json');
      if (!fs.existsSync(registryPath)) {
        return reject(new Error('Quarantine registry not found'));
      }

      let registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
      const idx = registry.findIndex(item => item.id === id);
      
      if (idx === -1) {
        return reject(new Error('Quarantine record not found'));
      }

      const item = registry[idx];

      if (!fs.existsSync(item.quarantinePath)) {
        // Clean from registry if file is gone
        registry.splice(idx, 1);
        fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2), 'utf8');
        return reject(new Error('Quarantined file is missing from disk'));
      }

      // Check if target directory exists
      const targetDir = path.dirname(item.originalPath);
      if (!fs.existsSync(targetDir)) {
        fs.mkdirSync(targetDir, { recursive: true });
      }

      // Restore file
      fs.copyFileSync(item.quarantinePath, item.originalPath);
      fs.unlinkSync(item.quarantinePath);

      console.log(`[Quarantine] Restored ${item.quarantinePath} to ${item.originalPath}`);

      // Remove from registry
      registry.splice(idx, 1);
      fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2), 'utf8');

      resolve(item.originalPath);
    } catch (err) {
      console.error('[Quarantine] Failed to restore file:', err);
      reject(err);
    }
  });
}

/**
 * Control scan status: cancel/pause/resume
 */
export function controlScan(action) {
  if (!activeScan) return false;
  if (action === 'cancel') {
    activeScan.cancelled = true;
    activeScan.running = false;
    return true;
  }
  if (action === 'pause') {
    activeScan.paused = true;
    return true;
  }
  if (action === 'resume') {
    activeScan.paused = false;
    return true;
  }
  return false;
}

/**
 * Get active scan information
 */
export function getActiveScanStatus() {
  if (!activeScan || !activeScan.running) {
    return { running: false };
  }
  return {
    running: true,
    paused: activeScan.paused,
    filesScanned: activeScan.filesScanned,
    threatsFound: activeScan.threatsFound,
    elapsedSeconds: Math.round((Date.now() - activeScan.startTime) / 1000)
  };
}
