import chokidar from 'chokidar';
import fs from 'fs';
import path from 'path';
import { scanFile } from './scanner.js';

let watcherInstance = null;
let watcherPath = null;
let watcherStatus = {
  active: false,
  path: null,
  filesMonitored: 0
};

/**
 * Start monitoring a directory for real-time protection
 * @param {string} targetDir 
 * @param {object} config 
 * @param {Function} eventCallback - function(eventName, details)
 */
export function startWatching(targetDir, config, eventCallback) {
  if (watcherInstance) {
    stopWatching();
  }

  // Ensure target folder exists
  const resolvedPath = path.resolve(targetDir);
  if (!fs.existsSync(resolvedPath)) {
    try {
      fs.mkdirSync(resolvedPath, { recursive: true });
    } catch (err) {
      console.error(`[Watcher] Failed to create folder to watch: ${resolvedPath}`, err);
      eventCallback('error', { message: `Could not create folder: ${err.message}` });
      return;
    }
  }

  watcherPath = resolvedPath;
  console.log(`[Watcher] Starting real-time monitor on: ${resolvedPath}`);
  
  // Set up Chokidar watcher
  watcherInstance = chokidar.watch(resolvedPath, {
    ignored: [
      /(^|[\/\\])\../, // Ignore hidden files (dotfiles)
      path.resolve(config.quarantineFolder || './quarantine') // Ignore quarantine folder
    ],
    persistent: true,
    ignoreInitial: true, // Do not trigger events for existing files
    awaitWriteFinish: {
      stabilityThreshold: 1000,
      pollInterval: 100
    }
  });

  watcherInstance
    .on('add', async (filePath) => {
      const fileName = path.basename(filePath);
      console.log(`[Watcher] File added: ${filePath}`);
      eventCallback('activity', { action: 'added', file: fileName, path: filePath });
      
      // Run scanner on the added file
      await handleWatchScan(filePath, config, eventCallback);
    })
    .on('change', async (filePath) => {
      const fileName = path.basename(filePath);
      console.log(`[Watcher] File modified: ${filePath}`);
      eventCallback('activity', { action: 'modified', file: fileName, path: filePath });
      
      // Run scanner on the modified file
      await handleWatchScan(filePath, config, eventCallback);
    })
    .on('unlink', (filePath) => {
      const fileName = path.basename(filePath);
      console.log(`[Watcher] File removed: ${filePath}`);
      eventCallback('activity', { action: 'removed', file: fileName, path: filePath });
    })
    .on('ready', () => {
      watcherStatus.active = true;
      watcherStatus.path = resolvedPath;
      console.log(`[Watcher] Real-time Shield is active and monitoring.`);
      eventCallback('status', { active: true, path: resolvedPath, message: 'Real-time Shield activated' });
    })
    .on('error', (error) => {
      console.error(`[Watcher] Error:`, error);
      eventCallback('error', { message: error.message || error });
    });
}

/**
 * Scan file triggered by watcher and execute quarantine if malicious
 */
async function handleWatchScan(filePath, config, eventCallback) {
  try {
    eventCallback('scan_start', { file: path.basename(filePath), path: filePath });
    
    const result = await scanFile(filePath, config, true);
    
    if (result.status === 'malicious') {
      eventCallback('threat', {
        type: 'malicious',
        file: result.fileName,
        path: filePath,
        details: result.details,
        source: result.source
      });
      
      // Handle auto-quarantine
      if (config.autoQuarantine) {
        try {
          const { quarantineFile } = await import('./scanner.js');
          const finalPath = await quarantineFile(filePath, config.quarantineFolder);
          eventCallback('quarantine', {
            file: result.fileName,
            originalPath: filePath,
            quarantinePath: finalPath,
            status: 'quarantined'
          });
        } catch (qErr) {
          eventCallback('error', { message: `Quarantine failed for ${result.fileName}: ${qErr.message}` });
        }
      }
    } else if (result.status === 'suspicious') {
      eventCallback('threat', {
        type: 'suspicious',
        file: result.fileName,
        path: filePath,
        details: result.details,
        source: result.source
      });
    } else {
      eventCallback('scan_clean', { file: result.fileName, path: filePath });
    }
  } catch (err) {
    console.error(`[Watcher] Error scanning watched file:`, err);
  }
}

/**
 * Stop monitoring
 */
export function stopWatching() {
  if (watcherInstance) {
    watcherInstance.close();
    watcherInstance = null;
    watcherPath = null;
    watcherStatus.active = false;
    watcherStatus.path = null;
    console.log(`[Watcher] Real-time Shield deactivated.`);
  }
}

/**
 * Get the current watcher status
 */
export function getWatcherStatus() {
  return {
    ...watcherStatus
  };
}
