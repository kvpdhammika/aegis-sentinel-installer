import fs from 'fs';
import path from 'path';

const BACKUP_DIR = path.resolve('quarantine/backups');
const REGISTRY_PATH = path.join(BACKUP_DIR, 'backup_registry.json');

/**
 * Backup a clean file to the recovery vault
 * @param {string} filePath 
 */
export function backupFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) return;
    
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return;

    // Limit backups to files < 15MB to prevent disk space bloat
    if (stat.size > 15 * 1024 * 1024) return;

    if (!fs.existsSync(BACKUP_DIR)) {
      fs.mkdirSync(BACKUP_DIR, { recursive: true });
    }

    // Convert absolute path to a safe unique backup filename
    const safeName = path.resolve(filePath).replace(/\\/g, '_').replace(/:/g, '');
    const backupPath = path.join(BACKUP_DIR, `${safeName}.bak`);

    // Copy to vault
    fs.copyFileSync(filePath, backupPath);

    // Save metadata in registry
    let registry = {};
    if (fs.existsSync(REGISTRY_PATH)) {
      try {
        registry = JSON.parse(fs.readFileSync(REGISTRY_PATH, 'utf8'));
      } catch (err) {
        registry = {};
      }
    }

    registry[filePath] = {
      backupPath,
      timestamp: new Date().toISOString(),
      originalSize: stat.size,
      fileName: path.basename(filePath)
    };

    fs.writeFileSync(REGISTRY_PATH, JSON.stringify(registry, null, 2), 'utf8');
  } catch (err) {
    console.error(`[Rollback Engine] Backup failed on ${filePath}:`, err.message);
  }
}

/**
 * Revert a modified or encrypted file to its last known clean state
 * @param {string} filePath 
 * @returns {boolean} true if restored successfully
 */
export function restoreBackup(filePath) {
  try {
    if (!fs.existsSync(REGISTRY_PATH)) {
      throw new Error('Backup registry not found.');
    }

    const registry = JSON.parse(fs.readFileSync(REGISTRY_PATH, 'utf8'));
    const record = registry[filePath];

    if (!record || !fs.existsSync(record.backupPath)) {
      throw new Error('No backup record found for this file.');
    }

    // Ensure target folder exists
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Revert file
    fs.copyFileSync(record.backupPath, filePath);
    return true;
  } catch (err) {
    console.error(`[Rollback Engine] Restore failed on ${filePath}:`, err.message);
    throw err;
  }
}

/**
 * Fetch all backed-up files list
 * @returns {Array<object>}
 */
export function getBackupList() {
  if (!fs.existsSync(REGISTRY_PATH)) {
    return [];
  }
  try {
    const registry = JSON.parse(fs.readFileSync(REGISTRY_PATH, 'utf8'));
    return Object.keys(registry).map(filePath => ({
      filePath,
      fileName: registry[filePath].fileName,
      timestamp: registry[filePath].timestamp,
      sizeKB: Math.round(registry[filePath].originalSize / 1024 * 100) / 100
    }));
  } catch (err) {
    return [];
  }
}
