import fs from 'fs';
import path from 'path';

const DB_PATH = path.resolve('signatures.json');
const STATS_PATH = path.resolve('db_stats.json');

// In-memory set of SHA-256 malware signatures (stored in lowercase)
let signatureSet = new Set();
let dbMetadata = {
  lastUpdated: null,
  count: 0,
  sources: ['MalwareBazaar Recent Feed']
};

/**
 * Load signatures and metadata from disk
 */
export function loadDatabase() {
  try {
    // Load metadata
    if (fs.existsSync(STATS_PATH)) {
      const statsRaw = fs.readFileSync(STATS_PATH, 'utf8');
      dbMetadata = JSON.parse(statsRaw);
    }

    // Load signatures
    if (fs.existsSync(DB_PATH)) {
      const dbRaw = fs.readFileSync(DB_PATH, 'utf8');
      const hashes = JSON.parse(dbRaw);
      
      signatureSet = new Set(hashes.map(h => h.toLowerCase().trim()));
      dbMetadata.count = signatureSet.size;
      console.log(`[Database] Loaded ${signatureSet.size} signatures from disk.`);
    } else {
      signatureSet = new Set();
      dbMetadata.count = 0;
      console.log('[Database] No existing signatures.json found. Starting clean.');
    }
    return true;
  } catch (err) {
    console.error('[Database] Error loading database files:', err);
    return false;
  }
}

/**
 * Check if a SHA-256 hash exists in the local database
 * @param {string} sha256 
 * @returns {boolean}
 */
export function hasSignature(sha256) {
  if (!sha256 || typeof sha256 !== 'string') return false;
  return signatureSet.has(sha256.toLowerCase().trim());
}

/**
 * Save new signatures to the local database file
 * @param {Array<string>} sha256Array 
 * @returns {boolean}
 */
export function addSignatures(sha256Array) {
  try {
    let addedCount = 0;
    
    // Add each hash to the set
    for (const hash of sha256Array) {
      const cleaned = hash.toLowerCase().trim();
      // Basic validation: SHA256 length is 64 hex characters
      if (cleaned.length === 64 && /^[0-9a-f]{64}$/.test(cleaned)) {
        if (!signatureSet.has(cleaned)) {
          signatureSet.add(cleaned);
          addedCount++;
        }
      }
    }

    // Persist signatures
    fs.writeFileSync(DB_PATH, JSON.stringify(Array.from(signatureSet), null, 2), 'utf8');
    
    // Update metadata
    dbMetadata.count = signatureSet.size;
    dbMetadata.lastUpdated = new Date().toISOString();
    fs.writeFileSync(STATS_PATH, JSON.stringify(dbMetadata, null, 2), 'utf8');

    console.log(`[Database] Added ${addedCount} new signatures. Total signatures: ${signatureSet.size}`);
    return true;
  } catch (err) {
    console.error('[Database] Error writing signatures to disk:', err);
    return false;
  }
}

/**
 * Clear the database
 */
export function clearDatabase() {
  try {
    signatureSet.clear();
    dbMetadata.count = 0;
    dbMetadata.lastUpdated = new Date().toISOString();
    
    if (fs.existsSync(DB_PATH)) fs.unlinkSync(DB_PATH);
    fs.writeFileSync(STATS_PATH, JSON.stringify(dbMetadata, null, 2), 'utf8');
    
    console.log('[Database] Signatures database cleared.');
    return true;
  } catch (err) {
    console.error('[Database] Error clearing database:', err);
    return false;
  }
}

/**
 * Get current database statistics
 */
export function getStats() {
  let fileSize = 0;
  try {
    if (fs.existsSync(DB_PATH)) {
      const stats = fs.statSync(DB_PATH);
      fileSize = stats.size;
    }
  } catch (err) {
    // Ignore
  }

  return {
    count: signatureSet.size,
    lastUpdated: dbMetadata.lastUpdated,
    fileSizeKB: Math.round(fileSize / 1024 * 100) / 100,
    sources: dbMetadata.sources
  };
}
