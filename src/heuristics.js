import fs from 'fs';

/**
 * Calculates the Shannon Entropy of a buffer (measure of randomness, range 0.0 to 8.0)
 * @param {Buffer} buffer 
 * @returns {number} entropy value
 */
export function calculateEntropy(buffer) {
  if (!buffer || buffer.length === 0) return 0;
  
  const len = buffer.length;
  const frequencies = new Uint32Array(256);
  
  // Count byte occurrences
  for (let i = 0; i < len; i++) {
    frequencies[buffer[i]]++;
  }
  
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    const count = frequencies[i];
    if (count > 0) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
  }
  
  return Math.round(entropy * 100) / 100;
}

/**
 * Heuristics check: Checks if file looks like a packed or encrypted executable
 * @param {Buffer} buffer 
 * @param {string} fileName 
 * @returns {object|null} detection details if suspicious, otherwise null
 */
export function analyzeHeuristics(buffer, fileName) {
  if (!buffer || buffer.length < 64) return null;

  // Check 1: Is it a PE (Portable Executable) binary?
  // MZ header is 'M' (77, 0x4d) and 'Z' (90, 0x5a) at bytes 0 & 1
  const isPE = buffer[0] === 77 && buffer[1] === 90;
  
  // Also check common executable extensions just in case
  const lowerName = fileName.toLowerCase();
  const isExecutableExt = lowerName.endsWith('.exe') || 
                           lowerName.endsWith('.dll') || 
                           lowerName.endsWith('.sys') || 
                           lowerName.endsWith('.scr') ||
                           lowerName.endsWith('.com');

  if (!isPE && !isExecutableExt) {
    return null; // Only apply entropy heuristics to executable files to minimize false positives
  }

  // Check 2: Calculate entropy
  const entropy = calculateEntropy(buffer);
  
  // A standard compiled PE binary typically has an entropy of 5.0 to 6.8.
  // Encrypted or packed binaries (typical of ransomware or virus packers) have an entropy > 7.3.
  const ENTROPY_THRESHOLD = 7.3;
  
  if (entropy > ENTROPY_THRESHOLD) {
    return {
      suspicious: true,
      reason: 'High Entropy Executable',
      details: `Entropy is ${entropy}/8.0 (Threshold: ${ENTROPY_THRESHOLD}). The file exhibits high randomness, indicating it is likely encrypted or packed (obfuscated).`,
      entropy: entropy
    };
  }

  return null;
}
