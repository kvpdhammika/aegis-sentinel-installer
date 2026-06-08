import fs from 'fs';
import path from 'path';

const RULES_PATH = path.resolve('rules.json');

// Default built-in YARA-like rules
const DEFAULT_RULES = [
  {
    name: 'Threat.Test.EICAR',
    description: 'EICAR Standard Antivirus Test File signature',
    severity: 'malicious',
    condition: 'any',
    patterns: [
      { type: 'text', value: 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' }
    ]
  },
  {
    name: 'Trojan.PHP.Webshell',
    description: 'Suspicious PHP web shell functions (eval/base64 dropper or terminal command execution)',
    severity: 'suspicious',
    condition: 'any',
    patterns: [
      { type: 'text', value: 'eval(base64_decode' },
      { type: 'text', value: 'system($_GET' },
      { type: 'text', value: 'shell_exec($_POST' },
      { type: 'text', value: 'passthru($_GET' },
      { type: 'text', value: 'exec($_POST' }
    ]
  },
  {
    name: 'Ransomware.Note.Indicator',
    description: 'Text pattern typical of a ransomware demand notice',
    severity: 'malicious',
    condition: 'any',
    patterns: [
      { type: 'text', value: 'all your files have been encrypted' },
      { type: 'text', value: 'your files are encrypted' },
      { type: 'text', value: 'YOUR_FILES_ARE_LOCKED' },
      { type: 'text', value: 'restore_files_instructions' },
      { type: 'text', value: 'decrypt files contact' }
    ]
  },
  {
    name: 'HackTool.Powershell.Downloader',
    description: 'Suspicious PowerShell outbound file downloader script',
    severity: 'suspicious',
    condition: 'all',
    patterns: [
      { type: 'text', value: 'Net.WebClient' },
      { type: 'text', value: 'DownloadFile' },
      { type: 'text', value: 'bypass' }
    ]
  }
];

let compiledRules = [];

/**
 * Load and compile rules from rules.json or load defaults
 */
export function loadRules() {
  try {
    if (fs.existsSync(RULES_PATH)) {
      const raw = fs.readFileSync(RULES_PATH, 'utf8');
      compiledRules = JSON.parse(raw);
      console.log(`[Rules Engine] Loaded ${compiledRules.length} rules from disk.`);
    } else {
      compiledRules = DEFAULT_RULES;
      fs.writeFileSync(RULES_PATH, JSON.stringify(DEFAULT_RULES, null, 2), 'utf8');
      console.log(`[Rules Engine] Initialized default rules.json on disk.`);
    }
    
    // Compile string buffers for fast matching
    compiledRules.forEach(rule => {
      rule.patterns.forEach(pattern => {
        if (pattern.type === 'text') {
          pattern.buffer = Buffer.from(pattern.value, 'utf8');
        } else if (pattern.type === 'hex') {
          // Parse hex space-separated string e.g. "4d 5a 90 00"
          const cleanHex = pattern.value.replace(/\s+/g, '');
          pattern.buffer = Buffer.from(cleanHex, 'hex');
        }
      });
    });
    
    return true;
  } catch (err) {
    console.error('[Rules Engine] Error compiling rules:', err);
    compiledRules = DEFAULT_RULES;
    return false;
  }
}

/**
 * Scan a file buffer against compiled signature patterns
 * @param {Buffer} buffer 
 * @returns {Array<object>} array of rule matches
 */
export function scanBuffer(buffer) {
  if (compiledRules.length === 0) {
    loadRules();
  }

  const matches = [];

  for (const rule of compiledRules) {
    let matchCount = 0;
    const matchedPatterns = [];

    for (const pattern of rule.patterns) {
      if (!pattern.buffer) continue;
      
      // Fast buffer search in Node.js
      const idx = buffer.indexOf(pattern.buffer);
      if (idx !== -1) {
        matchCount++;
        matchedPatterns.push({
          value: pattern.value,
          offset: idx
        });
      }
    }

    // Evaluate rule logic
    let isMatched = false;
    if (rule.condition === 'any' && matchCount > 0) {
      isMatched = true;
    } else if (rule.condition === 'all' && matchCount === rule.patterns.length) {
      isMatched = true;
    } else if (typeof rule.condition === 'number' && matchCount >= rule.condition) {
      isMatched = true;
    }

    if (isMatched) {
      matches.push({
        name: rule.name,
        description: rule.description,
        severity: rule.severity,
        matchedPatterns
      });
    }
  }

  return matches;
}

/**
 * Expose rules list
 */
export function getActiveRules() {
  if (compiledRules.length === 0) {
    loadRules();
  }
  return compiledRules.map(r => ({
    name: r.name,
    description: r.description,
    severity: r.severity,
    condition: r.condition,
    patternCount: r.patterns.length
  }));
}

/**
 * Parses a raw YARA text file into standard JSON rule format.
 * Extracts string and hex patterns and handles simple conditions.
 * @param {string} yaraText 
 * @returns {Array<object>} array of parsed rules
 */
export function parseYaraText(yaraText) {
  const rules = [];
  
  // Clean block comments /* ... */
  let cleanText = yaraText.replace(/\/\*[\s\S]*?\*\//g, '');
  
  // Clean single-line comments // ...
  cleanText = cleanText.split('\n').map(line => {
    const idx = line.indexOf('//');
    return idx === -1 ? line : line.substring(0, idx);
  }).join('\n');
  
  // Split rules by rule boundaries
  const ruleBlocks = cleanText.split(/\brule\s+/);
  
  for (let i = 1; i < ruleBlocks.length; i++) {
    const block = ruleBlocks[i];
    
    // Extract rule name
    const nameMatch = block.match(/^([a-zA-Z0-9_]+)/);
    if (!nameMatch) continue;
    const ruleName = nameMatch[1];
    
    const stringsStart = block.toLowerCase().indexOf('strings:');
    const conditionStart = block.toLowerCase().indexOf('condition:');
    
    if (stringsStart === -1 || conditionStart === -1) continue;
    
    const stringsSection = block.substring(stringsStart + 8, conditionStart);
    const conditionSection = block.substring(conditionStart + 10).trim();
    
    // Extract description from meta block if exists
    const metaStart = block.toLowerCase().indexOf('meta:');
    let description = `Imported APT rule: ${ruleName}`;
    if (metaStart !== -1 && metaStart < stringsStart) {
      const metaSection = block.substring(metaStart + 5, stringsStart);
      const descMatch = metaSection.match(/(?:description|info)\s*=\s*"([^"]+)"/i);
      if (descMatch) {
        description = descMatch[1];
      }
    }
    
    // Parse individual strings
    const patterns = [];
    const stringLines = stringsSection.split('\n');
    
    for (let line of stringLines) {
      line = line.trim();
      if (!line.startsWith('$')) continue;
      
      const equalsIdx = line.indexOf('=');
      if (equalsIdx === -1) continue;
      
      const varValue = line.substring(equalsIdx + 1).trim();
      let cleanVal = varValue;
      if (cleanVal.endsWith(';')) {
        cleanVal = cleanVal.substring(0, cleanVal.length - 1).trim();
      }
      
      if (cleanVal.startsWith('"')) {
        const closingQuoteIdx = cleanVal.lastIndexOf('"');
        if (closingQuoteIdx > 0) {
          const content = cleanVal.substring(1, closingQuoteIdx);
          const cleanContent = content.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
          // Ignore short common strings
          if (cleanContent.length >= 4) {
            patterns.push({
              type: 'text',
              value: cleanContent
            });
          }
        }
      } else if (cleanVal.startsWith('{')) {
        const closingBraceIdx = cleanVal.indexOf('}');
        if (closingBraceIdx > 0) {
          const hexContent = cleanVal.substring(1, closingBraceIdx).trim();
          // Filter out complex wildcards or jumps
          if (!hexContent.includes('?') && !hexContent.includes('[') && !hexContent.includes('-')) {
            patterns.push({
              type: 'hex',
              value: hexContent
            });
          }
        }
      }
    }
    
    if (patterns.length === 0) continue;
    
    // Determine condition (default to 'any', but check for 'all')
    let condition = 'any';
    const cleanCond = conditionSection.toLowerCase();
    if (cleanCond.includes('all of them') || cleanCond.includes('all of ($s')) {
      condition = 'all';
    }
    
    rules.push({
      name: `APT.${ruleName}`,
      description: description,
      severity: 'malicious',
      condition: condition,
      patterns: patterns
    });
  }
  
  return rules;
}

/**
 * Merges newly parsed APT rules into the local rules.json file and recompiles
 * @param {Array<object>} newRules 
 * @returns {number} number of newly added rules
 */
export function mergeRules(newRules) {
  let existingRules = [];
  try {
    if (fs.existsSync(RULES_PATH)) {
      existingRules = JSON.parse(fs.readFileSync(RULES_PATH, 'utf8'));
    } else {
      existingRules = [...DEFAULT_RULES];
    }
  } catch (err) {
    existingRules = [...DEFAULT_RULES];
  }

  let addedCount = 0;
  for (const rule of newRules) {
    const idx = existingRules.findIndex(r => r.name === rule.name);
    if (idx !== -1) {
      existingRules[idx] = rule;
    } else {
      existingRules.push(rule);
      addedCount++;
    }
  }

  try {
    fs.writeFileSync(RULES_PATH, JSON.stringify(existingRules, null, 2), 'utf8');
    loadRules();
    return addedCount;
  } catch (err) {
    console.error('[Rules Engine] Failed to save merged rules:', err);
    throw err;
  }
}

