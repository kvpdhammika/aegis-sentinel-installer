import { exec } from 'child_process';
import fs from 'fs';
import path from 'path';
import { getFileSHA256 } from './scanner.js';
import { hasSignature } from './db.js';
import { analyzeProcessBehavior } from './behavioral.js';

/**
 * Executes a shell command and returns a promise with stdout
 */
function runShellCommand(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, { maxBuffer: 1024 * 1024 * 10 }, (err, stdout, stderr) => {
      if (err) return reject(err);
      resolve(stdout);
    });
  });
}

/**
 * Fetch list of running processes on Windows with PIDs, names, executable paths, and memory
 * @returns {Promise<Array<object>>}
 */
export async function getRunningProcesses() {
  try {
    // PowerShell command to fetch process info as JSON
    const cmd = `powershell -NoProfile -Command "Get-CimInstance Win32_Process | Select-Object Name, ProcessId, ExecutablePath, WorkingSetSize, CommandLine | ConvertTo-Json -Compress"`;
    const stdout = await runShellCommand(cmd);
    
    if (!stdout || stdout.trim() === '') {
      return [];
    }

    let rawData;
    try {
      rawData = JSON.parse(stdout);
    } catch (parseErr) {
      // If it returned a single object instead of array, wrap it
      if (stdout.trim().startsWith('{')) {
        rawData = [JSON.parse(stdout.trim())];
      } else {
        throw parseErr;
      }
    }

    // Standardize array format
    const processes = Array.isArray(rawData) ? rawData : [rawData];
    
    return processes.map(proc => ({
      name: proc.Name || 'Unknown',
      pid: proc.ProcessId || 0,
      path: proc.ExecutablePath || null,
      memoryMB: proc.WorkingSetSize ? Math.round(proc.WorkingSetSize / 1024 / 1024 * 10) / 10 : 0,
      commandLine: proc.CommandLine || '',
      status: 'unknown',
      sha256: null,
      details: 'Not Scanned'
    })).filter(p => p.pid > 4); // Filter out idle and System processes (PIDs 0-4)
    
  } catch (err) {
    console.error('[Process Scanner] Error listing processes:', err);
    // Fallback: Return empty array
    return [];
  }
}

/**
 * Scan running processes for malware indicators
 * @param {object} config - app config settings
 * @returns {Promise<Array<object>>} scanned processes list
 */
export async function scanProcesses(config = {}) {
  const list = await getRunningProcesses();
  const scannedList = [];

  for (const proc of list) {
    if (!proc.path || !fs.existsSync(proc.path)) {
      // No binary path or system lock (e.g. system services)
      proc.status = 'clean';
      proc.details = 'System Process (Inaccessible Binary)';
      scannedList.push(proc);
      continue;
    }

    try {
      // Calculate hash
      const hash = await getFileSHA256(proc.path);
      proc.sha256 = hash;

      // Match against local database
      if (hasSignature(hash)) {
        proc.status = 'malicious';
        proc.details = 'Flagged: Hash matches known threat in local database!';
      } else {
        // Run behavioral analysis
        const ioa = analyzeProcessBehavior(proc);
        if (ioa) {
          proc.status = ioa.severity === 'malicious' ? 'malicious' : 'suspicious';
          proc.details = `Behavior Warning: ${ioa.description}`;
        } else {
          proc.status = 'clean';
          proc.details = 'No threat detected (Local signature check)';
        }
      }
    } catch (err) {
      // Locked by OS (typical for core Windows services like csrss.exe)
      proc.status = 'clean';
      proc.details = `Active service (Verify: ${err.code || 'LOCKED'})`;
    }

    scannedList.push(proc);
  }

  return scannedList;
}

/**
 * Terminate a process by PID
 * @param {number} pid 
 */
export function killProcess(pid) {
  return new Promise((resolve, reject) => {
    if (!pid || pid <= 4) return reject(new Error('Invalid PID or system protected process'));
    
    exec(`taskkill /F /PID ${pid}`, (err, stdout, stderr) => {
      if (err) return reject(err);
      resolve(stdout);
    });
  });
}
