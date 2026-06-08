/**
 * Analyze process execution arguments for Indicators of Attack (IOAs)
 * @param {object} proc - process info object
 * @returns {object|null} IOA details if suspicious/malicious, otherwise null
 */
export function analyzeProcessBehavior(proc) {
  if (!proc || !proc.commandLine) return null;
  
  const cmdLower = proc.commandLine.toLowerCase();
  
  // Rule 1: Ransomware shadow copy deletion
  if ((cmdLower.includes('vssadmin') && cmdLower.includes('delete') && cmdLower.includes('shadows')) ||
      (cmdLower.includes('wmic') && cmdLower.includes('shadowcopy') && cmdLower.includes('delete')) ||
      (cmdLower.includes('shadowcopy') && cmdLower.includes('delete')) ||
      (cmdLower.includes('bcdedit') && cmdLower.includes('recoveryenabled') && cmdLower.includes('no'))) {
    return {
      ioa: 'IOA.Ransomware.ShadowDeletion',
      severity: 'malicious',
      description: 'Suspicious attempt to delete Windows Shadow Copies or disable system recovery (typical ransomware behavior).'
    };
  }
  
  // Rule 2: PowerShell Execution Policy Bypass
  if (cmdLower.includes('powershell') && 
      (cmdLower.includes('bypass') || cmdLower.includes('-ep ') || cmdLower.includes('-exec ') || cmdLower.includes('-encodedcommand') || cmdLower.includes('-enc '))) {
    return {
      ioa: 'IOA.DefenseEvasion.PseBypass',
      severity: 'suspicious',
      description: 'PowerShell execution with bypass flags or encoded payloads (evasion technique).'
    };
  }
  
  // Rule 3: Registry Persistence Hijack
  if (cmdLower.includes('reg') && cmdLower.includes('add') && cmdLower.includes('currentversion\\run')) {
    return {
      ioa: 'IOA.Persistence.RegStartupHijack',
      severity: 'suspicious',
      description: 'Attempt to add auto-start persistence registry keys.'
    };
  }

  // Rule 4: Local System Account Additions
  if (cmdLower.includes('net user') && cmdLower.includes('/add')) {
    return {
      ioa: 'IOA.CredentialAccess.AccountCreation',
      severity: 'suspicious',
      description: 'Local system user account creation detected.'
    };
  }

  return null;
}
