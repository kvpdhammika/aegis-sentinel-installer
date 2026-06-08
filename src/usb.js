import { spawn } from 'child_process';

let usbProcess = null;

/**
 * Start background USB insertion monitoring.
 * @param {object} config - app config settings
 * @param {Function} logCallback - logs messages to UI
 * @param {Function} scanTriggerCallback - callback to start scan on a directory
 */
export function startUSBMonitor(config, logCallback, scanTriggerCallback) {
  if (usbProcess) {
    return; // Already running
  }

  // PowerShell query to watch Win32_VolumeChangeEvent EventType = 2 (Arrival)
  const psCommand = `
    $query = "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2"
    $watcher = New-Object System.Management.ManagementEventWatcher($query)
    Write-Host "USB_MONITOR_ACTIVE"
    while ($true) {
        try {
            $event = $watcher.WaitForNextEvent()
            $driveLetter = $event.DriveName
            if ($driveLetter) {
                $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$driveLetter'"
                if ($drive.DriveType -eq 2) {
                    Write-Host "USB_INSERTED:$driveLetter"
                }
            }
        } catch {
            Start-Sleep -Seconds 2
        }
    }
  `;

  console.log('[USB Monitor] Launching WMI USB event listener in PowerShell...');
  
  usbProcess = spawn('powershell', ['-NoProfile', '-Command', psCommand]);

  usbProcess.stdout.on('data', (data) => {
    const lines = data.toString().split(/\r?\n/);
    for (const line of lines) {
      const cleanLine = line.trim();
      if (!cleanLine) continue;

      if (cleanLine === 'USB_MONITOR_ACTIVE') {
        logCallback('USB Auto-Scan Monitor is active and listening for insertions.', 'success');
      } else if (cleanLine.startsWith('USB_INSERTED:')) {
        const driveLetter = cleanLine.split(':')[1] + ':';
        logCallback(`Detected USB device connected at drive letter: ${driveLetter}`, 'warning');
        
        if (config.usbAutoScan !== false) {
          logCallback(`Starting automatic threat scan on USB drive: ${driveLetter}\\`, 'info');
          scanTriggerCallback(driveLetter + '\\');
        } else {
          logCallback(`USB Auto-Scan is disabled in settings. Skipping scan for drive ${driveLetter}`, 'info');
        }
      }
    }
  });

  usbProcess.stderr.on('data', (data) => {
    console.error('[USB Monitor] PowerShell Error:', data.toString());
  });

  usbProcess.on('close', (code) => {
    console.log(`[USB Monitor] PowerShell listener exited with code ${code}`);
    usbProcess = null;
  });
}

/**
 * Stop background USB insertion monitoring.
 */
export function stopUSBMonitor() {
  if (usbProcess) {
    usbProcess.kill();
    usbProcess = null;
    console.log('[USB Monitor] USB event listener stopped.');
  }
}
