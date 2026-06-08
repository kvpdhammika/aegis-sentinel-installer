# Aegis Sentinel Installer Script
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Requesting Administrator privileges to register Task Scheduler services..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

Clear-Host
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "      AEGIS SENTINEL INSTALLER SYSTEM" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

$defaultPath = Join-Path $env:ProgramFiles "Aegis Sentinel"
Write-Host "Default install directory: $defaultPath"
$targetPath = Read-Host "Press Enter to install to default directory, or enter custom path"
if ([string]::IsNullOrWhiteSpace($targetPath)) {
    $targetPath = $defaultPath
}

Write-Host "Installing to: $targetPath" -ForegroundColor Cyan

if (-not (Test-Path $targetPath)) {
    New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
}

Write-Host "Copying application binaries and runtimes..."
Copy-Item -Path "$PSScriptRoot\*" -Destination $targetPath -Recurse -Force -Exclude "install.ps1","install.bat"

# Create Desktop Shortcut
Write-Host "Creating Desktop Shortcut..."
$WshShell = New-Object -ComObject WScript.Shell
$DesktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
$Shortcut = $WshShell.CreateShortcut(Join-Path $DesktopPath "Aegis Sentinel.lnk")
$Shortcut.TargetPath = Join-Path $targetPath "start-sentinel.vbs"
$Shortcut.WorkingDirectory = $targetPath
$Shortcut.Description = "Launch Aegis Sentinel Cyber Sentry"
$Shortcut.IconLocation = "shell32.dll,220" # Shield icon
$Shortcut.Save()

# Register Task Scheduler Task (Auto-launch on startup/logon)
Write-Host "Registering Background Sentry Daemon in Task Scheduler..."
$taskName = "AegisSentinelSentry"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$targetPath\start-sentinel.vbs`"" -WorkingDirectory $targetPath
# Register task to run with active elevated privileges
Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -RunLevel Highest -Force | Out-Null

# Start the application immediately
Write-Host "Starting Aegis Sentinel..." -ForegroundColor Green
$WshShell.Run("`"$targetPath\start-sentinel.vbs`"", 0)

# Open Dashboard
Start-Sleep -Seconds 2
Start-Process "http://localhost:3000"

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "    AEGIS SENTINEL INSTALLED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "The application is running in the background."
Write-Host "Open http://localhost:3000 in your browser at any time."
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")