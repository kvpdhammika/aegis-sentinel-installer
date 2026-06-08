# 🛡️ Aegis Sentinel - Endpoint Detection & Response (EDR) System

Aegis Sentinel is a premium, real-time local Endpoint Detection and Response (EDR) agent and web-based security console for Windows environments. It features automated threat intelligence lookups, real-time filesystem monitoring, memory process sentry, custom YARA-like heuristic rule matching, a DNS sinkhole, forensics logs, and ransomware rollback vaults.

Developed for the **Defence Cyber Command**, Aegis Sentinel is designed to run as a silent background daemon that automatically secures your system and streams telemetry directly to a modern, animated web dashboard.

---

## 🚀 Key Features

| Subsystem | Functionality | Technical Approach |
| :--- | :--- | :--- |
| **🔍 Manual File Scanner** | On-demand recursive scanning of logical drives (C:\ to Z:\). | Streams file chunks to compute SHA-256; cross-references local DB, MalwareBazaar, and VirusTotal. |
| **🛡️ Real-Time Shield** | Instantly intercept filesystem modifications and creations. | Uses `chokidar` directory watchdogs to run real-time file hashes and auto-quarantine threats. |
| **🧠 Heuristics Engine** | Detect packed, encrypted, or obfuscated payloads (e.g. ransomware). | Computes **Shannon Entropy** on executable binaries. Flagged if entropy exceeds a `7.3/8.0` threshold. |
| **💻 Process Sentry** | Detect active in-memory threats and terminate malicious processes. | Walks active processes, computes parent binary hashes, and analyzes execution args for Indicators of Attack (IOAs). |
| **🎯 Rules Center** | Heuristic match signatures using compiled pattern tables. | Runs multi-pattern matching (text/hex) and parses/merges community YARA rules (e.g. APT1, APT15, Stuxnet). |
| **🌐 Hosts Sentry** | Outbound Command & Control (C2) request sinkholing. | Fetches URLhaus malicious domain lists and updates the Windows system `hosts` file to block DNS resolution. |
| **📋 Forensics Sentry** | Auditable security incident logging. | Chronological JSON event logging containing timestamps, subsystem source, severity, and forensic metadata. |
| **⏪ Rollback Vault** | Ransomware mitigation & file recovery. | Backs up verified clean files *before* they are altered, offering instant reverting back to a clean state. |
| **⚙️ Stealth Daemon** | Persistent, silent background Windows service. | Launches via WScript host using Windows Task Scheduler at logon with elevated (`Highest`) privileges. |

---

## 📁 Repository Structure

```
aegis-sentinel-installer/
├── public/                 # Web Dashboard Frontend assets
│   ├── css/style.css       # Premium custom HSL CSS styling
│   ├── img/dcc_logo.png    # Brand Assets (Defence Cyber Command)
│   ├── js/app.js           # Frontend client dashboard logic
│   └── index.html          # Web-based Threat Center UI
├── src/                    # EDR Subsystem Backend modules
│   ├── behavioral.js       # process Indicators of Attack (IOA) rule rulesets
│   ├── db.js               # Local SHA-256 malware signatures database manager
│   ├── forensics.js        # Forensic incident timeline recorder
│   ├── heuristics.js       # Shannon Entropy and PE header calculators
│   ├── hosts.js            # DNS blocklist applier (hosts file manager)
│   ├── processes.js        # Memory walker and PID terminator
│   ├── rollback.js         # Ransomware backup vault and restorer
│   ├── scanner.js          # On-demand scanner & quarantine orchestrator
│   ├── updater.js          # MalwareBazaar signature synchronizer
│   ├── usb.js              # Removable drive auto-scan detector
│   ├── watcher.js          # real-time shield watcher (chokidar helper)
│   └── yara.js             # custom pattern matching / YARA translator
├── runtime/                # Node runtime dependencies
│   └── node.exe            # Packaged lightweight node binary (for offline use)
├── config.json             # Application settings file
├── rules.json              # Custom YARA rules signature file
├── server.js               # Core Express server & SSE events emitter
├── install.ps1             # PowerShell installer script (registers tasks, shortcuts)
├── install.bat             # Helper batch script to bypass execution policies
├── start.bat               # Starts node web console
└── start-sentinel.vbs      # VBScript helper to launch start.bat silently
```

---

## 🔧 Installation & Setup

Aegis Sentinel is designed to install seamlessly on Windows systems with full background persistence.

### Option A: Standard Automated Installer (Recommended)
1. Right-click **`install.bat`** and select **Run as Administrator**.
2. The installer will:
   - Copy binaries to your Program Files (`C:\Program Files\Aegis Sentinel`).
   - Register the `AegisSentinelSentry` Task Scheduler task to start automatically at logon with highest privileges.
   - Create a desktop shortcut with a secure shield icon.
   - Launch the background daemon and open the dashboard in your web browser.

### Option B: Manual Execution
If you prefer to run it manually in a developer environment:
1. Initialize dependencies:
   ```bash
   npm install
   ```
2. Start the Express server:
   ```bash
   npm start
   ```
3. Open your browser and navigate to `http://localhost:3000`.

---

## ⚙️ Configuration (`config.json`)

Key settings are stored in `config.json` at the root of the install directory. These can also be configured dynamically from the **Configurations** tab in the dashboard.

```json
{
  "virusTotalApiKey": "YOUR_VIRUSTOTAL_API_KEY",
  "threatFoxApiKey": "YOUR_THREATFOX_API_KEY",
  "onlineLookupEnabled": true,
  "virusTotalEnabled": false,
  "autoQuarantine": true,
  "monitoredFolder": "E:\\anti\\monitored",
  "quarantineFolder": "E:\\anti\\quarantine",
  "shieldActive": true,
  "usbAutoScan": true
}
```

* **`monitoredFolder`**: The target folder monitored by the Real-Time Shield.
* **`quarantineFolder`**: The folder where malicious files are isolated and neutralized (renamed with `.quarantined` suffix).
* **`autoQuarantine`**: If enabled, any file flagged as malicious during manual scan or real-time monitoring will immediately be neutralized.
* **`usbAutoScan`**: If enabled, any newly connected USB drive will trigger an automatic background scan.

---

## 🧠 Core EDR Heuristics & Analysis Details

### 1. File Entropy Calculations
Obfuscated, packed, or encrypted executable binaries often indicate active ransomware or crypter wrappers. Aegis Sentinel measures **Shannon Entropy** ($H$) using the byte distribution of files under 15MB:
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
Where $P(x_i)$ is the probability of occurrence of byte value $x_i$.
* **Entropy > 7.3**: Flagged as a suspicious high-entropy executable.

### 2. Behavioral Indicators of Attack (IOAs)
The **Process Sentry** analyzes the command line arguments of executing programs to intercept common attack methods:
* **Shadow Copy Deletion**: Intercepts `vssadmin delete shadows`, `wmic shadowcopy delete`, or `bcdedit` command lines.
* **Defense Evasion**: Catches PowerShell running with `-ExecutionPolicy Bypass`, `-EncodedCommand`, or `-enc`.
* **Registry Persistence**: Detects attempts to write to `CurrentVersion\Run` key registry parameters.
* **Credential Access**: Alerts on local user account creations via `net user /add`.

### 3. DNS Sinkholing
The **Hosts Sentry** appends thousands of known malicious command and control (C2) domains mapping to `127.0.0.1`. Outbound network attempts to contact these hosts are blocked locally, breaking the malware's communication path.

---

## 🌐 REST API Reference

Aegis Sentinel provides a REST API to facilitate EDR automation and integration with other systems.

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/status` | `GET` | Returns system configurations, scanner states, database stats, and watcher status. |
| `/api/config` | `POST` | Dynamically updates system configurations (e.g. paths, API keys, state toggles). |
| `/api/update-db` | `POST` | Triggers a background sync with MalwareBazaar and streams logs via SSE. |
| `/api/clear-db` | `POST` | Empties the local signature database from disk and memory. |
| `/api/scan` | `POST` | Starts a manual scan on a path (pass `path: "ALL_DRIVES"` for full drives scan). |
| `/api/scan/control` | `POST` | Action controls active scans (options: `pause`, `resume`, `cancel`). |
| `/api/quarantine` | `GET` | Fetches the quarantine registry list from `quarantine_registry.json`. |
| `/api/quarantine/restore`| `POST` | Restores a quarantined file by ID back to its original location. |
| `/api/processes` | `GET` | Scans currently executing memory processes and checks binary hashes. |
| `/api/processes/kill` | `POST` | Kills a running process by its PID. |
| `/api/rules/sync` | `POST` | Synchronizes community YARA rules (e.g. APT1, Stuxnet) from GitHub. |
| `/api/hosts/apply` | `POST` | Appends downloaded URLhaus blocklists to the Windows system hosts file. |
| `/api/rollback` | `GET` | Retrieves the list of files currently backed up in the rollback vault. |
| `/api/events` | `GET` | Server-Sent Events (SSE) stream path for real-time dashboard telemetry. |

---

## 🛡️ License

Developed by KVP Dhammika. All Rights Reserved.
