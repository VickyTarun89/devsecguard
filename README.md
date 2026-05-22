# DevSecGuard 🛡️

DevSecGuard is a **100% local, zero-dependency, open-source security tool** designed for Windows 11. It protects developers from supply-chain malware like **"Mini Shai-Hulud"**, which injects persistent execution hooks into developer workspaces and features a dead-man's switch wiper.

## ⚠️ CRITICAL SAFETY WARNING
**DO NOT REVOKE ANY COMPROMISED GITHUB OR NPM TOKENS YET.**
The malware installs a local background daemon process (`gh-token-monitor`) that checks if your credentials are valid. If you revoke the token, the daemon receives a `401 Unauthorized` and immediately triggers a wiper command (such as deleting all files in your user home directory).

You **must** run DevSecGuard's **Active Eradication** phase first to terminate the daemon and delete all startup/persistence hooks before you rotate your API tokens.

---

## Features
1. **Wiper Daemon Termination:** Instantly searches for and kills running processes associated with `gh-token-monitor`, unauthorized `bun.exe` scripts, or node-monitoring daemons.
2. **System Persistence Cleaning:** Scans and removes registry Run keys and Windows Scheduled Tasks named `gh-token-monitor`.
3. **IDE Settings Sanitization:** Parses and cleans auto-run hooks from `.vscode/tasks.json` (auto-run tasks on `folderOpen`) and Claude Code configuration settings (`.claude/settings.json`, `~/.claude.json`).
4. **File Eradication:** Automatically removes hidden/system/read-only locks and deletes malware payloads (`router_init.js`, `router_runtime.js`, `setup.mjs`, `tanstack_runner.js`) from workspace and temp directories.
5. **Clearance Signal:** Generates a secure signal letting you know when it is 100% safe to proceed with credential rotation.
6. **Zero Dependencies:** Written in pure, native Node.js. No nested dependencies to inspect, guaranteeing zero supply-chain risk from this tool itself.

---

## Installation & Running

### Prerequisites
* Node.js (version 16 or later recommended)
* Windows 11 (running in a standard shell or PowerShell terminal)

### 1. Command Line Interface (CLI)

* **Run a Safe Audit (Dry Run / Read-Only):**
  This scans the current directory and system temp folders, listing what would be cleaned without modifying any files or stopping any processes.
  ```bash
  node src/remediator.js --dry-run
  ```
  Or to scan a specific folder:
  ```bash
  node src/remediator.js --dry-run --path "C:\path\to\your\project"
  ```

* **Run Active Eradication (Cleanup Mode):**
  This terminates the wiper daemon processes, deletes persistence registry keys/scheduled tasks, cleans config hooks, and deletes the payload files.
  ```bash
  node src/remediator.js --clean
  ```
  Or for a specific folder:
  ```bash
  node src/remediator.js --clean --path "C:\path\to\your\project"
  ```

### 2. Interactive Local Dashboard

Launch the dashboard server locally:
```bash
node src/server.js
```
Then, open your browser and navigate to:
[http://127.0.0.1:8422](http://127.0.0.1:8422)

From the dashboard, you can paste in workspace paths, run audits, view real-time log consoles, and execute eradication.

---

## Verification Sandbox
We have provided a safe test script in `test/setupSandbox.js` that populates a mock directory with dummy malware files, an auto-running VS Code task, and a Claude Code setting hook.

1. Set up the sandbox:
   ```bash
   node test/setupSandbox.js
   ```
2. Scan the sandbox in dry-run mode to see it detect the threat:
   ```bash
   node src/remediator.js --dry-run --path test-sandbox
   ```
3. Run eradication on the sandbox to clean it up:
   ```bash
   node src/remediator.js --clean --path test-sandbox
   ```
4. Verify that a follow-up scan detects 0 threats:
   ```bash
   node src/remediator.js --dry-run --path test-sandbox
   ```

---

## License
MIT License - Free and Open Source. Use at your own risk.
