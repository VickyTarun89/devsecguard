# Product Requirements Document (PRD): DevSecGuard

## 1. Overview
DevSecGuard is a lightweight, 100% local, zero-dependency utility designed to protect developer workstations on Windows 11 from the **Mini Shai-Hulud** supply chain malware and related developer environment persistence threats.

## 2. Problem Statement
The "Mini Shai-Hulud" malware compromises developer workstations by:
1. Running a background process (`gh-token-monitor`) that acts as a dead-man's switch. If the user revokes their compromised tokens, the process wipes their home directory.
2. Establishing persistent execution hooks in `.vscode/tasks.json` (auto-run on project open) and `.claude/settings.json` / `~/.claude.json`.
3. Dropping hidden payloads (like `router_runtime.js`, `setup.mjs`, and malicious `bun` binaries) in temp directories.
4. Protecting its files from easy deletion using Windows file-attribute permissions.

Standard security solutions often fail to handle the precise sequencing required (terminating the daemon *before* token revocation) and developers hesitate to run closed-source security utilities that require high file permissions.

## 3. Product Goals
* **Zero Trust Supply Chain:** The utility itself must have **zero external npm dependencies** to ensure it cannot be compromised.
* **100% Local & Private:** No telemetry, tracking, or outbound network calls.
* **Safety First Sequence:** Enforce that background processes are neutralized before credentials are mutated.
* **Erase Persistence:** Completely clean out VS Code and Claude Code auto-start hooks.
* **Ease of Use:** Provide both a simple CLI (with dry-run/simulation capability) and a premium, locally served visual dashboard.

## 4. Key Features & Requirements

### Feature 1: Process and Service Neutralization (Daemon Killer)
* **Requirement 1.1:** Query running system processes for matches to `gh-token-monitor`, `bun.exe` executing unauthorized scripts, or node processes with arguments containing `router_runtime` or `gh-token-monitor`.
* **Requirement 1.2:** Forcefully terminate these processes immediately.
* **Requirement 1.3:** Query and delete Windows Scheduled Tasks named `gh-token-monitor` or related targets.
* **Requirement 1.4:** Inspect Windows Registry Run keys (HKCU and HKLM) for startup items pointing to these payloads and delete them.

### Feature 2: IDE Configurations Sanitizer
* **Requirement 2.1:** Scan project folders recursively for `.vscode/tasks.json` and examine tasks with `"runOn": "folderOpen"`. If they execute suspicious Node/Bun commands, download scripts, or launch payloads, sanitize the task or disable the auto-run setting.
* **Requirement 2.2:** Scan user directory and workspace directories for `.claude.json` and `.claude/settings.json`. Sanitize any startup hook fields or hooks executing malicious modules.

### Feature 3: File System Eradicator
* **Requirement 3.1:** Locate and remove file payloads (`router_init.js`, `router_runtime.js`, `setup.mjs`, `tanstack_runner.js`) from target workspaces and `%TEMP%`/`%TMP%`.
* **Requirement 3.2:** Detect if files are marked as read-only or system-protected. Automatically remove these flags (using native file permissions commands) and delete the files.

### Feature 4: Command-Line Interface (CLI)
* **Requirement 4.1:** Core mode `node src/remediator.js --dry-run` to output scan results without making changes.
* **Requirement 4.2:** Active remediation mode `node src/remediator.js --clean` to execute the sequential cleanup.

### Feature 5: Local Web Dashboard
* **Requirement 5.1:** Native Node.js web server (`node src/server.js`) that runs locally on an ephemeral port.
* **Requirement 5.2:** Premium, highly visual dashboard (HTML/CSS) to visualize threat levels, toggle git hooks, run scans, and view logs in real-time.
