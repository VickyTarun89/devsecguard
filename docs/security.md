# Security & Self-Defense Measures: DevSecGuard

## 1. Remediation Sequencing (Preventing the Wiper)
The most critical security feature of DevSecGuard is its **sequenced execution plan**. The Mini Shai-Hulud malware contains a dead-man's switch daemon (`gh-token-monitor`) that polls the GitHub API. If it receives a `401 Unauthorized` response (which happens when you revoke the token), it triggers a destructive wiper command.

To defeat this, DevSecGuard enforces the following sequence:

```
[System Infected]
       |
       v
1. Force Terminate Daemon Processes (Kill gh-token-monitor, node/bun monitoring subprocesses)
       |
       v
2. Delete System Persistence (Delete Scheduled Tasks, Registry Run Keys)
       |
       v
3. Sanitize IDE Settings (Clean VS Code tasks.json and Claude Code settings.json)
       |
       v
4. Eradicate File Artifacts (Unlock file attributes, delete malicious scripts & bin files)
       |
       v
[System Disarmed & Safe]
       |
       v
5. Rotate/Revoke Compromised Credentials (Tokens, API Keys, SSH keys)
```

By completing steps 1 through 4 *before* step 5, the wiper mechanism is entirely neutralized before the token becomes invalid.

## 2. Windows 11 Permission Management
The malware attempts to protect its payload files from deletion by marking them with System, Hidden, and Read-Only attributes, or by locking file handles.

* **Attribute Stripping:** Before deleting files, the remediator runs Windows-native command shell instructions:
  `attrib -r -s -h <filepath>`
  This strips Read-Only (`-r`), System (`-s`), and Hidden (`-h`) flags.
* **Process Handle Release:** By killing any active Node/Bun processes first, any locked file handles on the malware payloads are released, allowing standard file deletion to succeed.

## 3. Detecting Evasion Tactics
Malware authors may attempt to bypass detections by renaming files or executing under standard system process names. To combat this:
* **Deep Command-Line Parsing:** Instead of looking only for a process named `gh-token-monitor.exe`, we query the full execution command-line of all `node.exe` and `bun.exe` processes. If a process was launched with arguments referencing `router_runtime`, `setup.mjs`, or key-monitoring strings, it is flagged and killed.
* **VS Code Task Heuristics:** We do not just look for a specific task name. We scan the entire `tasks.json` structure looking for tasks configured with `"runOn": "folderOpen"` that invoke shell scripts or binaries, downloading scripts, or launching payloads.
* **Scheduled Task Querying:** We perform wildcard searches on active scheduled tasks on Windows to find background tasks running in user profiles or temp directories.
