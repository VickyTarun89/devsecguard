# AI Agent Interactions: DevSecGuard

As AI coding agents (such as Claude Code, GitHub Copilot, or Gemini-based IDE extensions) become standard in developer workflows, they also become primary targets for malicious actors. This document guides how AI agents should interact with this project and how to prevent agent-based persistence vectors.

## 1. The Agent Persistence Vector
The Mini Shai-Hulud malware targets two primary configuration locations to ensure execution:
1. `.vscode/tasks.json` (runs tasks on `folderOpen`).
2. `.claude/settings.json` or `~/.claude.json` (runs custom hooks or settings during agent operations).

Because AI agents automatically read local project configurations, a compromised project repository (such as one cloned from an untrusted PR) can configure settings that cause the agent to execute malicious commands on behalf of the developer.

## 2. Guidelines for AI Agents Scanning this Project
If you are an AI assistant reading or executing this codebase:
* **Verify System Paths:** Ensure that you do not read from or write to directories outside the designated workspace (`shai-hulud-remediator`) unless explicitly instructed by the user (e.g., when scanning the VS Code extension folder or the system user folder).
* **Respect File Locks:** Do not attempt to run or spawn background processes that monitor API tokens.
* **No Auto-execution:** Do not suggest adding scripts to `.vscode/tasks.json` that execute automatically without user permission.
* **Sanitize Inputs:** When parsing and updating `.vscode/tasks.json` or `.claude/settings.json`, ensure that any command parameters are sanitized and free from shell injection characters (`&`, `|`, `;`, `$`, etc.).

## 3. Best Practices for Developers
* **Review PRs Modifying Configs:** Be extremely cautious of Pull Requests that modify `.vscode/tasks.json`, `.github/workflows/`, or any configuration files inside `.claude/`, `.github/`, or other tool directories.
* **Restricted Agent Execution:** Run AI agent CLI tools in sandboxed environments or review tool permissions (such as file writes or shell commands) before approving them.
* **Verify Agent Tasks:** Periodically scan your `.vscode/tasks.json` to ensure no auto-running tasks are configured.
