# Privacy Guarantee: DevSecGuard

DevSecGuard is designed with a **Zero-Exfiltration, local-first** privacy model. As a developer security tool, it handles highly sensitive details (such as identifying exposed API keys and scanning local IDE settings). This document outlines the guarantees of this architecture.

## 1. 100% Local Execution
* All scanning, file auditing, and process termination are executed locally on your workstation.
* There is no backend server hosted by the creators of DevSecGuard. There are no remote database connections.
* The local dashboard runs on an ephemeral port (default `8422`) and binds exclusively to loopback interface `127.0.0.1` (localhost). It cannot be reached by other computers on your network.

## 2. Zero Network Activity
* DevSecGuard does not perform any external network requests.
* There are no check-in calls, analytics reporting, telemetry collections, or crash reporting to external APIs.
* You can run DevSecGuard completely disconnected from the Internet.

## 3. Safe Secret Scanning
* **No Extraction:** When the scanner detects exposed credentials (like AWS keys, OpenAI keys, or GitHub PATs), it identifies their presence, file path, and line number to warn you.
* **No Storage:** DevSecGuard does not store, write, or cache your actual credentials to any file, log database, or config. The tokens are only matched in-memory during the scan and are discarded immediately.
* **No Telemetry:** Stolen or found keys are never sent anywhere.

## 4. No Dependencies (`Zero Trust` Dependency Stack)
* Traditional security tools pull down hundreds of transitive dependencies (e.g. via npm), which creates a secondary supply chain risk.
* DevSecGuard uses **zero npm dependencies**. The package.json lists `dependencies: {}`. 
* It is written entirely in native Javascript modules and runs directly on the Node.js standard runtime. You can audit the entire codebase in less than 15 minutes.
