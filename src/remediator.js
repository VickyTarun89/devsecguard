import { killDaemonProcesses } from './processKiller.js';
import { cleanSystemPersistence } from './systemPersistCleaner.js';
import { sanitizeIDEPersistence } from './ideSanitizer.js';
import { eradicateMalwareFiles } from './fileEradicator.js';
import path from 'path';

/**
 * Runs the full DevSecGuard remediation sequence.
 * 
 * @param {object} options - Execution configurations.
 * @param {string} options.scanDir - The directory to scan.
 * @param {boolean} options.clean - If true, execute active cleanup; otherwise run audit only.
 * @returns {Promise<{ success: boolean, logs: string[], findings: object }>}
 */
export async function runRemediationSequence(options) {
  const { scanDir = process.cwd(), clean = false } = options;
  const dryRun = !clean;
  
  const logs = [];
  const findings = {
    processes: null,
    systemPersistence: null,
    idePersistence: null,
    files: null
  };

  logs.push(`================================================================`);
  logs.push(` DevSecGuard Remediation Sequence - Started`);
  logs.push(` Workspace Scan Path: ${scanDir}`);
  logs.push(` Execution Mode: ${dryRun ? 'SAFE SCAN & AUDIT (Read-Only)' : 'ACTIVE ERADICATION & CLEANUP'}`);
  logs.push(`================================================================`);

  try {
    // PHASE 1: Kill monitoring processes (THE DEAD-MAN'S SWITCH)
    logs.push('\n[PHASE 1] Terminating active monitoring daemons...');
    findings.processes = await killDaemonProcesses(dryRun);
    logs.push(...findings.processes.logs);

    // PHASE 2: Delete system startup items (Scheduled Tasks / Registry entries)
    logs.push('\n[PHASE 2] Neutralizing system-level persistence...');
    findings.systemPersistence = await cleanSystemPersistence(dryRun);
    logs.push(...findings.systemPersistence.logs);

    // PHASE 3: Sanitize local IDE configurations (tasks.json, settings.json)
    logs.push('\n[PHASE 3] Sanitizing IDE startup hooks...');
    findings.idePersistence = await sanitizeIDEPersistence(scanDir, dryRun);
    logs.push(...findings.idePersistence.logs);

    // PHASE 4: Eradicate malware script and executable payloads
    logs.push('\n[PHASE 4] Removing malware files on disk...');
    findings.files = await eradicateMalwareFiles(scanDir, dryRun);
    logs.push(...findings.files.logs);

    // SUMMARY & CLEARANCE
    logs.push('\n================================================================');
    logs.push(' DevSecGuard Audit Summary');
    logs.push('================================================================');
    
    const threatsDetected = 
      findings.processes.found || 
      findings.systemPersistence.found || 
      findings.idePersistence.found || 
      findings.files.found;

    if (threatsDetected) {
      logs.push(' STATUS: THREATS DETECTED');
      if (dryRun) {
        logs.push(' WARNING: Malicious processes, files, or configurations were found.');
        logs.push('          Do NOT rotate or revoke your tokens yet, as the daemon may still be active.');
        logs.push('          Run with the --clean option to safely eliminate the threat first.');
      } else {
        logs.push(' SUCCESS: Active persistence mechanisms have been neutralized!');
        logs.push('          It is now SAFE to proceed with rotating and revoking your credentials.');
      }
    } else {
      logs.push(' STATUS: NO THREATS DETECTED');
      logs.push('          Your workspace and system show no signs of the Mini Shai-Hulud infection.');
      logs.push('          It is safe to rotate your credentials.');
    }
    
    logs.push('================================================================\n');

    return {
      success: true,
      logs,
      findings
    };
  } catch (err) {
    logs.push(`[FATAL] Remediation aborted due to error: ${err.message}`);
    return {
      success: false,
      logs,
      findings
    };
  }
}

// Support running directly via command line
const isDirectRun = import.meta.url === `file:///${path.resolve(process.argv[1]).replace(/\\/g, '/')}`;

if (isDirectRun) {
  const args = process.argv.slice(2);
  const isClean = args.includes('--clean');
  
  let scanPath = process.cwd();
  const pathIndex = args.indexOf('--path');
  if (pathIndex !== -1 && args[pathIndex + 1]) {
    scanPath = path.resolve(args[pathIndex + 1]);
  }

  runRemediationSequence({ scanDir: scanPath, clean: isClean }).then(res => {
    console.log(res.logs.join('\n'));
    process.exit(res.success ? 0 : 1);
  });
}
