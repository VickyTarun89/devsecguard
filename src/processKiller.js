import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/**
 * Searches for and kills any processes associated with the Mini Shai-Hulud malware.
 * Specifically targets gh-token-monitor, rogue bun instances, or node scripts.
 * 
 * @param {boolean} dryRun - If true, only reports findings without killing processes.
 * @returns {Promise<{ found: boolean, killed: string[], logs: string[] }>}
 */
export async function killDaemonProcesses(dryRun = false) {
  const result = {
    found: false,
    killed: [],
    logs: []
  };

  result.logs.push('[Process Audit] Starting scan for active wiper daemons...');

  // Search query using PowerShell to get processes and command lines
  // We search for processes containing 'gh-token-monitor', 'router_runtime', 'tanstack_runner', or 'setup.mjs' in command line parameters
  const queryCommand = `powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*gh-token-monitor*' -or $_.CommandLine -like '*router_runtime*' -or $_.CommandLine -like '*tanstack_runner*' -or $_.Name -eq 'gh-token-monitor.exe' } | Select-Object ProcessId, Name, CommandLine | ConvertTo-Json"`;

  try {
    const { stdout } = await execAsync(queryCommand);
    if (!stdout || stdout.trim() === '') {
      result.logs.push('[Process Audit] No malicious processes found running.');
      return result;
    }

    let processes = [];
    try {
      const parsed = JSON.parse(stdout);
      processes = Array.isArray(parsed) ? parsed : [parsed];
    } catch (e) {
      // In case of a single output or parsing error, try parsing line by line or fallback
      result.logs.push(`[Process Audit] Error parsing process results: ${e.message}`);
      return result;
    }

    const activeThreats = [];
    for (const proc of processes) {
      const pid = parseInt(proc.ProcessId || proc.processid, 10);
      const name = proc.Name || proc.name;
      const cmdline = proc.CommandLine || proc.commandline || '';

      // Safety check: Never terminate this process, its parents, or active setup scripts, or search queries
      if (
        pid === process.pid || 
        cmdline.includes('remediator.js') || 
        cmdline.includes('server.js') || 
        cmdline.includes('setupSandbox.js') ||
        cmdline.includes('Get-CimInstance') ||
        cmdline.includes('taskkill')
      ) {
        continue;
      }
      activeThreats.push(proc);
    }

    if (activeThreats.length === 0) {
      result.logs.push('[Process Audit] No malicious processes found running.');
      return result;
    }

    result.found = true;
    result.logs.push(`[Process Audit] Found ${activeThreats.length} suspicious process(es).`);

    for (const proc of activeThreats) {
      const pid = parseInt(proc.ProcessId || proc.processid, 10);
      const name = proc.Name || proc.name;
      const cmdline = proc.CommandLine || proc.commandline || '';

      result.logs.push(`[Process Audit] Threat identified - PID: ${pid} | Name: ${name} | Cmd: ${cmdline.substring(0, 100)}...`);

      if (dryRun) {
        result.logs.push(`[Process Audit] [DRY RUN] Would terminate PID ${pid}.`);
        result.killed.push(`PID ${pid} (${name})`);
      } else {
        result.logs.push(`[Process Audit] Terminating PID ${pid} (${name})...`);
        try {
          // Force terminate the process
          await execAsync(`taskkill /F /PID ${pid}`);
          result.logs.push(`[Process Audit] Successfully terminated PID ${pid}.`);
          result.killed.push(`PID ${pid} (${name})`);
        } catch (killErr) {
          result.logs.push(`[Process Audit] [WARNING] Failed to terminate PID ${pid}: ${killErr.message}`);
        }
      }
    }
  } catch (err) {
    // If PowerShell returns exit code 1 or fails (which can happen if no matching processes are found, causing ConvertTo-Json to receive null)
    // We double-check if it's just a null/empty output.
    if (err.message && err.message.includes('ConvertTo-Json')) {
      result.logs.push('[Process Audit] No matching processes found (JSON conversion skipped).');
    } else {
      result.logs.push(`[Process Audit] Failed to query running processes: ${err.message}`);
    }
  }

  return result;
}
