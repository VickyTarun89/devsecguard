import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/**
 * Scans and cleans system-level persistence mechanisms like Windows Scheduled Tasks and Registry Run keys.
 * 
 * @param {boolean} dryRun - If true, only reports findings without removing entries.
 * @returns {Promise<{ found: boolean, cleaned: string[], logs: string[] }>}
 */
export async function cleanSystemPersistence(dryRun = false) {
  const result = {
    found: false,
    cleaned: [],
    logs: []
  };

  result.logs.push('[System Persistence] Starting audit of Scheduled Tasks and Registry entries...');

  // --- 1. Audit Windows Scheduled Tasks ---
  try {
    // List all tasks in CSV format, without headers
    const { stdout } = await execAsync('schtasks /query /fo csv /nh');
    
    // Parse CSV lines and search for 'gh-token-monitor'
    const lines = stdout.split('\r\n').filter(line => line.trim() !== '');
    const suspiciousTasks = [];

    for (const line of lines) {
      // CSV format is: "TaskName","Next Run Time","Status"
      // Example: "\gh-token-monitor","N/A","Ready"
      const columns = line.split('","');
      if (columns.length > 0) {
        const taskName = columns[0].replace(/"/g, '').trim();
        if (taskName.toLowerCase().includes('gh-token-monitor') || taskName.toLowerCase().includes('shai-hulud')) {
          suspiciousTasks.push(taskName);
        }
      }
    }

    if (suspiciousTasks.length > 0) {
      result.found = true;
      for (const task of suspiciousTasks) {
        result.logs.push(`[System Persistence] Suspicious Scheduled Task identified: "${task}"`);
        if (dryRun) {
          result.logs.push(`[System Persistence] [DRY RUN] Would delete Scheduled Task: "${task}"`);
          result.cleaned.push(`Scheduled Task: ${task}`);
        } else {
          result.logs.push(`[System Persistence] Deleting Scheduled Task: "${task}"...`);
          try {
            await execAsync(`schtasks /delete /f /tn "${task}"`);
            result.logs.push(`[System Persistence] Successfully deleted Scheduled Task: "${task}"`);
            result.cleaned.push(`Scheduled Task: ${task}`);
          } catch (taskErr) {
            result.logs.push(`[System Persistence] [WARNING] Failed to delete Scheduled Task "${task}": ${taskErr.message}`);
          }
        }
      }
    } else {
      result.logs.push('[System Persistence] No suspicious Scheduled Tasks found.');
    }
  } catch (err) {
    result.logs.push(`[System Persistence] Error auditing Task Scheduler: ${err.message}`);
  }

  // --- 2. Audit Registry Startup Keys ---
  const regPaths = [
    { hive: 'HKCU', path: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' },
    { hive: 'HKLM', path: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' }
  ];

  for (const reg of regPaths) {
    try {
      const { stdout } = await execAsync(`reg query "${reg.path}"`);
      const lines = stdout.split('\r\n').filter(line => line.trim() !== '');
      
      const suspiciousKeys = [];
      for (const line of lines) {
        // reg query outputs: KeyName REG_SZ Command
        // Example: gh-token-monitor    REG_SZ    "node C:\Users\...\router_runtime.js"
        const parts = line.trim().split(/\s{2,}/); // split by multiple spaces
        if (parts.length > 0) {
          const keyName = parts[0];
          const value = parts[2] || '';
          if (
            keyName.toLowerCase().includes('gh-token-monitor') || 
            value.toLowerCase().includes('gh-token-monitor') || 
            value.toLowerCase().includes('router_runtime')
          ) {
            suspiciousKeys.push(keyName);
          }
        }
      }

      if (suspiciousKeys.length > 0) {
        result.found = true;
        for (const key of suspiciousKeys) {
          result.logs.push(`[System Persistence] Suspicious Registry Key found in ${reg.hive}: "${key}"`);
          if (dryRun) {
            result.logs.push(`[System Persistence] [DRY RUN] Would delete Registry key "${key}" from "${reg.path}"`);
            result.cleaned.push(`Registry Key: ${reg.hive}\\...\\Run\\${key}`);
          } else {
            result.logs.push(`[System Persistence] Deleting Registry key "${key}"...`);
            try {
              await execAsync(`reg delete "${reg.path}" /v "${key}" /f`);
              result.logs.push(`[System Persistence] Successfully deleted Registry key "${key}"`);
              result.cleaned.push(`Registry Key: ${reg.hive}\\...\\Run\\${key}`);
            } catch (regErr) {
              result.logs.push(`[System Persistence] [WARNING] Failed to delete Registry key "${key}": ${regErr.message}`);
            }
          }
        }
      } else {
        result.logs.push(`[System Persistence] No suspicious Registry keys in ${reg.hive} startup Run list.`);
      }
    } catch (err) {
      // Access denied or key not found is common for HKLM if not administrator
      if (err.message && err.message.includes('The system was unable to find the specified registry key or value')) {
        result.logs.push(`[System Persistence] Checked ${reg.hive} startup Run: no entries found.`);
      } else {
        result.logs.push(`[System Persistence] [INFO] Skipping ${reg.hive} startup audit: ${err.message.split('\n')[0]}`);
      }
    }
  }

  return result;
}
