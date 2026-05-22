import fs from 'fs';
import path from 'path';
import os from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/**
 * Searches directories for a list of malware files and tries to delete them.
 * Handles unlocking read-only/system file attributes.
 * 
 * @param {string} scanDir - The project workspace directory to scan.
 * @param {boolean} dryRun - If true, only reports findings without deleting files.
 * @returns {Promise<{ found: boolean, deleted: string[], logs: string[] }>}
 */
export async function eradicateMalwareFiles(scanDir, dryRun = false) {
  const result = {
    found: false,
    deleted: [],
    logs: []
  };

  const suspiciousNames = [
    'router_init.js',
    'router_runtime.js',
    'setup.mjs',
    'tanstack_runner.js',
    'gh-token-monitor',
    'gh-token-monitor.exe'
  ];

  result.logs.push('[File Scan] Checking directories for malicious artifacts...');

  // Paths to search
  const searchDirs = [scanDir];

  // Include Windows Temp folders
  const tempDir = process.env.TEMP || process.env.TMP || os.tmpdir();
  if (tempDir) {
    result.logs.push(`[File Scan] Including system temp directory: ${tempDir}`);
    searchDirs.push(tempDir);
  }

  // Scan directories for matching file names
  const filesToDelete = [];

  for (const dir of searchDirs) {
    try {
      if (!fs.existsSync(dir)) continue;
      const list = fs.readdirSync(dir);
      for (const item of list) {
        const itemPath = path.join(dir, item);
        let stat;
        try {
          stat = fs.statSync(itemPath);
        } catch (e) {
          continue; // Inaccessible file
        }

        if (stat && stat.isFile()) {
          const lowerName = item.toLowerCase();
          const matchesMalwareName = suspiciousNames.includes(lowerName);
          
          // Also look for bun.exe inside the temp directory (malware installs local bun to run its monitoring scripts)
          const isRogueBun = (dir === tempDir && lowerName === 'bun.exe');

          if (matchesMalwareName || isRogueBun) {
            filesToDelete.push(itemPath);
          }
        }
      }
    } catch (err) {
      result.logs.push(`[File Scan] Error checking directory "${dir}": ${err.message}`);
    }
  }

  if (filesToDelete.length === 0) {
    result.logs.push('[File Scan] No malicious file payloads detected.');
    return result;
  }

  result.found = true;
  result.logs.push(`[File Scan] Detected ${filesToDelete.length} malicious file payload(s).`);

  for (const filePath of filesToDelete) {
    result.logs.push(`[File Scan] Malware payload found: "${filePath}"`);
    
    if (dryRun) {
      result.logs.push(`[File Scan] [DRY RUN] Would delete file: "${filePath}"`);
      result.deleted.push(filePath);
    } else {
      result.logs.push(`[File Scan] Eradicating file "${filePath}"...`);
      
      try {
        // Step 1: Unlock file attributes using Windows shell
        try {
          result.logs.push(`[File Scan] Stripping system, hidden, and read-only attributes from "${filePath}"`);
          // Windows attrib command removes: -r (read-only), -s (system file), -h (hidden)
          await execAsync(`attrib -r -s -h "${filePath}"`);
        } catch (attribErr) {
          result.logs.push(`[File Scan] Attrib unlock note: ${attribErr.message.split('\n')[0]}`);
        }

        // Step 2: Set Node permissions to read-write
        try {
          fs.chmodSync(filePath, 0o666);
        } catch (chmodErr) {
          result.logs.push(`[File Scan] Chmod permission update note: ${chmodErr.message}`);
        }

        // Step 3: Unlink (delete) the file
        fs.unlinkSync(filePath);
        result.logs.push(`[File Scan] Successfully deleted: "${filePath}"`);
        result.deleted.push(filePath);
      } catch (delErr) {
        result.logs.push(`[File Scan] [ERROR] Failed to delete "${filePath}": ${delErr.message}`);
      }
    }
  }

  return result;
}
