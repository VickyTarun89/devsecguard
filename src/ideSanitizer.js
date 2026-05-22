import fs from 'fs';
import path from 'path';
import os from 'os';

/**
 * Recursively searches for files matching a list of filenames in a directory.
 * Ignores node_modules, .git, and common binary directories.
 * 
 * @param {string} dir - The directory to scan.
 * @param {string[]} filenames - The filenames to search for.
 * @returns {string[]} - Array of matching absolute file paths.
 */
function findConfigFiles(dir, filenames) {
  let results = [];
  let list;
  try {
    list = fs.readdirSync(dir);
  } catch (err) {
    return results; // Access denied or directory doesn't exist
  }

  for (const file of list) {
    const filePath = path.join(dir, file);
    let stat;
    try {
      stat = fs.statSync(filePath);
    } catch (e) {
      continue; // Skip broken symlinks or inaccessible files
    }

    if (stat && stat.isDirectory()) {
      const base = path.basename(filePath).toLowerCase();
      // Skip heavy or system folders to save CPU time
      if (base !== 'node_modules' && base !== '.git' && base !== 'dist' && base !== 'build' && base !== 'appdata' && base !== 'local settings') {
        results = results.concat(findConfigFiles(filePath, filenames));
      }
    } else {
      if (filenames.includes(path.basename(filePath).toLowerCase())) {
        results.push(filePath);
      }
    }
  }
  return results;
}

/**
 * Scans and cleans VS Code and Claude Code configuration settings.
 * 
 * @param {string} scanDir - The project workspace directory to scan.
 * @param {boolean} dryRun - If true, only reports findings without writing modifications.
 * @returns {Promise<{ found: boolean, cleaned: string[], logs: string[] }>}
 */
export async function sanitizeIDEPersistence(scanDir, dryRun = false) {
  const result = {
    found: false,
    cleaned: [],
    logs: []
  };

  result.logs.push(`[IDE Audit] Starting scan for configuration persistence hooks in: ${scanDir}`);

  // Find all tasks.json and settings.json files in target workspace
  const targets = findConfigFiles(scanDir, ['tasks.json', 'settings.json']);
  
  // Also check user home directory for global Claude Code settings
  const userHome = os.homedir();
  const globalClaudeConfig = path.join(userHome, '.claude.json');
  if (fs.existsSync(globalClaudeConfig)) {
    result.logs.push(`[IDE Audit] Found global Claude Code config: ${globalClaudeConfig}`);
    targets.push(globalClaudeConfig);
  }

  if (targets.length === 0) {
    result.logs.push('[IDE Audit] No configuration files found in the scan path.');
    return result;
  }

  for (const filePath of targets) {
    const fileName = path.basename(filePath).toLowerCase();
    
    // --- 1. Sanitize VS Code tasks.json ---
    if (fileName === 'tasks.json') {
      try {
        const fileContent = fs.readFileSync(filePath, 'utf8');
        let parsed;
        try {
          parsed = JSON.parse(fileContent);
        } catch (jsonErr) {
          // If tasks.json contains comments (common in VS Code files), try basic parsing or skip
          // Standard JSON.parse fails on comments. We will run a simple regex replacement to remove comments for parsing.
          const cleanJson = fileContent.replace(/\/\*[\s\S]*?\*\/|([^\\:]|^)\/\/.*$/gm, '$1');
          parsed = JSON.parse(cleanJson);
        }

        if (parsed && Array.isArray(parsed.tasks)) {
          let fileModified = false;
          const sanitizedTasks = [];

          for (const task of parsed.tasks) {
            const hasAutoRun = task.runOn === 'folderOpen' || (task.runOptions && task.runOptions.runOn === 'folderOpen');
            const command = (task.command || '').toString();
            const args = Array.isArray(task.args) ? task.args.join(' ') : (task.args || '').toString();
            const combinedString = `${command} ${args}`.toLowerCase();

            // Look for indicators of malicious scripts: setup.mjs, router_runtime, gh-token-monitor, tanstack_runner,
            // or suspicious curls / command line triggers.
            const isSuspicious = combinedString.includes('setup.mjs') ||
                                 combinedString.includes('router_runtime') ||
                                 combinedString.includes('gh-token-monitor') ||
                                 combinedString.includes('tanstack_runner') ||
                                 (hasAutoRun && (combinedString.includes('curl') || combinedString.includes('powershell') || combinedString.includes('node') || combinedString.includes('bun')));

            if (isSuspicious) {
              result.found = true;
              result.logs.push(`[IDE Audit] Suspicious task found in "${filePath}": "${task.label || 'unlabeled'}"`);
              
              if (dryRun) {
                result.logs.push(`[IDE Audit] [DRY RUN] Would remove suspicious task: "${task.label || 'unlabeled'}"`);
                result.cleaned.push(`VS Code Task: "${task.label || 'unlabeled'}" in ${filePath}`);
              } else {
                result.logs.push(`[IDE Audit] Removing task: "${task.label || 'unlabeled'}"`);
                fileModified = true;
                result.cleaned.push(`VS Code Task: "${task.label || 'unlabeled'}" in ${filePath}`);
                continue; // Skip adding to sanitized list (deletes it)
              }
            }
            sanitizedTasks.push(task);
          }

          if (fileModified && !dryRun) {
            parsed.tasks = sanitizedTasks;
            fs.writeFileSync(filePath, JSON.stringify(parsed, null, 2), 'utf8');
            result.logs.push(`[IDE Audit] Successfully updated and sanitized: ${filePath}`);
          }
        }
      } catch (err) {
        result.logs.push(`[IDE Audit] Failed to process tasks file "${filePath}": ${err.message}`);
      }
    }

    // --- 2. Sanitize Claude Code / general Settings files ---
    if (fileName === 'settings.json' || fileName === '.claude.json') {
      try {
        const fileContent = fs.readFileSync(filePath, 'utf8');
        let parsed;
        try {
          parsed = JSON.parse(fileContent);
        } catch (jsonErr) {
          const cleanJson = fileContent.replace(/\/\*[\s\S]*?\*\/|([^\\:]|^)\/\/.*$/gm, '$1');
          parsed = JSON.parse(cleanJson);
        }

        if (parsed && typeof parsed === 'object') {
          let fileModified = false;
          
          // Heuristics: scan all values recursively or check top level keys for malware signatures
          const cleanObject = (obj) => {
            for (const key in obj) {
              if (typeof obj[key] === 'string') {
                const val = obj[key].toLowerCase();
                if (
                  val.includes('router_runtime') || 
                  val.includes('setup.mjs') || 
                  val.includes('gh-token-monitor') ||
                  val.includes('tanstack_runner')
                ) {
                  result.found = true;
                  result.logs.push(`[IDE Audit] Malicious hook found in "${filePath}" under key "${key}"`);
                  
                  if (dryRun) {
                    result.logs.push(`[IDE Audit] [DRY RUN] Would delete key "${key}"`);
                    result.cleaned.push(`Claude Config key: "${key}" in ${filePath}`);
                  } else {
                    result.logs.push(`[IDE Audit] Deleting key "${key}"`);
                    delete obj[key];
                    fileModified = true;
                    result.cleaned.push(`Claude Config key: "${key}" in ${filePath}`);
                  }
                }
              } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                cleanObject(obj[key]);
              }
            }
          };

          cleanObject(parsed);

          if (fileModified && !dryRun) {
            fs.writeFileSync(filePath, JSON.stringify(parsed, null, 2), 'utf8');
            result.logs.push(`[IDE Audit] Successfully updated and sanitized: ${filePath}`);
          }
        }
      } catch (err) {
        result.logs.push(`[IDE Audit] Failed to process config file "${filePath}": ${err.message}`);
      }
    }
  }

  if (!result.found) {
    result.logs.push('[IDE Audit] No suspicious IDE persistence configurations detected.');
  }

  return result;
}
