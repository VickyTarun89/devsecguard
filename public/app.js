document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const pathInput = document.getElementById('scan-path');
  const btnReset = document.getElementById('btn-browse');
  const btnScan = document.getElementById('btn-scan');
  const btnClean = document.getElementById('btn-clean');
  const btnClearConsole = document.getElementById('btn-clear-console');
  const consoleOutput = document.getElementById('console-output');

  // Status badges & bars
  const statusProcess = document.getElementById('status-process');
  const barProcess = document.getElementById('bar-process');

  const statusPersistence = document.getElementById('status-persistence');
  const barPersistence = document.getElementById('bar-persistence');

  const statusIde = document.getElementById('status-ide');
  const barIde = document.getElementById('bar-ide');

  const statusFiles = document.getElementById('status-files');
  const barFiles = document.getElementById('bar-files');

  const overallStatus = document.getElementById('overall-status');

  // Set default path value (we will fetch from backend or use placeholder/empty)
  // Let's call the backend immediately to get a scan with no path (which defaults to the current server directory)
  pathInput.value = ''; // Will default to process.cwd() on backend

  // Event Listeners
  btnReset.addEventListener('click', () => {
    pathInput.value = '';
    writeConsoleLine('[System] Scan path reset to default server directory.', 'system');
  });

  btnClearConsole.addEventListener('click', () => {
    consoleOutput.innerHTML = '';
    writeConsoleLine('[System] Console cleared.', 'system');
  });

  btnScan.addEventListener('click', () => {
    runRemediation(false);
  });

  btnClean.addEventListener('click', () => {
    if (confirm('⚠️ WARNING: Active Eradication will terminate processes and modify files. Are you sure you want to proceed?')) {
      runRemediation(true);
    }
  });

  // Core Request function
  async function runRemediation(isClean = false) {
    const targetPath = pathInput.value.trim();
    const actionName = isClean ? 'Active Eradication' : 'Safe Scan & Audit';
    
    // Disable buttons
    btnScan.disabled = true;
    btnClean.disabled = true;
    
    writeConsoleLine(`[System] Initiating ${actionName}...`, 'system');
    
    // Clear meters visual indicators to "Scanning" state
    setMeterState('process', 'Scanning...', 'warn');
    setMeterState('persistence', 'Scanning...', 'warn');
    setMeterState('ide', 'Scanning...', 'warn');
    setMeterState('files', 'Scanning...', 'warn');
    
    overallStatus.textContent = 'SCANNING...';
    overallStatus.className = 'overall-badge status-warn';

    try {
      let response;
      if (isClean) {
        response = await fetch('/api/clean', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: targetPath || null })
        });
      } else {
        const queryParams = targetPath ? `?path=${encodeURIComponent(targetPath)}` : '';
        response = await fetch(`/api/scan${queryParams}`);
      }

      if (!response.ok) {
        throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
      }

      const result = await response.json();
      
      // Print logs to console
      if (result.logs && Array.isArray(result.logs)) {
        for (const logLine of result.logs) {
          // Parse level based on prefix in logs
          let level = 'info';
          if (logLine.includes('[PHASE') || logLine.includes('===') || logLine.includes('Summary')) {
            level = 'system';
          } else if (logLine.includes('Threat identified') || logLine.includes('Malware payload found') || logLine.includes('Suspicious') || logLine.includes('WARNING')) {
            level = 'threat';
          } else if (logLine.includes('Successfully deleted') || logLine.includes('Successfully terminated') || logLine.includes('Successfully updated') || logLine.includes('SAFE')) {
            level = 'success';
          } else if (logLine.includes('No matching') || logLine.includes('No suspicious') || logLine.includes('No malicious')) {
            level = 'info';
          }
          writeConsoleLine(logLine, level);
        }
      }

      // Update meters based on findings
      const findings = result.findings;
      if (findings) {
        // Wiper Process Meter
        if (findings.processes) {
          if (findings.processes.found) {
            setMeterState('process', isClean ? 'Cleaned' : 'Threat Found', isClean ? 'good' : 'danger');
          } else {
            setMeterState('process', 'No Threat', 'good');
          }
        }

        // System Persistence Meter
        if (findings.systemPersistence) {
          if (findings.systemPersistence.found) {
            setMeterState('persistence', isClean ? 'Cleaned' : 'Threat Found', isClean ? 'good' : 'danger');
          } else {
            setMeterState('persistence', 'No Threat', 'good');
          }
        }

        // IDE Persistence Meter
        if (findings.idePersistence) {
          if (findings.idePersistence.found) {
            setMeterState('ide', isClean ? 'Cleaned' : 'Threat Found', isClean ? 'good' : 'danger');
          } else {
            setMeterState('ide', 'No Threat', 'good');
          }
        }

        // Files Meter
        if (findings.files) {
          if (findings.files.found) {
            setMeterState('files', isClean ? 'Cleaned' : 'Threat Found', isClean ? 'good' : 'danger');
          } else {
            setMeterState('files', 'No Threat', 'good');
          }
        }

        // Update overall badge
        const hasThreats = 
          findings.processes.found || 
          findings.systemPersistence.found || 
          findings.idePersistence.found || 
          findings.files.found;

        if (hasThreats) {
          if (isClean) {
            overallStatus.textContent = 'DISARMED & SAFE';
            overallStatus.className = 'overall-badge status-good';
          } else {
            overallStatus.textContent = 'ACTIVE THREAT DETECTED';
            overallStatus.className = 'overall-badge status-danger';
          }
        } else {
          overallStatus.textContent = 'SECURE & CLEAN';
          overallStatus.className = 'overall-badge status-good';
        }
      }

    } catch (err) {
      writeConsoleLine(`[ERROR] Connection failed: ${err.message}`, 'threat');
      setMeterState('process', 'Error', 'danger');
      setMeterState('persistence', 'Error', 'danger');
      setMeterState('ide', 'Error', 'danger');
      setMeterState('files', 'Error', 'danger');
      
      overallStatus.textContent = 'ERROR';
      overallStatus.className = 'overall-badge status-danger';
    } finally {
      // Enable buttons
      btnScan.disabled = false;
      btnClean.disabled = false;
    }
  }

  // Console output helper
  function writeConsoleLine(text, level = 'info') {
    const line = document.createElement('div');
    line.className = `console-line ${level}`;
    line.textContent = text;
    consoleOutput.appendChild(line);
    // Auto scroll to bottom
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
  }

  // Meter UI modifier helper
  function setMeterState(meterId, labelText, type = 'good') {
    let statusEl, barEl;
    if (meterId === 'process') {
      statusEl = statusProcess;
      barEl = barProcess;
    } else if (meterId === 'persistence') {
      statusEl = statusPersistence;
      barEl = barPersistence;
    } else if (meterId === 'ide') {
      statusEl = statusIde;
      barEl = barIde;
    } else if (meterId === 'files') {
      statusEl = statusFiles;
      barEl = barFiles;
    }

    statusEl.textContent = labelText;
    statusEl.className = `status-badge status-${type}`;
    
    barEl.className = `bar-fill fill-${type}`;
    if (type === 'danger') {
      barEl.style.width = '30%';
    } else if (type === 'warn') {
      barEl.style.width = '60%';
    } else {
      barEl.style.width = '100%';
    }
  }

  // Initial meter states
  setMeterState('process', 'Awaiting Scan', 'warn');
  setMeterState('persistence', 'Awaiting Scan', 'warn');
  setMeterState('ide', 'Awaiting Scan', 'warn');
  setMeterState('files', 'Awaiting Scan', 'warn');
});
