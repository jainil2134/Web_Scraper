// Global variable to store current session results
let lastScanData = null;

// Initialize Lucide icons on load
document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
});

/**
 * Appends messages to the simulated terminal
 */
function logToTerminal(message, type = 'info') {
    const terminal = document.getElementById('terminal');
    const time = new Date().toLocaleTimeString();
    let colorClass = 'text-blue-400';
    
    if (type === 'error') colorClass = 'text-red-400';
    if (type === 'success') colorClass = 'text-emerald-400';
    if (type === 'warning') colorClass = 'text-yellow-400';
    
    terminal.innerHTML += `<p class="mb-1"><span class="text-slate-600">[${time}]</span> <span class="${colorClass}">${message}</span></p>`;
    terminal.scrollTop = terminal.scrollHeight;
}

/**
 * Main function to start the audit by communicating with FastAPI
 */
async function startAudit() {
    const urlValue = document.getElementById('urlInput').value.trim();
    if (!urlValue) return alert("Please enter a URL");

    logToTerminal(`Starting full audit for: ${urlValue}`, 'warning');

    try {
        const resp = await fetch('/api/fullscan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlValue })
        });
        if (!resp.ok) throw new Error('Failed to start full scan');
        const body = await resp.json();
        const jobId = body.job_id;
        logToTerminal(`Scan started (job: ${jobId}). Polling for results...`, 'info');

        // Polling loop
        const poll = async () => {
            try {
                const s = await fetch(`/api/job/${jobId}`);
                const job = await s.json();
                if (job.status === 'running') {
                    logToTerminal('Scan still running...', 'info');
                    setTimeout(poll, 3000);
                    return;
                }
                if (job.status === 'failed') {
                    logToTerminal(`Scan failed: ${job.error}`, 'error');
                    return;
                }

                // success
                lastScanData = job.result_data;
                updateUI(lastScanData);
                logToTerminal('Full audit complete.', 'success');
            } catch (e) {
                logToTerminal(`Polling error: ${e.message}`, 'error');
            }
        };

        setTimeout(poll, 2000);
    } catch (error) {
        logToTerminal(`Link Error: ${error.message}`, 'error');
    }
}

/**
 * Updates the dashboard with results from the JSON response
 */
function updateUI(data) {
    // Top Stats
    document.getElementById('ipDisplay').innerText = data.target_ip;
    document.getElementById('vpnDisplay').innerText = data.vpn_status.includes('Found') ? "DETECTED" : "None";
    document.getElementById('riskDisplay').innerText = "AUDITED";
    document.getElementById('ispDisplaySmall').innerText = data.geo_intel.org || "N/A";

    // Detailed Table
    document.getElementById('asnDetail').innerText = data.geo_intel.as || "N/A";
    document.getElementById('ispDetail').innerText = `${data.geo_intel.isp} / ${data.geo_intel.org}`;
    document.getElementById('startDetail').innerText = data.scan_start_time;
    
    const ports = data.open_ports.map(p => p.port).join(', ');
    document.getElementById('portDetail').innerText = ports || "No common ports open";

    // Handle Security Headers
    // Use optional chaining to avoid crashes if keys are missing
    const headers = data.findings?.security_header_audit || {};
    formatHeader('hstsDetail', headers['Strict-Transport-Security']);
    formatHeader('cspDetail', headers['Content-Security-Policy']);

    // Finalize UI
    document.getElementById('statusBadge').innerText = "Complete";
    document.getElementById('statusBadge').className = "px-3 py-1 bg-emerald-600 rounded-full text-xs text-white";
    
    const dlBtn = document.getElementById('downloadBtn');
    dlBtn.disabled = false;
    dlBtn.classList.remove('opacity-50', 'cursor-not-allowed', 'text-slate-500');
    dlBtn.classList.add('bg-emerald-600', 'text-white', 'hover:bg-emerald-700');
}

/**
 * Helper to color-code security header status
 */
function formatHeader(elementId, value) {
    const el = document.getElementById(elementId);
    if (!value || value === "MISSING") {
        el.innerHTML = `<span class="text-red-400 font-bold">MISSING</span>`;
    } else {
        el.innerHTML = `<span class="text-emerald-400 font-bold">PRESENT</span>`;
    }
}

/**
 * Generates and downloads the JSON file
 */
function downloadReport() {
    if (!lastScanData) return;

    const hostname = new URL(document.getElementById('urlInput').value).hostname.replace(/\./g, '_');
    const filename = `${hostname}_audit_${new Date().getTime()}.json`;

    const blob = new Blob([JSON.stringify(lastScanData, null, 4)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    logToTerminal(`Snapshot saved: ${filename}`, 'success');
}


/**
 * Lightweight scrape action (title, meta, h1s, links)
 */
async function startScrape() {
    const urlValue = document.getElementById('urlInput').value.trim();
    if (!urlValue) return alert("Please enter a URL");

    logToTerminal(`Starting lightweight scrape for: ${urlValue}`, 'warning');

    try {
        const response = await fetch('/api/scrape', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlValue })
        });

        if (!response.ok) throw new Error('Scrape endpoint failed');

        const data = await response.json();
        lastScanData = data;

        if (data.error) {
            logToTerminal(`Scrape Error: ${data.error}`, 'error');
            return;
        }

        logToTerminal(`Title: ${data.title || 'N/A'}`, 'success');
        if (data.description) logToTerminal(`Description: ${data.description}`);
        if (Array.isArray(data.h1)) data.h1.forEach(h => logToTerminal(`H1: ${h}`));
        if (Array.isArray(data.links)) data.links.slice(0, 10).forEach(l => logToTerminal(`Link: ${l}`));

        const dlBtn = document.getElementById('downloadBtn');
        dlBtn.disabled = false;
        dlBtn.classList.remove('opacity-50', 'cursor-not-allowed', 'text-slate-500');
        dlBtn.classList.add('bg-emerald-600', 'text-white', 'hover:bg-emerald-700');

        logToTerminal('Scrape complete.', 'success');
    } catch (error) {
        logToTerminal(`Scrape failed: ${error.message}`, 'error');
    }
}