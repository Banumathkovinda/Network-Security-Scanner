/* Network Security Scanner — Advanced UI */
let networkScanResult = null;
let portScanResult = null;
let vulnScanResult = null;
let cveScanResult = null;
let nmapAvailable = false;
let historyFilter = 'all';
let allScansCache = [];
let lastRiskScore = null;
let lastSslInfo = null;
let lastVulns = [];

function apiHeaders() {
    const h = { 'Content-Type': 'application/json' };
    const key = sessionStorage.getItem('scannerApiKey');
    if (key) h['X-API-Key'] = key;
    return h;
}

async function parseApiResponse(res) {
    const text = await res.text();
    if (text.trimStart().startsWith('<')) {
        throw new Error('Server returned HTML. Restart: python simple_scanner.py');
    }
    try {
        return JSON.parse(text);
    } catch {
        throw new Error('Invalid response: ' + text.slice(0, 80));
    }
}

async function api(url, options = {}) {
    const res = await fetch(url, {
        ...options,
        credentials: 'same-origin',
        headers: { ...apiHeaders(), ...(options.headers || {}) },
    });
    const data = await parseApiResponse(res);
    if (res.status === 401) {
        location.href = '/login.html';
        throw new Error('Please log in');
    }
    return { res, data };
}

const TOAST_ICONS = { info: 'fa-circle-info', ok: 'fa-circle-check', err: 'fa-circle-xmark' };

function hideToast() {
    const el = document.getElementById('toast');
    if (!el) return;
    clearTimeout(el._t);
    el.classList.add('hidden');
    el.innerHTML = '';
}

function toast(msg, type = 'info') {
    const el = document.getElementById('toast');
    if (!el) return;
    const styles = {
        info: 'bg-slate-800 border border-slate-600 text-slate-100',
        ok: 'bg-emerald-900/90 border border-emerald-600/50 text-emerald-100',
        err: 'bg-rose-900/90 border border-rose-600/50 text-rose-100',
    };
    el.className = `hidden fixed bottom-6 right-6 z-50 rounded-xl px-5 py-3 text-sm ${styles[type] || styles.info}`;
    el.innerHTML = `<i class="fas ${TOAST_ICONS[type] || TOAST_ICONS.info}"></i><span>${msg}</span>`;
    el.classList.remove('hidden');
    clearTimeout(el._t);
    el._t = setTimeout(hideToast, 4200);
}

function dismissLegalNotice() {
    document.getElementById('legalNotice')?.classList.add('hidden');
    try { localStorage.setItem('scannerLegalDismissed', '1'); } catch (_) {}
}

function showLoading(msg = 'Scanning…') {
    document.getElementById('loadingText').textContent = msg;
    const el = document.getElementById('loadingOverlay');
    el.classList.remove('hidden');
    el.classList.add('flex');
}

function hideLoading() {
    document.getElementById('loadingOverlay').classList.add('hidden');
    document.getElementById('loadingOverlay').classList.remove('flex');
}

function switchTab(tab) {
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    const panel = document.getElementById('tab-' + tab);
    if (panel) panel.classList.remove('hidden');
    const btn = document.querySelector(`.tab-btn[data-tab="${tab}"]`);
    if (btn) btn.classList.add('active');
    if (tab === 'history') loadHistory();
    if (tab === 'compare') loadCompareDropdowns();
    if (tab === 'map') renderNetworkMapFromLast();
    if (tab === 'scan') refreshDashboard();
}

function severityBadge(sev) {
    const s = (sev || '').toLowerCase();
    const cls = s === 'high' ? 'badge-high' : s === 'medium' ? 'badge-medium' : 'badge-low';
    return `<span class="badge ${cls}">${s || 'info'}</span>`;
}

function confBar(pct) {
    const n = Math.min(100, Math.max(0, pct || 0));
    const col = n >= 80 ? '#10b981' : n >= 50 ? '#f59e0b' : '#f43f5e';
    return `<div class="conf-bar"><div class="conf-fill" style="width:${n}%;background:${col}"></div></div>`;
}

function renderRiskGauge(risk) {
    if (!risk) return '';
    const score = risk.score ?? 0;
    const color = risk.color || '#34d399';
    const r = 52;
    const circ = 2 * Math.PI * r;
    const offset = circ - (score / 100) * circ;
    return `
        <div class="risk-gauge" title="Risk score ${score}/100">
            <svg width="120" height="120" viewBox="0 0 120 120">
                <circle cx="60" cy="60" r="${r}" fill="none" stroke="rgba(51,65,85,0.8)" stroke-width="10"/>
                <circle cx="60" cy="60" r="${r}" fill="none" stroke="${color}" stroke-width="10"
                    stroke-dasharray="${circ}" stroke-dashoffset="${offset}" stroke-linecap="round"/>
            </svg>
            <div class="risk-gauge-center">
                <span class="risk-gauge-score" style="color:${color}">${score}</span>
                <span class="risk-gauge-label" style="color:${color}">${risk.label || 'Risk'}</span>
            </div>
        </div>`;
}

function renderSslPanel(ssl) {
    if (!ssl) return '';
    if (!ssl.available && ssl.error) {
        return `<div class="ssl-panel bad">
            <h4 class="font-semibold text-rose-300 mb-2 flex items-center gap-2">
                <i class="fas fa-lock-open"></i> TLS / SSL
            </h4>
            <p class="text-sm text-slate-400">${ssl.error}</p>
        </div>`;
    }
    if (!ssl.available) return '';
    const cls = ssl.expired || (ssl.warnings || []).some(w => w.severity === 'high') ? 'bad'
        : (ssl.warnings || []).length ? 'warn' : 'ok';
    const days = ssl.days_until_expiry;
    const daysText = days != null ? (days < 0 ? 'Expired' : `${days} days left`) : '—';
    return `
        <div class="ssl-panel ${cls}">
            <h4 class="font-semibold mb-3 flex items-center gap-2 text-indigo-200">
                <i class="fas fa-lock text-emerald-400"></i> TLS / SSL Certificate
            </h4>
            <div class="report-meta-grid mb-3">
                <div class="report-meta-item"><span class="label">Issuer</span><span class="value">${ssl.issuer || '—'}</span></div>
                <div class="report-meta-item"><span class="label">Subject</span><span class="value">${ssl.subject_cn || '—'}</span></div>
                <div class="report-meta-item"><span class="label">Protocol</span><span class="value">${ssl.protocol || '—'}</span></div>
                <div class="report-meta-item"><span class="label">Expires</span><span class="value ${ssl.expired ? 'text-rose-400' : ''}">${ssl.valid_until || '—'}</span></div>
                <div class="report-meta-item"><span class="label">Validity</span><span class="value">${daysText}</span></div>
                <div class="report-meta-item"><span class="label">Cipher</span><span class="value text-xs">${ssl.cipher || '—'}</span></div>
            </div>
            ${(ssl.warnings || []).length ? `<ul class="space-y-1 text-sm">${ssl.warnings.map(w =>
                `<li class="flex items-center gap-2">${severityBadge(w.severity)}<span>${w.message}</span></li>`
            ).join('')}</ul>` : '<p class="text-sm text-emerald-400/90"><i class="fas fa-check mr-1"></i>No TLS warnings</p>'}
        </div>`;
}

function renderSecurityHero(host, risk, ssl, subtitle = '') {
    if (!risk) return '';
    return `
        <div class="report-hero">
            <div class="flex flex-col md:flex-row gap-6 items-center md:items-start">
                ${renderRiskGauge(risk)}
                <div class="flex-1 text-center md:text-left min-w-0">
                    <p class="text-xs uppercase tracking-widest text-indigo-400 font-semibold mb-1">Security assessment</p>
                    <h3 class="text-2xl font-bold truncate">${host}</h3>
                    ${subtitle ? `<p class="text-slate-400 text-sm mt-1">${subtitle}</p>` : ''}
                    <p class="text-slate-300 text-sm mt-3 leading-relaxed">${risk.summary || ''}</p>
                    ${(risk.factors || []).length ? `
                        <ul class="factor-list mt-4 max-h-36 overflow-y-auto">
                            ${risk.factors.map(f => `<li><span class="factor-points">+${f.points}</span><span>${f.label}</span></li>`).join('')}
                        </ul>` : ''}
                </div>
            </div>
            ${ssl ? `<div class="mt-5">${renderSslPanel(ssl)}</div>` : ''}
        </div>`;
}

async function fetchSecurityEnrich(host, portData, vulnerabilities = null) {
    const body = { host, port_scan: portData, vulnerabilities };
    const { data } = await api('/api/security/enrich', { method: 'POST', body: JSON.stringify(body) });
    lastRiskScore = data.risk_score;
    lastSslInfo = data.ssl;
    if (vulnerabilities) lastVulns = vulnerabilities;
    return data;
}

async function refreshDashboard() {
    try {
        const { data } = await api('/api/scans');
        allScansCache = data.scans || [];
        document.getElementById('statScans').textContent = allScansCache.length;
        const ports = portScanResult?.tcp ? Object.keys(portScanResult.tcp).length : '—';
        document.getElementById('statPorts').textContent = ports;
        const hosts = networkScanResult?.hosts?.length ?? '—';
        document.getElementById('statHosts').textContent = hosts;
        const vulns = vulnScanResult?.vulnerabilities?.length ?? lastVulns?.length ?? '—';
        document.getElementById('statVulns').textContent = vulns;
        const riskEl = document.getElementById('statRisk');
        if (riskEl) {
            riskEl.textContent = lastRiskScore != null ? `${lastRiskScore.score}` : '—';
            riskEl.style.color = lastRiskScore?.color || '';
        }
    } catch (_) {}
}

async function initAuth() {
    const { data } = await api('/api/auth/status');
    const logoutBtn = document.getElementById('logoutBtn');
    if (data.auth_required) {
        if (!data.authenticated) {
            location.href = '/login.html';
            return;
        }
        logoutBtn?.classList.remove('hidden');
    }
}

document.getElementById('logoutBtn')?.addEventListener('click', async () => {
    await api('/api/auth/logout', { method: 'POST' });
    sessionStorage.removeItem('scannerApiKey');
    location.href = '/login.html';
});

function closePanel() {
    document.getElementById('scanPanel').classList.add('hidden');
}

function showPanel(title, html) {
    document.getElementById('panelTitle').textContent = title;
    document.getElementById('panelContent').innerHTML = html;
    document.getElementById('scanPanel').classList.remove('hidden');
    document.getElementById('scanPanel').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

const inputCls = 'input-field';

function showNetworkScan() {
    showPanel('Network Discovery', `
        <div class="space-y-4">
            <label class="block text-sm font-medium text-slate-300">Network or domain</label>
            <input type="text" id="networkRange" placeholder="192.168.1.0/24 or example.com" class="${inputCls}">
            <p class="text-slate-500 text-sm">CIDR for LAN · single domain for reachability check</p>
            <button type="button" onclick="performNetworkScan()" class="btn-primary w-full sm:w-auto">
                <i class="fas fa-play mr-2"></i>Start discovery
            </button>
        </div>`);
}

function showPortScan() {
    const prefill = document.getElementById('quickTarget')?.value || '';
    showPanel('Port Scan', `
        <div class="space-y-4">
            <label class="block text-sm font-medium text-slate-300">Target</label>
            <input type="text" id="targetHost" value="${prefill.replace(/"/g, '&quot;')}" placeholder="example.com or 192.168.1.1" class="${inputCls}">
            <label class="block text-sm font-medium text-slate-300">Port range</label>
            <select id="portRange" class="${inputCls}">
                <option value="quick">Quick — common ports</option>
                <option value="1-1000">Standard — 1–1000</option>
                <option value="1-65535">Full — all ports (slow)</option>
                <option value="custom">Custom</option>
            </select>
            <input type="text" id="customPorts" placeholder="80,443,8080" class="hidden ${inputCls}">
            <label class="flex items-center gap-3 p-3 rounded-xl bg-slate-800/50 border border-slate-700/50 cursor-pointer">
                <input type="checkbox" id="useNmapPort" class="w-4 h-4 rounded" ${nmapAvailable ? '' : 'disabled'}>
                <span class="text-sm"><span class="font-medium">Use Nmap</span> — accurate service versions</span>
            </label>
            <p class="text-xs ${nmapAvailable ? 'text-emerald-400' : 'text-amber-400'}">
                ${nmapAvailable ? '✓ Nmap detected' : 'Nmap not installed — using built-in scanner'}
            </p>
            <button type="button" onclick="performPortScan()" class="btn-primary w-full sm:w-auto">
                <i class="fas fa-play mr-2"></i>Scan ports
            </button>
        </div>`);
    document.getElementById('portRange').onchange = function () {
        document.getElementById('customPorts').classList.toggle('hidden', this.value !== 'custom');
    };
}

function showVulnCheck() {
    const prefill = document.getElementById('quickTarget')?.value || '';
    showPanel('Vulnerability Check', `
        <div class="space-y-4">
            <input type="text" id="vulnHost" value="${prefill.replace(/"/g, '&quot;')}" placeholder="Target host or domain" class="${inputCls}">
            <button type="button" onclick="performVulnCheck()" class="btn-primary w-full sm:w-auto bg-gradient-to-r from-rose-600 to-red-600">
                <i class="fas fa-shield-virus mr-2"></i>Run assessment
            </button>
        </div>`);
}

function showCveLookup() {
    showPanel('CVE Lookup (NVD)', `
        <div class="space-y-4">
            <input type="text" id="cveProduct" placeholder="Product — Apache, OpenSSH, nginx" class="${inputCls}">
            <input type="text" id="cveVersion" placeholder="Version — 2.4.49" class="${inputCls}">
            <button type="button" onclick="performCveManual()" class="btn-primary w-full sm:w-auto" style="background:linear-gradient(135deg,#f97316,#ea580c)">
                <i class="fas fa-search mr-2"></i>Search NVD
            </button>
        </div>`);
}

async function showSchedules() {
    const { data } = await api('/api/schedules');
    const list = data.schedules || [];
    const email = data.email || {};
    showPanel('Scheduled Scans', `
        <p class="text-sm mb-4 p-3 rounded-xl ${email.ready ? 'bg-emerald-950/40 text-emerald-300 border border-emerald-800/40' : 'bg-amber-950/40 text-amber-200 border border-amber-800/40'}">
            <i class="fas fa-envelope mr-2"></i>Email alerts: ${email.ready ? 'Configured' : 'Add SMTP settings to .env'}
        </p>
        <div class="grid gap-3 mb-4">
            <input id="schedTarget" placeholder="Target host" class="${inputCls}">
            <input id="schedHours" type="number" value="24" min="1" placeholder="Interval (hours)" class="${inputCls}">
            <input id="schedEmail" type="email" placeholder="Alert email (optional)" class="${inputCls}">
            <label class="flex items-center gap-2 text-sm"><input type="checkbox" id="schedCve" class="rounded"> Include CVE in report</label>
            <label class="flex items-center gap-2 text-sm"><input type="checkbox" id="schedNmap" class="rounded"> Use Nmap</label>
            <button type="button" onclick="addSchedule()" class="btn-primary">Add schedule</button>
        </div>
        <div class="space-y-2 max-h-56 overflow-y-auto">${list.map(s => `
            <div class="history-item">
                <div class="history-icon bg-cyan-500/20 text-cyan-400"><i class="fas fa-clock"></i></div>
                <div class="flex-1 min-w-0">
                    <p class="font-medium truncate">${s.target}</p>
                    <p class="text-xs text-slate-500">Every ${s.interval_hours}h · ${s.last_run ? 'Last: ' + new Date(s.last_run).toLocaleString() : 'Not run yet'}</p>
                </div>
                <button type="button" onclick="deleteSchedule('${s.id}')" class="text-rose-400 hover:text-rose-300 text-sm px-2">Remove</button>
            </div>`).join('') || '<div class="empty-state py-8"><p>No schedules</p></div>'}
        </div>`);
}

async function runQuickScanBar() {
    const host = document.getElementById('quickTarget')?.value?.trim();
    if (!host) { toast('Enter a target in the quick scan bar', 'err'); return; }
    showLoading('Building security report…');
    try {
        const { res, data } = await api('/api/security/report', {
            method: 'POST',
            body: JSON.stringify({ host, use_nmap: nmapAvailable }),
        });
        if (!res.ok) throw new Error(data.error);
        portScanResult = data.port_scan;
        lastVulns = data.vulnerabilities || [];
        vulnScanResult = { target: host, vulnerabilities: lastVulns };
        lastRiskScore = data.risk_score;
        lastSslInfo = data.ssl;
        displaySecurityReport(data);
        toast(`Risk score: ${data.risk_score?.score}/100 (${data.risk_score?.label})`, 'ok');
    } catch (e) {
        toast(e.message, 'err');
    } finally {
        hideLoading();
        refreshDashboard();
    }
}

async function performNetworkScan() {
    const network = document.getElementById('networkRange')?.value?.trim();
    if (!network) { toast('Enter network or domain', 'err'); return; }
    showLoading('Discovering hosts…');
    try {
        const { res, data } = await api('/api/scan/network', { method: 'POST', body: JSON.stringify({ network }) });
        if (!res.ok) throw new Error(data.error);
        displayNetworkResults(data);
        toast(`Discovery complete — ${(data.hosts || []).length} host(s)`, 'ok');
    } catch (e) {
        toast(e.message, 'err');
    } finally {
        hideLoading();
        closePanel();
        refreshDashboard();
    }
}

async function performPortScan() {
    const host = document.getElementById('targetHost')?.value?.trim();
    const portRange = document.getElementById('portRange')?.value;
    if (!host) { toast('Enter target', 'err'); return; }
    showLoading('Scanning ports…');
    try {
        let endpoint = '/api/scan/host';
        const body = { host, use_nmap: document.getElementById('useNmapPort')?.checked || false };
        if (portRange === 'quick') endpoint = '/api/scan/quick';
        else if (portRange === 'custom') {
            const c = document.getElementById('customPorts')?.value;
            if (c) body.ports = c;
        } else body.ports = portRange;
        const { res, data } = await api(endpoint, { method: 'POST', body: JSON.stringify(body) });
        if (!res.ok) throw new Error(data.error);
        document.getElementById('loadingText').textContent = 'Risk score & SSL…';
        let enrich = {};
        try {
            enrich = await fetchSecurityEnrich(host, data);
        } catch (_) {}
        displayPortResults(data, enrich.risk_score, enrich.ssl);
        toast(`Scan done — ${Object.keys(data.tcp || {}).length} open port(s)`, 'ok');
    } catch (e) {
        toast(e.message, 'err');
    } finally {
        hideLoading();
        closePanel();
        refreshDashboard();
    }
}

async function performVulnCheck() {
    const host = document.getElementById('vulnHost')?.value?.trim();
    if (!host) { toast('Enter target', 'err'); return; }
    showLoading('Running assessment…');
    try {
        const { data: portData } = await api('/api/scan/quick', { method: 'POST', body: JSON.stringify({ host }) });
        const ports = Object.entries(portData.tcp || {}).map(([p, i]) => ({ port: +p, service: i.name }));
        const { data: vulnData } = await api('/api/vulnerability/check', {
            method: 'POST',
            body: JSON.stringify({ host, ports }),
        });
        lastVulns = vulnData.vulnerabilities || [];
        showLoading('Risk score & SSL…');
        let enrich = {};
        try {
            enrich = await fetchSecurityEnrich(host, portData, lastVulns);
        } catch (_) {}
        displayVulnResults(vulnData, portData, enrich.risk_score, enrich.ssl);
        vulnScanResult = { target: host, vulnerabilities: lastVulns };
        toast(`Risk ${enrich.risk_score?.score ?? '—'}/100`, 'ok');
    } catch (e) {
        toast(e.message, 'err');
    } finally {
        hideLoading();
        closePanel();
        refreshDashboard();
    }
}

async function performCveManual() {
    const product = document.getElementById('cveProduct')?.value?.trim();
    if (!product) return;
    showLoading('Querying NVD…');
    try {
        const { data } = await api('/api/cve/lookup', {
            method: 'POST',
            body: JSON.stringify({ product, version: document.getElementById('cveVersion')?.value }),
        });
        displayCveResults({ services: [{ product, cve_lookup: data }] });
    } catch (e) {
        toast(e.message, 'err');
    } finally {
        hideLoading();
        closePanel();
    }
}

async function addSchedule() {
    const target = document.getElementById('schedTarget')?.value?.trim();
    if (!target) return;
    await api('/api/schedules', {
        method: 'POST',
        body: JSON.stringify({
            target,
            interval_hours: +document.getElementById('schedHours').value || 24,
            email: document.getElementById('schedEmail')?.value || undefined,
            include_cve: document.getElementById('schedCve')?.checked,
            use_nmap: document.getElementById('schedNmap')?.checked,
        }),
    });
    toast('Schedule added', 'ok');
    showSchedules();
}

async function deleteSchedule(id) {
    await api('/api/schedules/' + id, { method: 'DELETE' });
    toast('Removed', 'ok');
    showSchedules();
}

function showResults(html) {
    document.getElementById('resultsContent').innerHTML = html;
    document.getElementById('results').classList.remove('hidden');
    document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
}

function displayNetworkResults(data) {
    networkScanResult = data;
    if (data.error) {
        showResults(`<div class="card p-5 border-rose-500/30 text-rose-300"><i class="fas fa-circle-xmark mr-2"></i>${data.error}</div>`);
        return;
    }
    const hosts = data.hosts || [];
    const details = data.host_details || {};
    showResults(`
        <div class="card p-6">
            <div class="flex flex-wrap justify-between gap-3 mb-5">
                <div>
                    <h3 class="text-xl font-bold">Network discovery</h3>
                    <p class="text-slate-400 text-sm mt-1">${data.network_range || ''}</p>
                </div>
                <div class="flex gap-2">
                    <span class="badge badge-ok">${hosts.length} live</span>
                    <button type="button" onclick="switchTab('map')" class="btn-secondary text-sm"><i class="fas fa-circle-nodes mr-1"></i> View map</button>
                </div>
            </div>
            <div class="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
                ${hosts.length ? hosts.map(h => {
                    const d = details[h] || {};
                    return `<div class="p-4 rounded-xl bg-slate-800/60 border border-slate-700/50 hover:border-emerald-500/40 transition">
                        <div class="flex items-center gap-2 mb-2">
                            <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                            <span class="font-mono font-medium">${h}</span>
                        </div>
                        ${d.hostname ? `<p class="text-xs text-blue-400 font-mono">${d.hostname}</p>` : ''}
                        ${d.responding_port ? `<p class="text-xs text-slate-500 mt-2">Port ${d.responding_port} · ${d.service || ''}</p>` : ''}
                    </div>`;
                }).join('') : `<div class="empty-state col-span-full"><i class="fas fa-wifi"></i><p>No live hosts detected</p><p class="text-xs mt-2">Try a smaller CIDR or check firewall rules</p></div>`}
            </div>
        </div>`);
}

function displaySecurityReport(data) {
    portScanResult = data.port_scan;
    const risk = data.risk_score;
    const ssl = data.ssl;
    const portData = data.port_scan || {};
    const vulns = data.vulnerabilities || [];
    lastRiskScore = risk;
    lastSslInfo = ssl;
    lastVulns = vulns;
    const sub = `${Object.keys(portData.tcp || {}).length} open ports · ${vulns.length} finding(s)`;
    showResults(
        renderSecurityHero(data.host, risk, ssl, sub) +
        renderPortTableCard(portData, vulns) +
        renderVulnSection(vulns)
    );
}

function renderPortTableCard(data, vulns) {
    const ports = Object.entries(data.tcp || {});
    const vs = data.scan_metadata?.verification_summary || {};
    return `
        <div class="card p-6 mt-4">
            <div class="flex flex-wrap justify-between gap-3 mb-4">
                <h4 class="font-semibold text-lg"><i class="fas fa-plug text-emerald-400 mr-2"></i>Open ports</h4>
                <span class="badge badge-ok">${ports.length} open</span>
            </div>
            ${vs.avg_confidence != null ? `<p class="text-xs text-slate-500 mb-3">Avg confidence ${vs.avg_confidence}%</p>` : ''}
            <div class="flex gap-2 mb-4">
                <button type="button" onclick="lookupCveFromPortScan()" class="btn-secondary text-sm"><i class="fas fa-database mr-1 text-orange-400"></i> CVE lookup</button>
            </div>
            <div class="overflow-x-auto rounded-xl border border-slate-700/50">
                <table class="port-table">
                    <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Product / Version</th><th>Conf.</th></tr></thead>
                    <tbody>${ports.length ? ports.map(([p, i]) => `<tr>
                        <td class="font-mono font-semibold text-indigo-300">${p}</td>
                        <td><span class="badge badge-ok text-[10px]">${i.state}</span></td>
                        <td>${i.name}</td>
                        <td><span class="text-emerald-400/90">${i.product}</span> <span class="text-slate-500">${i.version}</span></td>
                        <td>${confBar(i.confidence)}</td>
                    </tr>`).join('') : '<tr><td colspan="5" class="py-8 text-center text-slate-500">No open TCP ports</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>`;
}

function renderVulnSection(vulns) {
    if (!vulns.length) return `<div class="card p-5 mt-4 text-center text-emerald-400/90"><i class="fas fa-shield-check mr-2"></i>No rule-based vulnerabilities flagged</div>`;
    return `<div class="card p-6 mt-4 space-y-3">
        <h4 class="font-semibold"><i class="fas fa-triangle-exclamation text-rose-400 mr-2"></i>Findings</h4>
        ${vulns.map(v => `
            <div class="p-4 rounded-xl border-l-4 border-rose-500 bg-rose-950/20">
                <div class="flex justify-between gap-2 mb-1">
                    <span class="font-semibold">${(v.service || '').toUpperCase()} · Port ${v.port}</span>
                    ${severityBadge(v.severity)}
                </div>
                <p class="text-sm text-slate-300">${v.description}</p>
            </div>`).join('')}
    </div>`;
}

function displayPortResults(data, risk, ssl) {
    portScanResult = data;
    if (data.error) {
        showResults(`<div class="card p-5 text-rose-300">${data.error}</div>`);
        return;
    }
    risk = risk || lastRiskScore;
    ssl = ssl !== undefined ? ssl : lastSslInfo;
    const sub = `${Object.keys(data.tcp || {}).length} open ports · ${data.scan_time ? new Date(data.scan_time).toLocaleString() : ''}`;
    showResults(
        (risk ? renderSecurityHero(data.host, risk, ssl, sub) : '') +
        renderPortTableCard(data, [])
    );
}

function displayVulnResults(vulnData, portData, risk, ssl) {
    const vulns = vulnData.vulnerabilities || [];
    risk = risk || lastRiskScore;
    ssl = ssl !== undefined ? ssl : lastSslInfo;
    showResults(
        renderSecurityHero(portData.host, risk, ssl, `${vulns.length} finding(s)`) +
        renderVulnSection(vulns) +
        renderPortTableCard(portData, vulns)
    );
}

function displayCveResults(data) {
    const services = data.services || [];
    showResults(`
        <div class="card p-6 space-y-4">
            <h3 class="text-xl font-bold"><i class="fas fa-database text-orange-400 mr-2"></i>CVE results</h3>
            ${services.map(svc => {
                const lk = svc.cve_lookup || {};
                const cves = lk.cves || [];
                if (lk.error) return `<p class="text-rose-400">${lk.error}</p>`;
                return `<div class="p-4 rounded-xl bg-slate-800/50 border border-slate-700/50">
                    <h4 class="font-semibold text-orange-300">${svc.product} ${svc.version || ''}</h4>
                    <p class="text-xs text-slate-500 mb-3">${lk.keyword || ''}</p>
                    ${cves.length ? `<div class="space-y-2">${cves.map(c => `
                        <div class="p-3 rounded-lg bg-slate-900/80 text-sm">
                            <a href="${c.url}" target="_blank" class="text-blue-400 font-mono font-medium">${c.id}</a>
                            ${severityBadge(c.severity)}
                            ${c.score != null ? `<span class="text-slate-500 text-xs ml-2">CVSS ${c.score}</span>` : ''}
                            <p class="text-slate-400 mt-2 leading-relaxed">${c.description?.slice(0, 220)}…</p>
                        </div>`).join('')}</div>` : '<p class="text-slate-500 text-sm">No CVEs found</p>'}
                </div>`;
            }).join('')}
        </div>`);
}

async function lookupCveFromPortScan() {
    if (!portScanResult) return;
    showLoading('CVE lookup…');
    try {
        const { data } = await api('/api/cve/lookup-scan', {
            method: 'POST',
            body: JSON.stringify({ scan_result: portScanResult }),
        });
        displayCveResults(data);
    } catch (e) {
        toast(e.message, 'err');
    } finally {
        hideLoading();
    }
}

function setHistoryFilter(f) {
    historyFilter = f;
    document.querySelectorAll('.history-filter').forEach(b => {
        b.classList.toggle('active', b.dataset.filter === f);
    });
    renderHistoryList(allScansCache);
}

function historyIcon(type) {
    if (type === 'port') return { bg: 'bg-emerald-500/20', icon: 'fa-plug', color: 'text-emerald-400' };
    if (type === 'network') return { bg: 'bg-blue-500/20', icon: 'fa-network-wired', color: 'text-blue-400' };
    return { bg: 'bg-slate-500/20', icon: 'fa-file', color: 'text-slate-400' };
}

function renderHistoryList(scans) {
    const el = document.getElementById('historyList');
    const filtered = historyFilter === 'all' ? scans : scans.filter(s => s.type === historyFilter);
    if (!filtered.length) {
        el.innerHTML = `<div class="empty-state card"><i class="fas fa-clock-rotate-left"></i><p>No ${historyFilter === 'all' ? '' : historyFilter + ' '}scans saved yet</p></div>`;
        return;
    }
    el.innerHTML = filtered.map(s => {
        const hi = historyIcon(s.type);
        return `<div class="history-item">
            <div class="history-icon ${hi.bg} ${hi.color}"><i class="fas ${hi.icon}"></i></div>
            <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2 flex-wrap">
                    <span class="badge text-[10px] bg-slate-800 border-slate-600">${s.type}</span>
                    <span class="font-medium truncate">${s.label || s.target}</span>
                </div>
                <p class="text-xs text-slate-500 mt-1">${new Date(s.created_at).toLocaleString()}</p>
            </div>
            <code class="text-[10px] text-slate-600 hidden sm:block">${s.id}</code>
        </div>`;
    }).join('');
}

async function loadHistory() {
    try {
        const { data } = await api('/api/scans');
        allScansCache = data.scans || [];
        renderHistoryList(allScansCache);
    } catch (e) {
        document.getElementById('historyList').innerHTML = `<p class="text-rose-400 card p-4">${e.message}</p>`;
    }
}

async function loadCompareDropdowns() {
    try {
        const { data } = await api('/api/scans');
        const opts = (data.scans || []).map(s =>
            `<option value="${s.id}">[${s.type}] ${s.label} — ${new Date(s.created_at).toLocaleString()}</option>`
        ).join('');
        document.getElementById('compareA').innerHTML = '<option value="">Select baseline…</option>' + opts;
        document.getElementById('compareB').innerHTML = '<option value="">Select current…</option>' + opts;
    } catch (e) {
        toast(e.message, 'err');
    }
}

async function runCompare() {
    const a = document.getElementById('compareA').value;
    const b = document.getElementById('compareB').value;
    if (!a || !b) { toast('Select two scans', 'err'); return; }
    if (a === b) { toast('Choose different scans', 'err'); return; }
    showLoading('Comparing…');
    try {
        const { data } = await api(`/api/scans/compare?a=${a}&b=${b}`);
        if (data.error) throw new Error(data.error);
        displayCompareResults(data);
        toast('Comparison ready', 'ok');
    } catch (e) {
        toast(e.message, 'err');
    } finally {
        hideLoading();
    }
}

function displayCompareResults(data) {
    const el = document.getElementById('compareResults');
    el.classList.remove('hidden');
    if (data.type === 'port') {
        el.innerHTML = `
            <div class="grid md:grid-cols-2 gap-4">
                <div class="compare-col compare-added">
                    <h4 class="font-semibold text-emerald-400 mb-3 flex items-center gap-2">
                        <i class="fas fa-plus-circle"></i> Added (${data.added.length})
                    </h4>
                    ${data.added.map(p => `<div class="py-1.5 border-b border-emerald-900/30 text-sm font-mono">${p.port} <span class="text-slate-400">${p.name || ''}</span></div>`).join('') || '<p class="text-slate-500 text-sm">None</p>'}
                </div>
                <div class="compare-col compare-removed">
                    <h4 class="font-semibold text-rose-400 mb-3 flex items-center gap-2">
                        <i class="fas fa-minus-circle"></i> Removed (${data.removed.length})
                    </h4>
                    ${data.removed.map(p => `<div class="py-1.5 border-b border-rose-900/30 text-sm font-mono">${p.port}</div>`).join('') || '<p class="text-slate-500 text-sm">None</p>'}
                </div>
            </div>
            <div class="compare-col compare-changed card p-5 mt-4">
                <h4 class="font-semibold text-amber-400 mb-3"><i class="fas fa-arrows-rotate mr-2"></i>Changed (${data.changed.length})</h4>
                ${data.changed.map(c => `<p class="text-sm py-2 border-b border-amber-900/20"><b class="font-mono">${c.port}</b>:
                    <span class="text-slate-500">${c.before.product}/${c.before.version}</span> →
                    <span class="text-slate-300">${c.after.product}/${c.after.version}</span></p>`).join('') || '<p class="text-slate-500 text-sm">None</p>'}
            </div>
            <p class="text-center text-slate-500 text-sm mt-4">${data.unchanged_count} unchanged port(s)</p>`;
    } else if (data.type === 'network') {
        el.innerHTML = `
            <div class="grid md:grid-cols-2 gap-4">
                <div class="compare-col compare-added">
                    <h4 class="text-emerald-400 font-semibold mb-2">New hosts (${(data.added_hosts || []).length})</h4>
                    ${(data.added_hosts || []).map(h => `<p class="font-mono text-sm py-1">${h}</p>`).join('') || '<p class="text-slate-500 text-sm">None</p>'}
                </div>
                <div class="compare-col compare-removed">
                    <h4 class="text-rose-400 font-semibold mb-2">Removed hosts (${(data.removed_hosts || []).length})</h4>
                    ${(data.removed_hosts || []).map(h => `<p class="font-mono text-sm py-1">${h}</p>`).join('') || '<p class="text-slate-500 text-sm">None</p>'}
                </div>
            </div>
            <p class="text-center text-slate-500 text-sm mt-4">${(data.unchanged_hosts || []).length} unchanged host(s)</p>`;
    }
}

function renderNetworkMapFromLast() {
    const hint = document.getElementById('mapHint');
    if (!networkScanResult?.hosts?.length) {
        hint.textContent = 'Run Network Discovery on the Dashboard, then return here.';
        return;
    }
    hint.textContent = `${networkScanResult.network_range || 'Network'} — ${networkScanResult.hosts.length} host(s)`;
    const hosts = networkScanResult.hosts;
    const nodes = [{
        id: 1, label: 'Network\n' + (networkScanResult.network_range || '').slice(0, 24),
        shape: 'box', size: 28,
        color: { background: '#4f46e5', border: '#818cf8', highlight: { background: '#6366f1' } },
        font: { color: '#fff', size: 14 },
    }];
    const edges = [];
    hosts.forEach((h, i) => {
        const nid = i + 2;
        nodes.push({
            id: nid, label: h, shape: 'dot', size: 22,
            color: { background: '#10b981', border: '#34d399' },
            font: { color: '#e2e8f0', face: 'monospace' },
        });
        edges.push({ from: 1, to: nid, color: { color: 'rgba(99,102,241,0.4)' } });
    });
    const container = document.getElementById('networkMapCanvas');
    if (typeof vis === 'undefined') {
        hint.textContent = 'Map library failed to load — refresh page.';
        return;
    }
    new vis.Network(container, { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) }, {
        physics: { barnesHut: { gravitationalConstant: -3000 }, stabilization: { iterations: 120 } },
        interaction: { hover: true, tooltipDelay: 100 },
        edges: { smooth: { type: 'continuous' } },
    });
}

function exportResultsJson() {
    const payload = { networkScanResult, portScanResult, vulnScanResult, cveScanResult, exported: new Date().toISOString() };
    if (!portScanResult && !networkScanResult && !vulnScanResult) {
        toast('No results to export', 'err');
        return;
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `scan-export-${Date.now()}.json`;
    a.click();
    toast('JSON downloaded', 'ok');
}

function downloadPDF() {
    if (!networkScanResult && !portScanResult && !vulnScanResult) {
        toast('Run a scan first', 'err');
        return;
    }
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    doc.setFontSize(18);
    doc.text('Security Scan Report', 20, 20);
    doc.setFontSize(10);
    doc.text(new Date().toLocaleString(), 20, 30);
    if (portScanResult?.host) {
        doc.text(`Host: ${portScanResult.host}`, 20, 40);
        let y = 50;
        Object.entries(portScanResult.tcp || {}).forEach(([p, i]) => {
            doc.text(`Port ${p}: ${i.name} — ${i.product} ${i.version}`, 20, y);
            y += 8;
        });
    }
    doc.save('scan-report.pdf');
    toast('PDF downloaded', 'ok');
}

(async function boot() {
    hideToast();
    hideLoading();
    if (localStorage.getItem('scannerLegalDismissed') === '1') {
        document.getElementById('legalNotice')?.classList.add('hidden');
    }
    await initAuth();
    try {
        const { data } = await api('/api/nmap/status');
        nmapAvailable = data.available;
    } catch (_) {}
    await refreshDashboard();
    switchTab('scan');
})();
