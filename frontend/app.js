// Dynamic API Base: Use relative path for Docker/Nginx, or explicit localhost:5001 for local dev (start.sh)
const API_BASE = window.location.port === '8000'
    ? 'http://localhost:5001/api'
    : '/api';
let currentFilters = {
    team: '',
    platform: '',
    label: '',
    osVersion: ''
};
let selectedAuditPolicyId = null;

function showLoading() {
    document.getElementById('loading-overlay')?.classList.remove('hidden');
}

function hideLoading() {
    document.getElementById('loading-overlay')?.classList.add('hidden');
}

// Initialize
async function init() {
    showLoading();
    await populateFilters();
    await updateDashboard();
    setupEventListeners();
    setupTooltip();
    setupInfoTooltips();
    updateSyncStatus();
    setInterval(updateSyncStatus, 30000);

    // Deep-link / restore page from hash
    const hashPage = (window.location.hash || '').replace(/^#/, '');
    if (hashPage && document.getElementById(hashPage)) {
        switchPage(hashPage);
    } else {
        updatePageBanner('dashboard');
    }

    window.addEventListener('hashchange', () => {
        const page = (window.location.hash || '').replace(/^#/, '') || 'dashboard';
        if (document.getElementById(page)) switchPage(page);
    });
}

function setupTooltip() {
    const tooltip = document.getElementById('global-tooltip');
    const content = document.getElementById('global-tooltip-content');
    if (!tooltip || !content) return;

    document.addEventListener('mouseover', (e) => {
        const cell = e.target.closest('.d3fend-heatmap-cell, .mitre-technique-cell');
        if (cell) {
            const text = cell.getAttribute('data-tooltip');
            if (!text) return;

            content.textContent = text;
            tooltip.classList.remove('hidden');

            const rect = cell.getBoundingClientRect();
            const tooltipRect = tooltip.getBoundingClientRect();

            // Check if it's a mitre cell (tends to be larger/taller)
            const isMitre = cell.classList.contains('mitre-technique-cell');
            const topOffset = isMitre ? 5 : 10;

            const top = rect.top - tooltipRect.height - topOffset;
            const left = rect.left + (rect.width / 2) - (tooltipRect.width / 2);

            tooltip.style.top = `${top}px`;
            tooltip.style.left = `${left}px`;
        }
    });

    document.addEventListener('mouseout', (e) => {
        if (e.target.closest('.d3fend-heatmap-cell, .mitre-technique-cell')) {
            tooltip.classList.add('hidden');
        }
    });

    // Also hide on scroll to prevent floating tooltips
    window.addEventListener('scroll', () => tooltip.classList.add('hidden'), true);
}

function setupInfoTooltips() {
    const tooltip = document.getElementById('global-tooltip');
    const content = document.getElementById('global-tooltip-content');
    if (!tooltip || !content) return;

    document.addEventListener('mouseover', (e) => {
        const icon = e.target.closest('.info-icon');
        if (icon) {
            const text = icon.getAttribute('data-help');
            if (!text) return;

            content.textContent = text;
            tooltip.classList.remove('hidden');

            const rect = icon.getBoundingClientRect();
            const tooltipRect = tooltip.getBoundingClientRect();

            const top = rect.top - tooltipRect.height - 10;
            const left = rect.left + (rect.width / 2) - (tooltipRect.width / 2);

            tooltip.style.top = `${top}px`;
            tooltip.style.left = `${left}px`;
        }
    });

    document.addEventListener('mouseout', (e) => {
        if (e.target.closest('.info-icon')) {
            tooltip.classList.add('hidden');
        }
    });
}

const PAGE_META = {
    dashboard: {
        title: 'Security Posture Summary',
        subtitle: 'Real-time CIS Controls & D3FEND analysis',
        docTitle: 'Summary · Fleet CIS'
    },
    architecture: {
        title: 'Security Architecture',
        subtitle: 'MITRE ATT&CK coverage and defensive depth',
        docTitle: 'Architecture · Fleet CIS'
    },
    audit: {
        title: 'Compliance Audit',
        subtitle: 'CIS evidence, drift, and remediation guidance',
        docTitle: 'Audit · Fleet CIS'
    },
    strategy: {
        title: 'Executive Strategy',
        subtitle: 'Posture, risk, and priority actions for leadership',
        docTitle: 'Strategy · Fleet CIS'
    },
    alerts: {
        title: 'Alert Manager',
        subtitle: 'Destinations, policy-fail rules, and delivery after sync',
        docTitle: 'Alerts · Fleet CIS'
    },
    settings: {
        title: 'Configuration',
        subtitle: 'Framework weights, sync, and dashboard preferences',
        docTitle: 'Settings · Fleet CIS'
    }
};

function updatePageBanner(page) {
    const meta = PAGE_META[page] || PAGE_META.dashboard;
    const titleEl = document.getElementById('page-title');
    const subEl = document.getElementById('page-subtitle');
    if (titleEl) titleEl.textContent = meta.title;
    if (subEl) subEl.textContent = meta.subtitle;
    document.title = meta.docTitle;
}

// Setup event listeners
function setupEventListeners() {
    // Navigation (nav links + sidebar brand)
    document.querySelectorAll('[data-page]').forEach(link => {
        link.addEventListener('click', (e) => {
            if (!link.classList.contains('nav-link') && !link.classList.contains('sidebar-brand')) return;
            e.preventDefault();
            const page = link.dataset.page;
            switchPage(page);
        });
    });

    // Filters
    document.getElementById('apply-filters').addEventListener('click', updateDashboard);
    document.getElementById('reset-filters').addEventListener('click', resetFilters);
    document.getElementById('platform-filter').addEventListener('change', updateOSVersions);
    document.getElementById('team-filter').addEventListener('change', updateDashboard);
    document.getElementById('label-filter').addEventListener('change', updateDashboard);
}

// Switch pages
function switchPage(page) {
    if (!page || !document.getElementById(page)) return;

    const pages = document.querySelectorAll('.page-content');
    pages.forEach(p => {
        p.classList.remove('active');
        p.style.opacity = '0';
        p.style.transform = 'translateY(10px)';
    });

    const targetPage = document.getElementById(page);
    targetPage.classList.add('active');

    requestAnimationFrame(() => {
        targetPage.style.transition = 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)';
        targetPage.style.opacity = '1';
        targetPage.style.transform = 'translateY(0)';
    });

    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.toggle('active', link.dataset.page === page);
    });

    updatePageBanner(page);

    if (window.location.hash !== `#${page}`) {
        history.replaceState(null, '', `#${page}`);
    }

    const filters = document.querySelector('.filters-bar');
    if (filters) {
        filters.style.display = page === 'alerts' ? 'none' : '';
    }
    if (page === 'alerts' && typeof window.loadAlertManager === 'function') {
        window.loadAlertManager();
    }
}

// Populate filters
async function populateFilters() {
    try {
        const [teamsResp, platformsResp, labelsResp] = await Promise.all([
            fetch(`${API_BASE}/teams`).then(r => r.json()),
            fetch(`${API_BASE}/platforms`).then(r => r.json()),
            fetch(`${API_BASE}/labels`).then(r => r.json())
        ]);

        const teams = teamsResp.teams || [];
        const platforms = platformsResp.platforms || [];
        const labels = labelsResp.labels || [];

        // Teams
        const teamSelect = document.getElementById('team-filter');
        teams.forEach(team => {
            const option = document.createElement('option');
            option.value = team;
            option.textContent = team;
            teamSelect.appendChild(option);
        });

        // Platforms
        const platformSelect = document.getElementById('platform-filter');
        platforms.forEach(platform => {
            const option = document.createElement('option');
            option.value = platform;
            option.textContent = platform;
            platformSelect.appendChild(option);
        });

        // Labels
        const labelSelect = document.getElementById('label-filter');
        labels.forEach(label => {
            const option = document.createElement('option');
            option.value = label;
            option.textContent = label;
            labelSelect.appendChild(option);
        });
    } catch (error) {
        console.error('Error populating filters:', error);
    }
}

// Update OS versions based on platform
async function updateOSVersions() {
    const platform = document.getElementById('platform-filter').value;
    const label = document.getElementById('label-filter').value;

    if (!platform) {
        document.getElementById('os-version-filter').innerHTML = '<option value="">All Versions</option>';
        return;
    }

    try {
        const params = new URLSearchParams();
        if (label) params.append('label', label);
        const resp = await fetch(`${API_BASE}/os-versions?${params}`).then(r => r.json());
        const allVersions = resp.os_versions || {};
        const versions = allVersions[platform] || [];

        const osSelect = document.getElementById('os-version-filter');
        osSelect.innerHTML = '<option value="">All Versions</option>';
        versions.forEach(version => {
            const option = document.createElement('option');
            option.value = version;
            option.textContent = version;
            osSelect.appendChild(option);
        });
    } catch (error) {
        console.error('Error updating OS versions:', error);
    }
}

function resetFilters() {
    document.getElementById('team-filter').value = '';
    document.getElementById('platform-filter').value = '';
    document.getElementById('label-filter').value = '';
    document.getElementById('os-version-filter').value = '';
    currentFilters = { team: '', platform: '', label: '', osVersion: '' };
    updateDashboard();
}

async function updateDashboard() {
    showLoading();
    currentFilters = {
        team: document.getElementById('team-filter').value,
        platform: document.getElementById('platform-filter').value,
        label: document.getElementById('label-filter').value,
        osVersion: document.getElementById('os-version-filter').value
    };

    try {
        const [summary, heatmap, safeguards] = await Promise.all([
            fetch(`${API_BASE}/compliance-summary?${new URLSearchParams(currentFilters)}`).then(r => r.json()),
            fetch(`${API_BASE}/heatmap-data?${new URLSearchParams(currentFilters)}`).then(r => r.json()),
            fetch(`${API_BASE}/safeguard-compliance?${new URLSearchParams(currentFilters)}`).then(r => r.json())
        ]);

        // Update All Specialized Pages (Async)
        await Promise.all([
            populateArchitecturePage(heatmap, summary),
            populateAuditPage(summary),
            populateStrategyPage(summary, heatmap)
        ]);

        // Update Summary Page KPIs
        updateMetrics(summary);

        // Update Summary Page Heatmap
        updateHeatmap(heatmap);

        // Update Summary Page Violations
        updateViolations(safeguards);

        // Update Summary Page Controls
        updateControlsStatus(safeguards);

    } catch (error) {
        console.error('Error updating dashboard:', error);
        showError(error.message);
    } finally {
        hideLoading();
    }
}

// Show error banner
function showError(message) {
    const banner = document.createElement('div');
    banner.style.cssText = 'background: #ff3333; color: white; padding: 10px; border-radius: 4px; font-weight: bold; position: fixed; top: 10px; left: 50%; transform: translateX(-50%); z-index: 9999; text-align: center;';
    banner.textContent = `⚠️ Error: ${message}`;
    document.body.prepend(banner);
    setTimeout(() => banner.remove(), 8000);
}

// Update metrics (KPI cards) — honest labels, no conflated "compliance"
function updateMetrics(summary) {
    if (!summary) return;

    const rate = summary.policy_pass_rate ?? summary.compliance_percentage ?? 0;
    const compliant = summary.fully_compliant_devices ?? summary.compliant_devices ?? 0;
    const total = summary.total_devices || 0;
    const openFailures = summary.open_failures ?? summary.policies_failed ?? 0;
    const failingPolicies = summary.failing_policies_count;
    const passed = summary.policies_passed ?? 0;
    const failed = summary.policies_failed ?? openFailures;

    const rateEl = document.getElementById('compliance-rate');
    const policyDetailEl = document.getElementById('policy-pass-detail');
    const barEl = document.getElementById('compliance-bar');
    const deviceCountEl = document.getElementById('device-count');
    const criticalCountEl = document.getElementById('critical-count');
    const failingPolEl = document.getElementById('failing-policies-sub');
    const riskLevelEl = document.getElementById('risk-level');
    const deviceSubEl = document.getElementById('device-compliance-sub');

    if (rateEl) rateEl.textContent = `${Math.round(rate)}%`;
    if (policyDetailEl) policyDetailEl.textContent = `${passed.toLocaleString()} pass / ${failed.toLocaleString()} fail checks`;
    if (barEl) barEl.style.width = `${rate}%`;
    if (deviceCountEl) deviceCountEl.textContent = total;
    if (criticalCountEl) criticalCountEl.textContent = openFailures.toLocaleString();
    if (failingPolEl) {
        failingPolEl.textContent = failingPolicies != null
            ? `${failingPolicies.toLocaleString()} distinct policies`
            : 'Open fail result rows';
    }
    if (deviceSubEl) deviceSubEl.textContent = `${compliant} / ${total} fully compliant`;

    let riskLevel = 'LOW';
    if (total === 0) riskLevel = 'UNAVAILABLE';
    else if ((summary.total_policy_results || 0) === 0) riskLevel = 'HIGH';
    else if (rate < 50) riskLevel = 'CRITICAL';
    else if (rate < 70) riskLevel = 'HIGH';
    else if (rate < 85) riskLevel = 'MEDIUM';

    if (riskLevelEl) {
        riskLevelEl.textContent = riskLevel;
        riskLevelEl.className = 'risk-badge ' + riskLevel.toLowerCase();
    }
}

// ─── Heat map state ───────────────────────────────────────────
let heatmapRawData = [];
let heatmapMeta = { multi_platform: false, fleet_size: 0, platforms: [], coarse_techniques: [] };
let heatmapGroupBy = 'safeguard'; // safeguard | d3fend | category | mitre | platform
let heatmapCisFilter = '';
let heatmapMitreFilter = '';
let heatmapListenersBound = false;
let heatmapResizeObserver = null;

const D3FEND_TACTIC_ORDER = [
    'Model', 'Harden', 'Detect', 'Isolate', 'Deceive', 'Evict', 'Restore', 'Unmapped'
];

function passRateOf(item) {
    if (item && typeof item.pass_rate === 'number') return item.pass_rate;
    if (!item || !item.total) return 0;
    return (item.pass / item.total) * 100;
}

function riskScoreOf(item) {
    if (item && typeof item.risk_score === 'number') return item.risk_score;
    // Fallback: invert pass rate if risk not provided
    return 100 - passRateOf(item);
}

/** Color by fleet exposure risk (higher = worse). */
function riskClass(riskScore, total) {
    if (!total) return 'rate-empty';
    if (riskScore >= 40) return 'rate-danger';
    if (riskScore >= 20) return 'rate-warning';
    if (riskScore >= 5) return 'rate-good';
    return 'rate-excellent';
}

/** @deprecated pass-rate coloring — prefer riskClass */
function rateClass(passRate, total) {
    if (!total) return 'rate-empty';
    if (passRate >= 80) return 'rate-excellent';
    if (passRate >= 60) return 'rate-good';
    if (passRate >= 40) return 'rate-warning';
    return 'rate-danger';
}

function escapeAttr(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

// CIS safeguard IDs (CIS4.8) are shared families. Fleet policy_id is unique.
function auditPolicyKey(policy) {
    if (!policy) return '';
    if (policy.policy_id != null && policy.policy_id !== '') {
        return String(policy.policy_id);
    }
    return `${policy.safeguard_id || ''}::${policy.name || policy.policy_name || ''}`;
}

function uniqueByPolicyId(items) {
    const seen = new Set();
    const out = [];
    (items || []).forEach(item => {
        const key = auditPolicyKey(item);
        if (!key || seen.has(key)) return;
        seen.add(key);
        out.push(item);
    });
    return out;
}

function findAuditPolicy(key, pool) {
    const want = String(key ?? '');
    const rows = uniqueByPolicyId(pool || auditData);
    return rows.find(p => auditPolicyKey(p) === want);
}

function policyMatchesAuditSearch(policy, query) {
    const q = (query || '').trim().toLowerCase();
    if (!q) return true;
    const fields = [
        policy.safeguard_id,
        policy.control,
        policy.cis_id,
        policy.cis_section,
        policy.name,
        policy.policy_name,
        policy.policy_id,
        ...(policy.cis_safeguard_ids || [])
    ];
    return fields.some(v => String(v || '').toLowerCase().includes(q));
}

function policyIdSelector(policyId) {
    const raw = String(policyId ?? '');
    const escaped = (window.CSS && CSS.escape) ? CSS.escape(raw) : raw.replace(/"/g, '\\"');
    return `.audit-policy-item[data-policy-id="${escaped}"]`;
}

function openAuditForPolicy(policyId) {
    if (policyId == null || policyId === '') return;
    selectedAuditPolicyId = String(policyId);
    currentAuditSearch = '';
    currentAuditFilter = null;
    const searchInput = document.getElementById('audit-search-input');
    if (searchInput) searchInput.value = '';
    switchPage('audit');
    updateAuditUI();
    const item = document.querySelector(`#audit-policy-list ${policyIdSelector(policyId)}`);
    item?.scrollIntoView({ block: 'nearest' });
}

function groupKeyForItem(item, mode) {
    if (mode === 'safeguard') {
        return item.cis_safeguard_id || 'CISNone';
    }
    if (mode === 'category') {
        return item.cis_category || item.cis_subcategory || 'Uncategorized';
    }
    if (mode === 'mitre') {
        const status = (item.mapping_status || '').toLowerCase();
        if (status === 'not_applicable') return 'No ATT&CK link';
        if (status === 'needs_review') return 'Needs review';
        const id = (item.attack_id || (item.attack_ids && item.attack_ids[0]) || '').trim();
        if (!id || id === 'Unmapped' || id === 'N/A') return 'Unmapped';
        return id;
    }
    if (mode === 'platform') {
        return item.platform || 'unknown';
    }
    return item.d3fend_tactic || 'Unmapped';
}

function groupLabelMeta(key, items, mode) {
    const avgRisk = items.length
        ? Math.round(items.reduce((s, i) => s + riskScoreOf(i), 0) / items.length)
        : 0;
    // Column headers: IDs / short labels only — full names live in cell tooltips
    if (mode === 'safeguard') {
        return { title: key, meta: `${items.length}` };
    }
    if (mode === 'category') {
        // Prefer short id-like slug; category strings are long — truncate hard
        const short = key.length > 18 ? key.slice(0, 16) + '…' : key;
        return { title: short, meta: `${items.length}` };
    }
    if (mode === 'd3fend' || mode === 'platform') {
        return { title: key, meta: `${items.length}` };
    }
    if (mode === 'mitre') {
        return { title: key || 'Unmapped', meta: `${items.length}` };
    }
    return { title: key, meta: `${items.length}` };
}

function sortGroupKeys(keys, mode) {
    if (mode === 'd3fend') {
        return [...keys].sort((a, b) => {
            const ia = D3FEND_TACTIC_ORDER.indexOf(a);
            const ib = D3FEND_TACTIC_ORDER.indexOf(b);
            return (ia > -1 ? ia : 99) - (ib > -1 ? ib : 99) || a.localeCompare(b);
        });
    }
    if (mode === 'safeguard') {
        return [...keys].sort((a, b) => {
            if (a === 'CISNone') return 1;
            if (b === 'CISNone') return -1;
            return a.localeCompare(b, undefined, { numeric: true });
        });
    }
    if (mode === 'platform' || mode === 'category') {
        return [...keys].sort((a, b) => a.localeCompare(b));
    }
    const mitreTail = new Set(['Unmapped', 'Needs review', 'No ATT&CK link']);
    return [...keys].sort((a, b) => {
        const aTail = mitreTail.has(a);
        const bTail = mitreTail.has(b);
        if (aTail && !bTail) return 1;
        if (bTail && !aTail) return -1;
        if (aTail && bTail) {
            const order = ['Needs review', 'No ATT&CK link', 'Unmapped'];
            return order.indexOf(a) - order.indexOf(b);
        }
        return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
    });
}

/** Compute cell size + columns so the matrix fills container width. */
function computeHeatmapLayout(container, groupCount, maxItemsInGroup) {
    const width = Math.max(container.clientWidth || 600, 320);
    const gap = 12;
    const colGap = 3;
    const usable = width - gap * Math.max(groupCount - 1, 0) - 8;
    const colWidth = Math.max(72, Math.floor(usable / Math.max(groupCount, 1)));

    // Prefer square cells that fill column width; clamp for touch targets
    let cell = Math.floor((colWidth - 8) / Math.max(4, Math.ceil(Math.sqrt(maxItemsInGroup || 1))));
    cell = Math.max(12, Math.min(28, cell));

    const cellsPerRow = Math.max(2, Math.floor((colWidth - 4) / (cell + colGap)));
    return { cell, cellsPerRow, colWidth };
}

function filterHeatmapData(data) {
    const cisQ = heatmapCisFilter.trim().toLowerCase();
    const mitreQ = heatmapMitreFilter.trim().toLowerCase();

    return data.filter(item => {
        if (cisQ) {
            const id = String(item.cis_id || item.cis_section || '').toLowerCase();
            const sg = String(item.cis_safeguard_id || '').toLowerCase();
            const name = String(item.policy_name || '').toLowerCase();
            const cat = String(item.cis_category || '').toLowerCase();
            if (!id.includes(cisQ) && !sg.includes(cisQ) && !name.includes(cisQ) && !cat.includes(cisQ)) {
                return false;
            }
        }
        if (mitreQ) {
            const attack = String(item.attack_id || '').toLowerCase();
            const attacks = (item.attack_ids || []).join(' ').toLowerCase();
            const tech = String(item.d3fend_technique || '').toLowerCase();
            if (!attack.includes(mitreQ) && !attacks.includes(mitreQ) && !tech.includes(mitreQ)) return false;
        }
        return true;
    });
}

function populateMitreDatalist(data) {
    const list = document.getElementById('heatmap-mitre-options');
    if (!list) return;
    const ids = new Set();
    data.forEach(i => {
        (i.attack_ids || []).forEach(a => {
            const t = String(a || '').trim();
            if (t && t !== 'Unmapped' && t !== 'N/A') ids.add(t);
        });
        const one = String(i.attack_id || '').trim();
        if (one && one !== 'Unmapped' && one !== 'N/A') ids.add(one);
    });
    list.innerHTML = DOMPurify.sanitize(
        [...ids]
            .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
            .map(id => `<option value="${escapeAttr(id)}"></option>`)
            .join('')
    );
}

function bindHeatmapControls() {
    if (heatmapListenersBound) return;
    heatmapListenersBound = true;

    const cisInput = document.getElementById('heatmap-cis-filter');
    const mitreInput = document.getElementById('heatmap-mitre-filter');
    const clearBtn = document.getElementById('heatmap-clear-filters');
    const groupBtns = document.querySelectorAll('.heatmap-group-btn');

    let debounceTimer = null;
    const rerender = () => renderHeatmapMatrix();

    const onFilterInput = () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            heatmapCisFilter = cisInput?.value || '';
            heatmapMitreFilter = mitreInput?.value || '';
            rerender();
        }, 180);
    };

    cisInput?.addEventListener('input', onFilterInput);
    mitreInput?.addEventListener('input', onFilterInput);

    const heatmapContainer = document.getElementById('heatmap-container');
    heatmapContainer?.addEventListener('click', (e) => {
        const cell = e.target.closest('.d3fend-heatmap-cell');
        if (!cell || !heatmapContainer.contains(cell)) return;
        const pid = cell.dataset.policyId;
        if (!pid) return;
        openAuditForPolicy(pid);
    });

    clearBtn?.addEventListener('click', () => {
        heatmapCisFilter = '';
        heatmapMitreFilter = '';
        if (cisInput) cisInput.value = '';
        if (mitreInput) mitreInput.value = '';
        rerender();
        cisInput?.focus();
    });

    groupBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            if (btn.disabled) return;
            heatmapGroupBy = btn.dataset.group || 'd3fend';
            groupBtns.forEach(b => {
                const active = b === btn;
                b.classList.toggle('active', active);
                b.setAttribute('aria-pressed', active ? 'true' : 'false');
            });
            rerender();
        });
    });

    // Re-layout on container resize (wide screens fill width)
    const container = document.getElementById('heatmap-container');
    if (container && typeof ResizeObserver !== 'undefined') {
        let roTimer = null;
        heatmapResizeObserver = new ResizeObserver(() => {
            clearTimeout(roTimer);
            roTimer = setTimeout(() => renderHeatmapMatrix(), 80);
        });
        heatmapResizeObserver.observe(container);
    }
    window.addEventListener('resize', () => {
        clearTimeout(bindHeatmapControls._rt);
        bindHeatmapControls._rt = setTimeout(() => renderHeatmapMatrix(), 120);
    });
}

function updateHeatmap(data) {
    heatmapRawData = data?.heatmap || [];
    heatmapMeta = {
        multi_platform: !!data?.multi_platform,
        fleet_size: data?.fleet_size || 0,
        platforms: data?.platforms || [],
        coarse_techniques: data?.coarse_techniques || [],
        catalog: data?.catalog || {},
        attack_coverage: data?.attack_coverage || {},
        identity: data?.identity || ''
    };
    bindHeatmapControls();
    populateMitreDatalist(heatmapRawData);
    renderHeatmapMatrix();
    updateAttackCoverageChip(heatmapMeta.attack_coverage);
}

function updateAttackCoverageChip(cov) {
    const el = document.getElementById('attack-coverage-chip');
    if (!el || !cov) return;
    const mapped = cov.pct_mapped != null ? cov.pct_mapped : '—';
    const review = cov.pct_needs_review != null ? cov.pct_needs_review : 0;
    const unmapped = cov.pct_unmapped != null ? cov.pct_unmapped : 0;
    const tech = cov.unique_techniques != null ? cov.unique_techniques : '—';
    el.textContent = `ATT&CK ${mapped}% mapped · ${tech} techniques`;
    el.title = `Mapped ${mapped}% · Needs review ${review}% · Unmapped ${unmapped}% · N/A ${cov.pct_not_applicable || 0}%`;
    el.classList.remove('hidden');
}

function renderHeatmapMatrix() {
    const container = document.getElementById('heatmap-container');
    const countEl = document.getElementById('heatmap-count');
    if (!container) return;

    const filtered = filterHeatmapData(heatmapRawData);

    if (countEl) {
        const total = heatmapRawData.length;
        const cat = heatmapMeta.catalog || {};
        const cov = heatmapMeta.attack_coverage || {};
        const matched = cat.matched_rows != null ? cat.matched_rows : total;
        const platNote = heatmapMeta.multi_platform
            ? ` · ${heatmapMeta.platforms.length} OS`
            : '';
        const mapNote = cov.pct_mapped != null ? ` · ATT&CK ${cov.pct_mapped}%` : '';
        const tagNote = heatmapMeta.identity === 'fleet_policies_tags' ? ' · tags' : '';
        countEl.textContent = filtered.length === total
            ? `${total} policies${platNote}${mapNote}${tagNote}`
            : `${filtered.length} / ${total}${platNote}${mapNote}`;
        countEl.title = [
            `Catalog matched ${matched}/${cat.total_rows || total}`,
            `safeguard-mapped ${cat.safeguard_mapped_rows || '—'}`,
            cov.pct_mapped != null
                ? `ATT&CK mapped ${cov.pct_mapped}% · review ${cov.pct_needs_review || 0}% · unmapped ${cov.pct_unmapped || 0}%`
                : ''
        ].filter(Boolean).join('; ');
    }

    if (heatmapRawData.length === 0) {
        container.innerHTML = '<p class="heatmap-empty">No heatmap data available</p>';
        return;
    }

    if (filtered.length === 0) {
        container.innerHTML = '<p class="heatmap-empty">No controls match the current filters</p>';
        return;
    }

    const groups = {};
    filtered.forEach(item => {
        const key = groupKeyForItem(item, heatmapGroupBy);
        if (!groups[key]) groups[key] = [];
        groups[key].push(item);
    });

    // Worst fleet risk first
    Object.values(groups).forEach(list => {
        list.sort((a, b) =>
            riskScoreOf(b) - riskScoreOf(a) ||
            String(a.cis_id).localeCompare(String(b.cis_id), undefined, { numeric: true })
        );
    });

    const sortedKeys = sortGroupKeys(Object.keys(groups), heatmapGroupBy);
    const maxItems = Math.max(...sortedKeys.map(k => groups[k].length), 1);
    const layout = computeHeatmapLayout(container, sortedKeys.length, maxItems);

    let html = '<div class="d3fend-matrix d3fend-matrix-fill">';

    sortedKeys.forEach(key => {
        const items = groups[key];
        const { title, meta } = groupLabelMeta(key, items, heatmapGroupBy);
        const cols = layout.cellsPerRow;

        // Full label on hover only (e.g. safeguard title / category name)
        const headerHover = (() => {
            if (heatmapGroupBy === 'safeguard' && items[0]?.safeguard_title) {
                return `${key} — ${items[0].safeguard_title} (${items.length})`;
            }
            if (heatmapGroupBy === 'category') {
                return `${key} (${items.length})`;
            }
            return `${title} (${meta})`;
        })();

        html += `
            <div class="d3fend-column" data-group="${escapeAttr(key)}" style="flex: 1 1 ${layout.colWidth}px; min-width: ${Math.min(layout.colWidth, 120)}px;">
                <div class="d3fend-header compact" title="${escapeAttr(headerHover)}">
                    <span class="d3fend-header-title">${escapeAttr(title)}</span>
                    <span class="d3fend-header-meta">${escapeAttr(meta)}</span>
                </div>
                <div class="d3fend-content grid-view" style="grid-template-columns: repeat(${cols}, minmax(${layout.cell}px, 1fr));">
        `;

        items.forEach(item => {
            const risk = riskScoreOf(item);
            const passRate = passRateOf(item);
            const rateCls = riskClass(risk, item.total);
            const conf = item.mapping_confidence ? item.mapping_confidence : 'unmapped';
            const status = item.mapping_status || (item.attack_id ? 'mapped' : 'unmapped');
            const sg = item.cis_safeguard_id || 'CISNone';
            const section = item.cis_section || item.cis_id || '';
            const pname = item.policy_name || `CIS ${section || '?'}`;
            const atkList = (item.attack_ids && item.attack_ids.length)
                ? item.attack_ids.join(', ')
                : (item.attack_id || '');
            const tooltip = [
                pname,
                `Policy: ${item.policy_id ?? '—'} · Section: ${section || '—'}`,
                `Safeguard family: ${sg}${item.safeguard_title ? ' — ' + item.safeguard_title : ''}`,
                `${item.platform || 'os?'} · ${item.benchmark || ''}`,
                `Category: ${item.cis_category || '—'}`,
                `D3FEND: ${item.d3fend_technique || 'Unmapped'} (${item.d3fend_tactic || '—'}) [${conf}]`,
                atkList
                    ? `MITRE: ${atkList}${item.mapping_coarse ? ' (coarse primary)' : ''} · ${status}`
                    : `MITRE: (none) · ${status}`,
                item.mapping_rationale ? `Why: ${item.mapping_rationale}` : '',
                `Pass: ${Math.round(passRate)}% (${item.pass}/${item.total}) · Fleet risk: ${Math.round(risk)}%`
            ].filter(Boolean).join('\n');
            const aria = `${pname}, section ${section || 'none'}, family ${sg}, fleet risk ${Math.round(risk)} percent`;

            html += `
                <button type="button"
                    class="d3fend-heatmap-cell ${rateCls}"
                    style="width: ${layout.cell}px; height: ${layout.cell}px; min-width: ${layout.cell}px; min-height: ${layout.cell}px;"
                    data-tooltip="${escapeAttr(tooltip)}"
                    data-policy-id="${escapeAttr(item.policy_id ?? '')}"
                    data-cis-id="${escapeAttr(section)}"
                    data-safeguard="${escapeAttr(sg)}"
                    data-platform="${escapeAttr(item.platform || '')}"
                    data-attack-id="${escapeAttr(item.attack_id || '')}"
                    aria-label="${escapeAttr(aria)}">
                    <span class="d3fend-cell-id">${escapeAttr(section || sg.replace(/^CIS/, ''))}</span>
                </button>
            `;
        });

        html += '</div></div>';
    });

    html += '</div>';
    container.innerHTML = DOMPurify.sanitize(html, {
        ADD_ATTR: ['aria-label', 'data-tooltip', 'data-cis-id', 'data-attack-id', 'data-platform', 'data-safeguard', 'data-policy-id', 'style']
    });
}

// Update violations list
function updateViolations(data) {
    const container = document.getElementById('violations-list');
    if (!container) return;
    const safeguards = uniqueByPolicyId(data.safeguards || []);

    // Sort by failure count; show pass rate so identical fail counts still differentiate
    const sorted = [...safeguards]
        .filter(s => (s.fail || 0) > 0)
        .sort((a, b) => (b.fail - a.fail) || ((a.pass_rate || 0) - (b.pass_rate || 0)))
        .slice(0, 10);

    if (sorted.length === 0) {
        container.innerHTML = '<p style="color: var(--text-secondary); text-align: center;">No violations found</p>';
        return;
    }

    let html = '';
    sorted.forEach(s => {
        const rate = Math.round(s.pass_rate || 0);
        const control = s.control ? ` · ${s.control}` : '';
        const key = auditPolicyKey(s);
        html += `
            <div class="violation-item" data-policy-id="${escapeAttr(key)}" role="button" tabindex="0">
                <span class="violation-name" title="${escapeAttr(s.name)}">${escapeAttr(s.name)}</span>
                <span class="violation-count">${s.fail} hosts · ${rate}% pass${control}</span>
            </div>
        `;
    });
    container.innerHTML = DOMPurify.sanitize(html, { ADD_ATTR: ['data-policy-id'] });
    container.querySelectorAll('.violation-item[data-policy-id]').forEach(item => {
        const open = () => openAuditForPolicy(item.dataset.policyId);
        item.addEventListener('click', open);
        item.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                open();
            }
        });
    });
}

// Update controls status
function updateControlsStatus(data) {
    const container = document.getElementById('controls-status');
    if (!container) return;
    const safeguards = uniqueByPolicyId(data.safeguards || []);

    if (safeguards.length === 0) {
        container.innerHTML = '<p style="color: var(--text-secondary); text-align: center;">No controls data</p>';
        return;
    }

    let html = '';
    safeguards.slice(0, 12).forEach(s => {
        const passRate = s.pass_rate || 0;
        let statusClass = 'critical';
        if (passRate >= 80) statusClass = 'good';
        else if (passRate >= 50) statusClass = 'warning';
        const label = s.control || s.name || s.policy_name || s.safeguard_id;

        html += `
            <div class="control-item ${statusClass}" data-policy-id="${escapeAttr(auditPolicyKey(s))}">
                <span class="control-name" title="${escapeAttr(s.name || '')}">${escapeAttr(label)}</span>
                <span class="control-rate">${Math.round(passRate)}%</span>
            </div>
        `;
    });
    container.innerHTML = DOMPurify.sanitize(html, { ADD_ATTR: ['data-policy-id'] });
}




// ===== NEW SPECIALIZED PAGES =====

// 1. SECURITY ARCHITECTURE (MITRE ATT&CK Matrix)
async function populateArchitecturePage(heatmapData, summary) {
    try {
        const data = await fetch(`${API_BASE}/architecture?${new URLSearchParams(currentFilters)}`).then(r => r.json());

        // 1. Update Compliance Gauge
        const compliance = data.overall_compliance || data.defensive_score || 0;
        const gaugeArc = document.getElementById('compliance-gauge-arc');
        const gaugeValue = document.getElementById('arch-compliance');

        if (gaugeArc && gaugeValue) {
            const circumference = 339.3; // 2 * PI * 54
            const offset = circumference - (compliance / 100) * circumference;
            gaugeArc.style.strokeDashoffset = offset;
            gaugeValue.textContent = `${Math.round(compliance)}%`;

            // Color based on compliance level
            const color = compliance >= 80 ? 'var(--success-green)' :
                compliance >= 60 ? '#84CC16' :
                    compliance >= 40 ? 'var(--warning-orange)' : 'var(--danger-red)';
            gaugeArc.style.stroke = color;
            gaugeValue.style.color = color;
        }

        // 2. Mini trend bars — only when backend provides history (never fabricate)
        const miniBars = document.getElementById('arch-mini-bars');
        if (miniBars) {
            const series = Array.isArray(data.trend_series) ? data.trend_series : [];
            if (series.length && data.history_available) {
                const max = Math.max(...series.map(Number), 1);
                miniBars.innerHTML = DOMPurify.sanitize(
                    series.map(v => {
                        const h = Math.max(4, Math.round((Number(v) / max) * 18));
                        return `<div class="bar" style="height: ${h}px;"></div>`;
                    }).join('')
                );
            } else {
                miniBars.innerHTML = '';
                miniBars.classList.add('hidden');
            }
        }

        // 3. Compliance by MITRE Tactic bars
        const tacticBarsContainer = document.getElementById('tactic-compliance-bars');
        if (tacticBarsContainer && data.compliance_by_tactic) {
            const tacticAbbrev = {
                'Reconnaissance': 'RC', 'Resource Development': 'RD', 'Initial Access': 'IA',
                'Execution': 'EX', 'Persistence': 'PE', 'Privilege Escalation': 'PR',
                'Defense Evasion': 'DE', 'Credential Access': 'CA', 'Discovery': 'DI',
                'Lateral Movement': 'LM', 'Collection': 'CO', 'Command and Control': 'C2',
                'Exfiltration': 'EF', 'Impact': 'IM'
            };

            let barsHtml = '';
            Object.entries(data.compliance_by_tactic).slice(0, 7).forEach(([tactic, rate]) => {
                const color = rate >= 80 ? 'var(--success-green)' :
                    rate >= 60 ? '#84CC16' :
                        rate >= 40 ? 'var(--warning-orange)' : 'var(--danger-red)';
                barsHtml += `
                    <div class="tactic-bar">
                        <span class="label">${tacticAbbrev[tactic] || tactic.substring(0, 2)}</span>
                        <div class="bar-container">
                            <div class="bar-fill" style="width: ${rate}%; background: ${color};"></div>
                        </div>
                        <span class="rate" style="color: ${color};">${rate}%</span>
                    </div>`;
            });
            tacticBarsContainer.innerHTML = DOMPurify.sanitize(barsHtml);
        }

        // 4. Top 5 Weakest TTPs
        const weakestList = document.getElementById('top-weakest-list');
        if (weakestList && data.top_5_weakest) {
            weakestList.innerHTML = DOMPurify.sanitize(data.top_5_weakest.map(t => `
                <li>
                    <span class="ttp-name" title="${t.name}">${t.name}</span>
                    <span class="ttp-rate">${t.rate}%</span>
                </li>
            `).join(''));
        }

        // 5. Top 3 Strongest TTPs
        const strongestList = document.getElementById('top-strongest-list');
        if (strongestList && data.top_3_strongest) {
            strongestList.innerHTML = DOMPurify.sanitize(data.top_3_strongest.map(t => `
                <li>
                    <span class="ttp-name" title="${t.name}">${t.name}</span>
                    <span class="ttp-rate">${t.rate}%</span>
                </li>
            `).join(''));
        }

        // 6–7. Gains / Losses — only when real history exists (never fabricate)
        const gainsList = document.getElementById('gains-list');
        const lossesList = document.getElementById('losses-list');
        const noHistory = data.history_available === false ||
            !(data.biggest_gains && data.biggest_gains.length) ||
            !(data.biggest_losses && data.biggest_losses.length);

        if (gainsList) {
            if (noHistory || !data.biggest_gains?.length) {
                gainsList.innerHTML = '<li><span class="change-name">No historical trend data yet</span></li>';
            } else {
                gainsList.innerHTML = DOMPurify.sanitize(data.biggest_gains.map(g => `
                    <li>
                        <span class="change-name" title="${g.name}">${g.name}</span>
                        <span class="change-value gain">${g.change}</span>
                    </li>
                `).join(''));
            }
        }
        if (lossesList) {
            if (noHistory || !data.biggest_losses?.length) {
                lossesList.innerHTML = '<li><span class="change-name">No historical trend data yet</span></li>';
            } else {
                lossesList.innerHTML = DOMPurify.sanitize(data.biggest_losses.map(l => `
                    <li>
                        <span class="change-name" title="${l.name}">${l.name}</span>
                        <span class="change-value loss">${l.change}</span>
                    </li>
                `).join(''));
            }
        }

        // 8. Render MITRE ATT&CK Matrix
        renderMitreMatrix(data.mitre_matrix);

    } catch (e) { console.error('Architecture error:', e); }
}

// Render MITRE ATT&CK Matrix Heatmap
function renderMitreMatrix(matrixData) {
    const container = document.getElementById('mitre-matrix');
    if (!container) return;

    if (!matrixData || matrixData.length === 0) {
        container.innerHTML = '<p style="color: var(--text-secondary); text-align: center; padding: 40px;">No MITRE ATT&CK mapping data available</p>';
        return;
    }

    let html = '';

    matrixData.forEach(tacticData => {
        const tactic = tacticData.tactic;
        const tacticRate = tacticData.rate || 0;
        const techniques = tacticData.techniques || [];

        html += `
            <div class="mitre-tactic-column">
                <div class="mitre-tactic-header">
                    <span class="tactic-name">${tactic}</span>
                    <span class="tactic-rate">${tacticRate}%</span>
                </div>`;

        techniques.forEach(tech => {
            const rate = tech.rate || 0;
            const colorClass = rate >= 80 ? 'rate-excellent' :
                rate >= 60 ? 'rate-good' :
                    rate >= 40 ? 'rate-warning' : 'rate-danger';

            html += `
                <div class="mitre-technique-cell ${colorClass}" 
                     data-tooltip="${tech.id}: ${tech.name}\nCompliance: ${rate}%">
                    <span class="tech-name">${tech.name}</span>
                    <span class="tech-rate">${rate}%</span>
                </div>`;
        });

        html += '</div>';
    });

    container.innerHTML = DOMPurify.sanitize(html);
    // Tooltips use document-level handlers in setupTooltip()
}

// 2. COMPLIANCE AUDIT (Enhanced View)
let auditData = [];
let currentAuditFilter = null;
let currentAuditSearch = '';

async function populateAuditPage(summary) {
    try {
        const resp = await fetch(`${API_BASE}/safeguard-compliance?${new URLSearchParams(currentFilters)}`).then(r => r.json());
        auditData = uniqueByPolicyId(resp.safeguards || []);

        // 0. Update Platform Label
        const platformLabel = document.getElementById('audit-platform-label');
        if (platformLabel) {
            const currentPlatform = currentFilters.platform || 'All Platforms';
            platformLabel.textContent = currentPlatform === 'All Platforms' ? 'All Platforms' : currentPlatform;
        }

        // 1. Header counts distinct policies, never shared CIS4.8 families
        const total = auditData.length;
        const passed = auditData.filter(s => s.pass > 0 && s.fail === 0).length;
        const failed = auditData.filter(s => s.fail > 0).length;
        const rate = total > 0 ? (passed / total * 100) : 0;

        document.getElementById('audit-compliance-rate').textContent = `${Math.round(rate)}%`;
        document.getElementById('audit-pass-count').textContent = passed;
        document.getElementById('audit-fail-count').textContent = failed;

        // 2. Setup filters
        const passBtn = document.getElementById('audit-filter-pass');
        const failBtn = document.getElementById('audit-filter-fail');
        const searchInput = document.getElementById('audit-search-input');

        passBtn.onclick = () => {
            currentAuditFilter = currentAuditFilter === 'pass' ? null : 'pass';
            selectedAuditPolicyId = null;
            updateAuditUI();
        };
        failBtn.onclick = () => {
            currentAuditFilter = currentAuditFilter === 'fail' ? null : 'fail';
            selectedAuditPolicyId = null;
            updateAuditUI();
        };

        // Add Search Listener
        if (searchInput) {
            searchInput.oninput = (e) => {
                currentAuditSearch = e.target.value.toLowerCase().trim();
                selectedAuditPolicyId = null;
                updateAuditUI();
            };
        }

        // 3. Initial render
        updateAuditUI();

    } catch (e) { console.error('Audit error:', e); }
}

function updateAuditUI() {
    const listContainer = document.getElementById('audit-policy-list');
    const passBtn = document.getElementById('audit-filter-pass');
    const failBtn = document.getElementById('audit-filter-fail');

    // Update button states
    passBtn.classList.toggle('active', currentAuditFilter === 'pass');
    failBtn.classList.toggle('active', currentAuditFilter === 'fail');

    // Filter data
    let filtered = uniqueByPolicyId(auditData);

    // 1. Status Filter
    if (currentAuditFilter === 'pass') filtered = filtered.filter(s => s.fail === 0);
    if (currentAuditFilter === 'fail') filtered = filtered.filter(s => s.fail > 0);

    // 2. Search: name, benchmark section, policy_id, and every family sid
    if (currentAuditSearch) {
        filtered = filtered.filter(s => policyMatchesAuditSearch(s, currentAuditSearch));
    }

    // Render list
    if (filtered.length === 0) {
        listContainer.innerHTML = `<p style="padding: 20px; color: var(--text-secondary); text-align: center;">No policies found ${currentAuditSearch ? `matching "${currentAuditSearch}"` : ''}</p>`;
        return;
    }

    listContainer.innerHTML = filtered.map(s => {
        const statusClass = s.fail === 0 ? 'control-badge-pass' : s.pass === 0 ? 'control-badge-fail' : 'control-badge-risk';
        const rateClass = s.pass_rate >= 100 ? 'highlight-pass' : s.pass_rate >= 60 ? '' : 'highlight-fail';
        const key = auditPolicyKey(s);
        return `
        <div class="audit-policy-item" data-policy-id="${escapeAttr(key)}">
            <span class="control-badge ${statusClass}"></span>
            <span class="control-name" title="${escapeAttr(s.name || '')}">${escapeAttr(s.name || s.safeguard_id)}</span>
            <span class="control-rate ${rateClass}" title="${s.pass} pass / ${s.fail} fail">${Math.round(s.pass_rate)}%</span>
        </div>
    `;}).join('');

    // Attach click handlers
    listContainer.querySelectorAll('.audit-policy-item').forEach(item => {
        item.onclick = () => {
            // UI state
            listContainer.querySelectorAll('.audit-policy-item').forEach(i => i.classList.remove('active'));
            item.classList.add('active');

            selectedAuditPolicyId = item.dataset.policyId;
            const policy = findAuditPolicy(item.dataset.policyId);
            showPolicyDetails(policy);
        };
    });

    if (filtered.length > 0) {
        const preferred = selectedAuditPolicyId
            ? listContainer.querySelector(policyIdSelector(selectedAuditPolicyId))
            : null;
        (preferred || listContainer.querySelector('.audit-policy-item')).click();
    }
}

function showPolicyDetails(policy) {
    if (!policy) return;

    // Update compliance metrics
    const passHostsEl = document.getElementById('policy-pass-hosts');
    const failHostsEl = document.getElementById('policy-fail-hosts');
    const totalHostsEl = document.getElementById('policy-total-hosts');
    const passRateEl = document.getElementById('policy-pass-rate');
    const miniFillEl = document.getElementById('policy-mini-fill');

    if (passHostsEl) passHostsEl.textContent = policy.pass ?? '--';
    if (failHostsEl) failHostsEl.textContent = policy.fail ?? '--';
    if (totalHostsEl) totalHostsEl.textContent = (policy.pass || 0) + (policy.fail || 0);
    if (passRateEl) passRateEl.textContent = `${Math.round(policy.pass_rate ?? 0)}%`;
    if (miniFillEl) {
        miniFillEl.style.width = `${policy.pass_rate ?? 0}%`;
        miniFillEl.style.background = (policy.pass_rate ?? 0) >= 80 ? 'var(--success)' :
            (policy.pass_rate ?? 0) >= 50 ? 'var(--warning)' : 'var(--brand-500)';
    }

    document.getElementById('policy-description').textContent = policy.description || 'No description available for this policy.';
    document.getElementById('policy-resolution').textContent = policy.resolution || 'No resolution steps defined.';
    document.getElementById('policy-query').textContent = policy.query || '-- No query available';
}

// 3. EXECUTIVE STRATEGY (CISO Command Center)
let roadmapChart = null;

async function populateStrategyPage(summary, heatmapData) {
    try {
        const data = await fetch(`${API_BASE}/strategy?${new URLSearchParams(currentFilters)}`).then(r => r.json());

        // 1. Animated Posture Gauge
        const postureScore = data.posture_score || 0;
        document.getElementById('posture-score-value').textContent = Math.round(postureScore);

        // Animate gauge arc
        const gaugeArc = document.getElementById('gauge-arc');
        const arcLength = 251.2; // Path length for semicircle
        const offset = arcLength - (arcLength * postureScore / 100);
        gaugeArc.style.strokeDashoffset = offset;

        // Animate gauge needle position
        const needle = document.getElementById('gauge-needle');
        const angle = -90 + (180 * postureScore / 100); // -90 to 90 degrees
        const rad = angle * Math.PI / 180;
        const cx = 100 + 80 * Math.cos(rad);
        const cy = 100 + 80 * Math.sin(rad);
        needle.setAttribute('cx', cx);
        needle.setAttribute('cy', cy);

        // 2. Maturity Level
        const maturity = data.maturity_level || 1;
        document.querySelector('#maturity-badge .maturity-number').textContent = maturity;
        document.querySelectorAll('.scale-item').forEach(el => {
            el.classList.remove('active');
            if (parseInt(el.dataset.level) <= maturity) {
                el.classList.add('active');
            }
        });

        // 3. Strategic Metrics
        document.getElementById('coverage-value').textContent = `${data.compliance_coverage || 0}%`;
        document.getElementById('debt-value').textContent = data.security_debt || '--';
        document.getElementById('risk-value').textContent = data.risk_exposure || 0;
        // Velocity requires history; do not show fabricated 0
        const velEl = document.getElementById('velocity-value');
        if (velEl) {
            velEl.textContent = (data.velocity_available && data.remediation_velocity != null)
                ? `${data.remediation_velocity}`
                : '—';
            velEl.title = data.velocity_available
                ? 'Remediation velocity'
                : 'No historical snapshots yet — velocity unavailable';
        }

        // 4. Compliance Roadmap Chart (Chart.js) — height constrained by .strategy-chart-body
        const ctx = document.getElementById('roadmap-chart');
        if (ctx) {
            const roadmap = data.roadmap || [];
            const labels = roadmap.map(r => r.month);
            const projectedData = roadmap.map(r => r.projected);
            const actualData = roadmap.map(r => r.actual);

            if (roadmapChart) {
                roadmapChart.destroy();
            }

            roadmapChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Projected target',
                            data: projectedData,
                            borderColor: 'rgba(59, 130, 246, 0.5)',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            borderDash: [5, 5],
                            fill: false,
                            tension: 0.3,
                            spanGaps: true,
                            pointRadius: 2,
                            borderWidth: 2
                        },
                        {
                            label: 'Actual (measured)',
                            data: actualData,
                            borderColor: '#10B981',
                            backgroundColor: 'rgba(16, 185, 129, 0.2)',
                            fill: false,
                            tension: 0,
                            pointRadius: 3,
                            pointBackgroundColor: '#10B981',
                            spanGaps: false,
                            borderWidth: 2
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    layout: {
                        padding: { top: 4, right: 8, bottom: 0, left: 0 }
                    },
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: {
                            grid: { color: 'rgba(255,255,255,0.05)' },
                            ticks: {
                                color: 'rgba(255,255,255,0.6)',
                                maxRotation: 0,
                                autoSkip: true,
                                maxTicksLimit: 8,
                                font: { size: 10 }
                            }
                        },
                        y: {
                            min: 0,
                            max: 100,
                            grid: { color: 'rgba(255,255,255,0.05)' },
                            ticks: {
                                color: 'rgba(255,255,255,0.6)',
                                callback: v => v + '%',
                                font: { size: 10 },
                                maxTicksLimit: 5
                            }
                        }
                    }
                }
            });
        }

        // 5. Team Leaderboard
        const leaderboard = document.getElementById('team-leaderboard');
        const teams = data.team_leaderboard || [];
        leaderboard.innerHTML = DOMPurify.sanitize(teams.map((team, i) => {
            const rankClass = i === 0 ? 'gold' : i === 1 ? 'silver' : i === 2 ? 'bronze' : '';
            // The API reports trend 'unknown' with a null delta whenever a team has
            // fewer than two snapshot dates — a permanent, valid state, not an
            // error. Rendering the delta unconditionally produced the literal
            // "→ null%". 'down' already carries its own sign in delta, so the
            // arrow alone is the direction and the number is shown absolute.
            const trendIcon = team.trend === 'up' ? '↑' : team.trend === 'down' ? '↓' : '→';
            const hasDelta = team.trend === 'up' || team.trend === 'down';
            const trendText = hasDelta
                ? `${trendIcon} ${Math.abs(team.delta)}%`
                : (team.trend === 'unknown' ? '–' : '→');
            const trendTitle = team.trend === 'unknown'
                ? 'Not enough snapshot history yet to compute a trend'
                : `Trend: ${team.trend}`;
            return `
                <div class="leaderboard-item ${rankClass}">
                    <div class="leaderboard-rank">${team.rank}</div>
                    <div class="leaderboard-name">${team.name}</div>
                    <div class="leaderboard-score">${team.score}%</div>
                    <div class="leaderboard-trend ${team.trend}" title="${trendTitle}">${trendText}</div>
                </div>
            `;
        }).join('')) || '<p style="color:var(--text-secondary);text-align:center;">No team data</p>';

        // 6. Priority Actions
        const priorities = document.getElementById('priority-actions');
        const prios = data.priorities || [];
        priorities.innerHTML = DOMPurify.sanitize(prios.map((p, i) => `
            <div class="priority-item">
                <div class="priority-number">${i + 1}</div>
                <div class="priority-content">
                    <div class="priority-policy">${p.policy}</div>
                    <div class="priority-meta">
                        <span>Control ${p.control}</span>
                        <span>${p.affected} affected</span>
                    </div>
                </div>
                <div class="priority-badges">
                    <span class="priority-badge impact-${p.impact.toLowerCase()}">${p.impact} Impact</span>
                    <span class="priority-badge effort-${p.effort.toLowerCase()}">${p.effort} Effort</span>
                </div>
            </div>
        `).join('')) || '<p style="color:var(--text-secondary);text-align:center;padding:20px;">All policies passing! 🎉</p>';



    } catch (e) {
        console.error('Strategy error:', e);
    }
}

// Utility for Matrix Rendering (compact D3FEND heat map in secondary containers)
function renderD3FENDMatrix(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const heatmapData = (data && data.heatmap) ? data.heatmap : (Array.isArray(data) ? data : []);

    if (heatmapData.length === 0) {
        container.innerHTML = '<p class="heatmap-empty">No mapping data</p>';
        return;
    }

    const groups = {};
    heatmapData.forEach(item => {
        const tactic = item.d3fend_tactic || 'Unmapped';
        if (!groups[tactic]) groups[tactic] = [];
        groups[tactic].push(item);
    });

    const sortedTactics = sortGroupKeys(Object.keys(groups), 'd3fend');
    let html = '<div class="d3fend-matrix">';
    sortedTactics.forEach(tactic => {
        const items = groups[tactic];
        html += `<div class="d3fend-column">
            <div class="d3fend-header compact">
                <span class="d3fend-header-title">${escapeAttr(tactic)}</span>
                <span class="d3fend-header-meta">${items.length}</span>
            </div>
            <div class="d3fend-content grid-view">`;
        items.forEach(item => {
            const passRate = passRateOf(item);
            const rateCls = rateClass(passRate, item.total);
            const tooltip = `${item.policy_name || 'CIS ' + (item.cis_id || '')}\nSection ${item.cis_id || '—'} · ${item.d3fend_technique || 'Unmapped'} · ${Math.round(passRate)}%`;
            html += `<button type="button" class="d3fend-heatmap-cell ${rateCls}" data-tooltip="${escapeAttr(tooltip)}" data-policy-id="${escapeAttr(item.policy_id ?? '')}" aria-label="${escapeAttr(tooltip)}">
                <span class="d3fend-cell-id">${escapeAttr(item.cis_id)}</span>
            </button>`;
        });
        html += '</div></div>';
    });
    html += '</div>';
    container.innerHTML = DOMPurify.sanitize(html, { ADD_ATTR: ['aria-label', 'data-tooltip', 'data-policy-id'] });
}

// ===== SETTINGS PAGE =====

const DEFAULT_CONFIG = {
    impact_high_threshold: 5,
    impact_medium_threshold: 2,
    effort_low_keywords: ["Ensure", "Set"],
    effort_high_keywords: ["Manual", "Review"],
    security_debt_hours_per_issue: 0.5,
    risk_exposure_multiplier: 2,
    framework_cis_multiplier: 0.95,
    framework_nist_multiplier: 0.88,
    framework_iso_multiplier: 0.82
};

const API_TOKEN_STORAGE_KEY = 'fleet_cis_api_token';

function getStoredApiToken() {
    try {
        return sessionStorage.getItem(API_TOKEN_STORAGE_KEY) || '';
    } catch {
        return '';
    }
}

function setStoredApiToken(token) {
    try {
        if (token) sessionStorage.setItem(API_TOKEN_STORAGE_KEY, token);
        else sessionStorage.removeItem(API_TOKEN_STORAGE_KEY);
    } catch {
        /* private mode — ignore */
    }
}

async function loadConfigSettings() {
    try {
        const tokenInput = document.getElementById('config-api-token');
        if (tokenInput) tokenInput.value = getStoredApiToken();

        const config = await fetch(`${API_BASE}/config`).then(r => r.json());

        // Populate UI with current values
        if (config.impact_high_threshold) {
            document.getElementById('config-impact-high').value = config.impact_high_threshold.value;
        }
        if (config.impact_medium_threshold) {
            document.getElementById('config-impact-medium').value = config.impact_medium_threshold.value;
        }
        if (config.effort_low_keywords) {
            const keywords = config.effort_low_keywords.value;
            document.getElementById('config-effort-low').value = Array.isArray(keywords) ? keywords.join(', ') : keywords;
        }
        if (config.effort_high_keywords) {
            const keywords = config.effort_high_keywords.value;
            document.getElementById('config-effort-high').value = Array.isArray(keywords) ? keywords.join(', ') : keywords;
        }
        if (config.risk_exposure_multiplier) {
            document.getElementById('config-risk-multiplier').value = config.risk_exposure_multiplier.value;
        }
        if (config.security_debt_hours_per_issue) {
            document.getElementById('config-debt-hours').value = config.security_debt_hours_per_issue.value;
        }
        if (config.framework_cis_multiplier) {
            document.getElementById('config-framework-cis').value = config.framework_cis_multiplier.value;
        }
        if (config.framework_nist_multiplier) {
            document.getElementById('config-framework-nist').value = config.framework_nist_multiplier.value;
        }
        if (config.framework_iso_multiplier) {
            document.getElementById('config-framework-iso').value = config.framework_iso_multiplier.value;
        }
    } catch (e) {
        console.error('Error loading config:', e);
    }
}

async function saveConfigSettings() {
    const config = {
        impact_high_threshold: parseInt(document.getElementById('config-impact-high').value),
        impact_medium_threshold: parseInt(document.getElementById('config-impact-medium').value),
        effort_low_keywords: document.getElementById('config-effort-low').value.split(',').map(s => s.trim()).filter(s => s),
        effort_high_keywords: document.getElementById('config-effort-high').value.split(',').map(s => s.trim()).filter(s => s),
        risk_exposure_multiplier: parseFloat(document.getElementById('config-risk-multiplier').value),
        security_debt_hours_per_issue: parseFloat(document.getElementById('config-debt-hours').value),
        framework_cis_multiplier: parseFloat(document.getElementById('config-framework-cis').value),
        framework_nist_multiplier: parseFloat(document.getElementById('config-framework-nist').value),
        framework_iso_multiplier: parseFloat(document.getElementById('config-framework-iso').value)
    };

    try {
        const tokenInput = document.getElementById('config-api-token');
        const token = (tokenInput?.value || getStoredApiToken() || '').trim();
        if (!token) {
            showError('API token required to save (set DASHBOARD_API_TOKEN on server)');
            return;
        }
        setStoredApiToken(token);

        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        };
        const resp = await fetch(`${API_BASE}/config`, {
            method: 'PUT',
            headers,
            body: JSON.stringify(config)
        });
        const result = await resp.json().catch(() => ({}));

        if (resp.status === 401) {
            showError('Unauthorized — check API token');
            return;
        }
        if (resp.status === 503) {
            showError(result.error || 'Write API disabled on server');
            return;
        }
        if (result.success) {
            showSuccess(`Configuration saved! Updated ${result.updated} settings.`);
            await updateDashboard();
        } else {
            showError(result.error || 'Failed to save configuration');
        }
    } catch (e) {
        console.error('Error saving config:', e);
        showError('Error saving configuration');
    }
}

function resetConfigSettings() {
    document.getElementById('config-impact-high').value = DEFAULT_CONFIG.impact_high_threshold;
    document.getElementById('config-impact-medium').value = DEFAULT_CONFIG.impact_medium_threshold;
    document.getElementById('config-effort-low').value = DEFAULT_CONFIG.effort_low_keywords.join(', ');
    document.getElementById('config-effort-high').value = DEFAULT_CONFIG.effort_high_keywords.join(', ');
    document.getElementById('config-risk-multiplier').value = DEFAULT_CONFIG.risk_exposure_multiplier;
    document.getElementById('config-debt-hours').value = DEFAULT_CONFIG.security_debt_hours_per_issue;
    document.getElementById('config-framework-cis').value = DEFAULT_CONFIG.framework_cis_multiplier;
    document.getElementById('config-framework-nist').value = DEFAULT_CONFIG.framework_nist_multiplier;
    document.getElementById('config-framework-iso').value = DEFAULT_CONFIG.framework_iso_multiplier;
}

function showSuccess(message) {
    const banner = document.createElement('div');
    banner.style.cssText = 'background: #10B981; color: white; padding: 12px 20px; border-radius: 8px; font-weight: 600; position: fixed; top: 20px; right: 20px; z-index: 9999; box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);';
    banner.textContent = `✅ ${message}`;
    document.body.appendChild(banner);
    setTimeout(() => banner.remove(), 4000);
}

function setupSettingsListeners() {
    const saveBtn = document.getElementById('save-config');
    const resetBtn = document.getElementById('reset-config');

    if (saveBtn) saveBtn.addEventListener('click', saveConfigSettings);
    if (resetBtn) resetBtn.addEventListener('click', resetConfigSettings);
}

// --- Sync Status Indicator ---
async function updateSyncStatus() {
    const textEl = document.getElementById('sync-status-text');
    const iconEl = document.getElementById('sync-icon');
    if (!textEl) return;

    try {
        const data = await fetch(`${API_BASE}/sync-status`).then(r => r.json());

        if (!data.last_sync || data.status === 'never') {
            textEl.textContent = 'never';
            return;
        }

        // Show spinning icon while sync is running
        if (data.status === 'running') {
            textEl.textContent = 'syncing...';
            if (iconEl) iconEl.classList.add('fa-spin');
            return;
        }

        if (iconEl) iconEl.classList.remove('fa-spin');

        // Format as relative time
        const syncTime = new Date(data.last_sync);
        const now = new Date();
        const diffMs = now - syncTime;
        const diffSec = Math.floor(diffMs / 1000);
        const diffMin = Math.floor(diffSec / 60);
        const diffHr = Math.floor(diffMin / 60);

        let relativeText;
        if (diffSec < 30) relativeText = 'just now';
        else if (diffMin < 1) relativeText = `${diffSec}s ago`;
        else if (diffMin < 60) relativeText = `${diffMin} min ago`;
        else if (diffHr < 24) relativeText = `${diffHr}h ago`;
        else relativeText = syncTime.toLocaleDateString();

        textEl.textContent = relativeText;

        if (data.status === 'failed') {
            textEl.textContent += ' ⚠';
            textEl.title = `Last sync failed: ${data.error || 'Unknown error'}`;
        } else if (data.degraded) {
            // A sync can succeed overall while individual Fleet fetches failed, so
            // some policies were not refreshed. Without this the dashboard looked
            // identical to a clean sync and the partial failure stayed invisible.
            textEl.textContent += ' ⚠';
            textEl.title = `Last sync completed with errors: ${data.error || 'some fetches failed'}`;
        }
    } catch (e) {
        textEl.textContent = 'offline';
    }
}

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
    init();
    loadConfigSettings();
    setupSettingsListeners();
});
