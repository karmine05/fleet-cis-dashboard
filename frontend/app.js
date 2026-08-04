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

// Setup event listeners
function setupEventListeners() {
    // Navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
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
    const pages = document.querySelectorAll('.page-content');
    pages.forEach(p => {
        p.classList.remove('active');
        p.style.opacity = '0';
        p.style.transform = 'translateY(10px)';
    });

    const targetPage = document.getElementById(page);
    targetPage.classList.add('active');

    // Trigger animation in next frame
    requestAnimationFrame(() => {
        targetPage.style.transition = 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)';
        targetPage.style.opacity = '1';
        targetPage.style.transform = 'translateY(0)';
    });

    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
        if (link.dataset.page === page) {
            link.classList.add('active');
        }
    });
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

// Update metrics (KPI cards)
function updateMetrics(summary) {
    const rate = summary.compliance_percentage || 0;
    const compliant = summary.compliant_devices || 0;
    const total = summary.total_devices || 0;
    const failed = summary.policies_failed || 0;

    const rateEl = document.getElementById('compliance-rate');
    const countEl = document.getElementById('compliant-count');
    const barEl = document.getElementById('compliance-bar');
    const deviceCountEl = document.getElementById('device-count');
    const criticalCountEl = document.getElementById('critical-count');
    const riskLevelEl = document.getElementById('risk-level');

    if (rateEl) rateEl.textContent = `${Math.round(rate)}%`;
    if (countEl) countEl.textContent = `${compliant} / ${total} Devices`;
    if (barEl) barEl.style.width = `${rate}%`;
    if (deviceCountEl) deviceCountEl.textContent = total;
    if (criticalCountEl) criticalCountEl.textContent = failed;

    // Risk level
    let riskLevel = 'LOW';
    // Edge case: no summary data
    if (!summary) {
        riskLevel = 'UNAVAILABLE';
    }
    // Edge case: no devices
    else if (total === 0) {
        riskLevel = 'UNAVAILABLE';
    }
    // Edge case: no policy results (mapping not possible)
    else if (summary.total_policy_results === 0) {
        riskLevel = 'HIGH';
    }
    // Normal calculation
    else if (rate < 50) riskLevel = 'CRITICAL';
    else if (rate < 70) riskLevel = 'HIGH';
    else if (rate < 85) riskLevel = 'MEDIUM';

    if (riskLevelEl) riskLevelEl.textContent = riskLevel;
}

// Update heatmap
// Update heatmap (D3FEND Matrix)
function updateHeatmap(data) {
    const container = document.getElementById('heatmap-container');
    const heatmapData = data.heatmap || [];

    if (heatmapData.length === 0) {
        container.innerHTML = '<p style="color: var(--text-secondary); text-align: center; padding: 40px;">No heatmap data available</p>';
        return;
    }

    // Group by D3FEND Tactic -> Technique
    const groups = {};
    const tactics = ['Model', 'Harden', 'Detect', 'Isolate', 'Deceive', 'Evict', 'Restore'];

    heatmapData.forEach(item => {
        const tactic = item.d3fend_tactic || 'Unmapped';
        if (!groups[tactic]) groups[tactic] = [];
        groups[tactic].push(item);
    });

    let html = '<div class="d3fend-matrix">';

    // Render columns (Compact D3FEND Matrix)
    const sortedTactics = Object.keys(groups).sort((a, b) => {
        const idxA = tactics.indexOf(a);
        const idxB = tactics.indexOf(b);
        return (idxA > -1 ? idxA : 99) - (idxB > -1 ? idxB : 99);
    });

    sortedTactics.forEach(tactic => {
        html += `
            <div class="d3fend-column">
                <div class="d3fend-header compact">${tactic}</div>
                <div class="d3fend-content grid-view">
        `;

        groups[tactic].forEach(item => {
            const passRate = item.total > 0 ? (item.pass / item.total * 100) : 0;
            const hue = Math.round(passRate * 1.2);
            const color = `hsla(${hue}, 70%, 55%, 0.85)`;

            // Detailed Tooltip Content - using literal newlines for CSS content:attr()
            const tooltipTitle = `Technique: ${item.d3fend_technique}`;
            const tooltipMeta = `CIS ${item.cis_id} | ATT&CK ${item.attack_id || 'N/A'}`;
            const tooltipStats = `Pass Rate: ${Math.round(passRate)}% (${item.pass}/${item.total})`;

            // String with literal newlines for CSS attr processing
            const fullTooltip = `${tooltipTitle}\n${tooltipMeta}\n${tooltipStats}`;

            html += `
                <div class="d3fend-heatmap-cell" 
                     style="background-color: ${color};" 
                     data-tooltip="${fullTooltip}">
                    <span class="d3fend-cell-id">${item.cis_id}</span>
                </div>
            `;
        });

        html += `</div></div>`;
    });

    html += '</div>';
    container.innerHTML = DOMPurify.sanitize(html);
}

// Update violations list
function updateViolations(data) {
    const container = document.getElementById('violations-list');
    if (!container) return;
    const safeguards = data.safeguards || [];

    // Sort by failure count
    const sorted = [...safeguards].sort((a, b) => b.fail - a.fail).slice(0, 10);

    if (sorted.length === 0) {
        container.innerHTML = '<p style="color: var(--text-secondary); text-align: center;">No violations found</p>';
        return;
    }

    let html = '';
    sorted.forEach(s => {
        html += `
            <div class="violation-item">
                <span class="violation-name">${s.name}</span>
                <span class="violation-count">${s.fail} failures</span>
            </div>
        `;
    });
    container.innerHTML = DOMPurify.sanitize(html);
}

// Update controls status
function updateControlsStatus(data) {
    const container = document.getElementById('controls-status');
    if (!container) return;
    const safeguards = data.safeguards || [];

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

        html += `
            <div class="control-item ${statusClass}">
                <span class="control-name">${s.control || s.safeguard_id}</span>
                <span class="control-rate">${Math.round(passRate)}%</span>
            </div>
        `;
    });
    container.innerHTML = DOMPurify.sanitize(html);
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

        // 2. Mini trend bars (simulated)
        const miniBars = document.getElementById('arch-mini-bars');
        if (miniBars) {
            const barHeights = [12, 14, 11, 16, 15, 18];
            miniBars.innerHTML = DOMPurify.sanitize(barHeights.map(h => `<div class="bar" style="height: ${h}px;"></div>`).join(''));
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

        // 6. Biggest Gains
        const gainsList = document.getElementById('gains-list');
        if (gainsList && data.biggest_gains) {
            gainsList.innerHTML = DOMPurify.sanitize(data.biggest_gains.map(g => `
                <li>
                    <span class="change-name" title="${g.name}">${g.name}</span>
                    <span class="change-value gain">${g.change}</span>
                </li>
            `).join('')) || '<li><span class="change-name">No recent gains</span></li>';
        }

        // 7. Biggest Losses
        const lossesList = document.getElementById('losses-list');
        if (lossesList && data.biggest_losses) {
            lossesList.innerHTML = DOMPurify.sanitize(data.biggest_losses.map(l => `
                <li>
                    <span class="change-name" title="${l.name}">${l.name}</span>
                    <span class="change-value loss">${l.change}</span>
                </li>
            `).join('')) || '<li><span class="change-name">No recent losses</span></li>';
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

    // Attach tooltip handlers
    container.querySelectorAll('.mitre-technique-cell').forEach(cell => {
        cell.addEventListener('mouseenter', showGlobalTooltip);
        cell.addEventListener('mouseleave', hideGlobalTooltip);
        cell.addEventListener('mousemove', moveGlobalTooltip);
    });
}

// 2. COMPLIANCE AUDIT (Enhanced View)
let auditData = [];
let currentAuditFilter = null;
let currentAuditSearch = '';

async function populateAuditPage(summary) {
    try {
        const resp = await fetch(`${API_BASE}/safeguard-compliance?${new URLSearchParams(currentFilters)}`).then(r => r.json());
        auditData = resp.safeguards || [];

        // 0. Update Platform Label
        const platformLabel = document.getElementById('audit-platform-label');
        if (platformLabel) {
            const currentPlatform = currentFilters.platform || 'All Platforms';
            platformLabel.textContent = currentPlatform === 'All Platforms' ? 'All Platforms' : currentPlatform;
        }

        // 1. Calculate and show header metrics
        // ... (existing logic for counts) ...
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
            updateAuditUI();
        };
        failBtn.onclick = () => {
            currentAuditFilter = currentAuditFilter === 'fail' ? null : 'fail';
            updateAuditUI();
        };

        // Add Search Listener
        if (searchInput) {
            searchInput.oninput = (e) => {
                currentAuditSearch = e.target.value.toLowerCase().trim();
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
    let filtered = auditData;

    // 1. Status Filter
    if (currentAuditFilter === 'pass') filtered = filtered.filter(s => s.fail === 0);
    if (currentAuditFilter === 'fail') filtered = filtered.filter(s => s.fail > 0);

    // 2. Search Filter (CIS Number or Name)
    if (currentAuditSearch) {
        filtered = filtered.filter(s => {
            const id = (s.safeguard_id || '').toLowerCase();
            const name = (s.name || '').toLowerCase();
            const control = (s.control || '').toLowerCase();
            return id.includes(currentAuditSearch) ||
                name.includes(currentAuditSearch) ||
                control.includes(currentAuditSearch);
        });
    }

    // Render list
    if (filtered.length === 0) {
        listContainer.innerHTML = `<p style="padding: 20px; color: var(--text-secondary); text-align: center;">No policies found ${currentAuditSearch ? `matching "${currentAuditSearch}"` : ''}</p>`;
        return;
    }

    listContainer.innerHTML = DOMPurify.sanitize(filtered.map(s => `
        <div class="audit-policy-item" data-id="${s.safeguard_id}">
            ${s.name}
        </div>
    `).join(''));

    // Attach click handlers
    listContainer.querySelectorAll('.audit-policy-item').forEach(item => {
        item.onclick = () => {
            // UI state
            listContainer.querySelectorAll('.audit-policy-item').forEach(i => i.classList.remove('active'));
            item.classList.add('active');

            // Find data
            const id = item.dataset.id;
            const policy = auditData.find(p => p.safeguard_id === id);
            showPolicyDetails(policy);
        };
    });

    // Auto-select first if available
    if (filtered.length > 0) {
        listContainer.querySelector('.audit-policy-item').click();
    }
}

function showPolicyDetails(policy) {
    if (!policy) return;

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
        document.getElementById('velocity-value').textContent = `${data.remediation_velocity || 0}/wk`;

        // 4. Compliance Roadmap Chart (Chart.js)
        const ctx = document.getElementById('roadmap-chart');
        if (ctx) {
            const roadmap = data.roadmap || [];
            const labels = roadmap.map(r => r.month);
            const projectedData = roadmap.map(r => r.projected);
            const actualData = roadmap.map(r => r.actual);

            // Destroy previous chart if exists
            if (roadmapChart) {
                roadmapChart.destroy();
            }

            roadmapChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Projected',
                            data: projectedData,
                            borderColor: 'rgba(59, 130, 246, 0.5)',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            borderDash: [5, 5],
                            fill: true,
                            tension: 0.4
                        },
                        {
                            label: 'Actual',
                            data: actualData,
                            borderColor: '#10B981',
                            backgroundColor: 'rgba(16, 185, 129, 0.2)',
                            fill: true,
                            tension: 0.4,
                            pointRadius: 4,
                            pointBackgroundColor: '#10B981'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: {
                            grid: { color: 'rgba(255,255,255,0.05)' },
                            ticks: { color: 'rgba(255,255,255,0.6)' }
                        },
                        y: {
                            min: 0,
                            max: 100,
                            grid: { color: 'rgba(255,255,255,0.05)' },
                            ticks: {
                                color: 'rgba(255,255,255,0.6)',
                                callback: v => v + '%'
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
            const trendIcon = team.trend === 'up' ? '↑' : team.trend === 'down' ? '↓' : '→';
            const trendText = team.trend !== 'stable' ? `${trendIcon} ${team.delta}%` : '→';
            return `
                <div class="leaderboard-item ${rankClass}">
                    <div class="leaderboard-rank">${team.rank}</div>
                    <div class="leaderboard-name">${team.name}</div>
                    <div class="leaderboard-score">${team.score}%</div>
                    <div class="leaderboard-trend ${team.trend}">${trendText}</div>
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

// Utility for Matrix Rendering
function renderD3FENDMatrix(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;

    // Safety check for data structure
    const heatmapData = (data && data.heatmap) ? data.heatmap : (Array.isArray(data) ? data : []);

    if (heatmapData.length === 0) {
        container.innerHTML = '<p style="color: var(--text-secondary); text-align: center; padding: 20px;">No mapping data</p>';
        return;
    }

    const tactics = ['Model', 'Harden', 'Detect', 'Isolate', 'Deceive', 'Evict', 'Restore'];
    const groups = {};
    heatmapData.forEach(item => {
        const tactic = item.d3fend_tactic || 'Unmapped';
        if (!groups[tactic]) groups[tactic] = [];
        groups[tactic].push(item);
    });

    let html = '<div class="d3fend-matrix">';
    tactics.forEach(tactic => {
        if (!groups[tactic]) return;
        html += `<div class="d3fend-column"><div class="d3fend-header compact">${tactic}</div><div class="d3fend-content grid-view">`;
        groups[tactic].forEach(item => {
            const passRate = item.total > 0 ? (item.pass / item.total * 100) : 0;
            const hue = Math.round(passRate * 1.2);
            const color = `hsla(${hue}, 70%, 55%, 0.85)`;
            html += `<div class="d3fend-heatmap-cell" style="background-color: ${color};" data-tooltip="CIS ${item.cis_id}: ${item.d3fend_technique}"></div>`;
        });
        html += `</div></div>`;
    });
    html += '</div>';
    container.innerHTML = DOMPurify.sanitize(html);
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

async function loadConfigSettings() {
    try {
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
        const resp = await fetch(`${API_BASE}/config`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        const result = await resp.json();

        if (result.success) {
            showSuccess(`Configuration saved! Updated ${result.updated} settings.`);
            // Refresh dashboard with new settings
            await updateDashboard();
        } else {
            showError('Failed to save configuration');
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
