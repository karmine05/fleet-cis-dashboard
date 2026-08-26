/* Alert Manager page. Relies on API_BASE, token helpers, and banners from app.js. */

const ALERT_KIND_LABELS = {
    policy_duration: 'Policy fail duration',
    scoped_duration: 'Scoped fail duration',
    compliance_threshold: 'Compliance threshold',
    label_safeguard: 'Label + policy/safeguard',
};

let alertCatalog = { policies: [], fleets: [], platforms: [], labels: [] };
let alertDestinations = [];
let alertSelectedPolicies = [];

function alertToken() {
    const input = document.getElementById('alert-api-token');
    const token = (input?.value || getStoredApiToken() || '').trim();
    if (token) setStoredApiToken(token);
    return token;
}

function alertHeaders(json = false) {
    const token = alertToken();
    const headers = { Authorization: `Bearer ${token}` };
    if (json) headers['Content-Type'] = 'application/json';
    return headers;
}

async function alertFetch(path, options = {}) {
    const token = alertToken();
    if (!token) {
        showError('API token required (set DASHBOARD_API_TOKEN)');
        return null;
    }
    // Write endpoints (including list/get) require Bearer. Merge last so a
    // caller that omits headers, or passes {}, cannot drop Authorization.
    const headers = Object.assign(
        {},
        options.headers || {},
        alertHeaders(options.body != null)
    );
    const resp = await fetch(`${API_BASE}${path}`, Object.assign({}, options, { headers }));
    const data = await resp.json().catch(() => ({}));
    if (resp.status === 401) {
        showError('Unauthorized — check API token');
        return null;
    }
    if (resp.status === 503) {
        showError(data.error || 'Write API disabled on server');
        return null;
    }
    if (!resp.ok) {
        showError(data.error || `Request failed (${resp.status})`);
        return null;
    }
    return data;
}

async function loadAlertManager() {
    const tokenInput = document.getElementById('alert-api-token');
    if (tokenInput && !tokenInput.value) tokenInput.value = getStoredApiToken();
    if (!alertToken()) {
        document.getElementById('alert-dest-list').textContent = 'Enter the write API token to load destinations.';
        document.getElementById('alert-rule-list').textContent = 'Enter the write API token to load rules.';
        return;
    }
    const [catalog, dests, rules, incidents] = await Promise.all([
        alertFetch('/alerts/catalog'),
        alertFetch('/alerts/destinations'),
        alertFetch('/alerts/rules'),
        alertFetch('/alerts/incidents'),
    ]);
    if (catalog) alertCatalog = catalog;
    if (dests) {
        alertDestinations = dests.destinations || [];
        renderAlertDestinations(alertDestinations);
        fillAlertDestSelect(alertDestinations);
    }
    if (rules) renderAlertRules(rules.rules || []);
    if (incidents) renderAlertIncidents(incidents.incidents || []);
    fillAlertScopeSelects();
}

function renderAlertDestinations(items) {
    const root = document.getElementById('alert-dest-list');
    if (!items.length) {
        root.textContent = 'No destinations yet.';
        return;
    }
    root.innerHTML = items.map((d) => {
        const badge = d.enabled ? '<span class="alert-badge on">on</span>' : '<span class="alert-badge off">off</span>';
        return `<article class="alert-item" data-id="${alertEscape(d.destination_id)}">
            <div>
                <div class="alert-item-title">${badge}${alertEscape(d.name)}</div>
                <div class="alert-item-meta">${alertEscape(d.channel)}</div>
            </div>
            <div class="alert-item-actions">
                <button type="button" data-act="test">Test</button>
                <button type="button" data-act="edit">Edit</button>
                <button type="button" data-act="delete">Delete</button>
            </div>
        </article>`;
    }).join('');
    root.querySelectorAll('.alert-item').forEach((el) => {
        el.querySelector('[data-act="test"]').addEventListener('click', () => testAlertDestination(el.dataset.id));
        el.querySelector('[data-act="edit"]').addEventListener('click', () => editAlertDestination(el.dataset.id));
        el.querySelector('[data-act="delete"]').addEventListener('click', () => deleteAlertDestination(el.dataset.id));
    });
}

function renderAlertRules(items) {
    const root = document.getElementById('alert-rule-list');
    if (!items.length) {
        root.textContent = 'No rules yet.';
        return;
    }
    const destName = Object.fromEntries(alertDestinations.map((d) => [d.destination_id, d.name]));
    root.innerHTML = items.map((r) => {
        const badge = r.enabled ? '<span class="alert-badge on">on</span>' : '<span class="alert-badge off">off</span>';
        const kind = ALERT_KIND_LABELS[r.kind] || r.kind;
        return `<article class="alert-item" data-id="${alertEscape(r.rule_id)}">
            <div>
                <div class="alert-item-title">${badge}${alertEscape(r.name)}</div>
                <div class="alert-item-meta">${alertEscape(kind)} → ${alertEscape(destName[r.destination_id] || r.destination_id)}</div>
            </div>
            <div class="alert-item-actions">
                <button type="button" data-act="edit">Edit</button>
                <button type="button" data-act="delete">Delete</button>
            </div>
        </article>`;
    }).join('');
    root.querySelectorAll('.alert-item').forEach((el) => {
        el.querySelector('[data-act="edit"]').addEventListener('click', () => editAlertRule(el.dataset.id));
        el.querySelector('[data-act="delete"]').addEventListener('click', () => deleteAlertRule(el.dataset.id));
    });
}

function renderAlertIncidents(items) {
    const root = document.getElementById('alert-incident-list');
    if (!items.length) {
        root.textContent = 'No incidents recorded.';
        return;
    }
    root.innerHTML = items.slice(0, 20).map((i) => {
        const badge = i.status === 'open'
            ? '<span class="alert-badge on">open</span>'
            : '<span class="alert-badge off">resolved</span>';
        return `<article class="alert-item">
            <div>
                <div class="alert-item-title">${badge}${alertEscape(i.subject || '')}</div>
                <div class="alert-item-meta">${alertEscape(i.fired_at || '')}</div>
            </div>
        </article>`;
    }).join('');
}

function fillAlertDestSelect(items) {
    const select = document.getElementById('alert-rule-dest');
    const current = select.value;
    select.innerHTML = items.map((d) =>
        `<option value="${alertEscape(d.destination_id)}">${alertEscape(d.name)} (${alertEscape(d.channel)})</option>`
    ).join('');
    if (current) select.value = current;
}

function fillAlertScopeSelects() {
    fillMulti('alert-rule-platforms', alertCatalog.platforms || []);
    fillMulti('alert-rule-fleets', alertCatalog.fleets || []);
    fillMulti('alert-rule-labels', alertCatalog.labels || []);
    const label = document.getElementById('alert-rule-label');
    label.innerHTML = (alertCatalog.labels || []).map((n) =>
        `<option value="${alertEscape(n)}">${alertEscape(n)}</option>`
    ).join('');
}

function fillMulti(id, values) {
    const el = document.getElementById(id);
    const selected = new Set(Array.from(el.selectedOptions).map((o) => o.value));
    el.innerHTML = values.map((v) =>
        `<option value="${alertEscape(v)}"${selected.has(v) ? ' selected' : ''}>${alertEscape(v)}</option>`
    ).join('');
}

function selectedValues(id) {
    return Array.from(document.getElementById(id).selectedOptions).map((o) => o.value);
}

function setSelectedValues(id, values) {
    const wanted = new Set(values || []);
    const el = document.getElementById(id);
    Array.from(el.options).forEach((opt) => {
        opt.selected = wanted.has(opt.value);
    });
}

function showChannelFields() {
    const channel = document.getElementById('alert-dest-channel').value;
    document.querySelectorAll('.alert-channel-fields').forEach((el) => {
        const channels = (el.dataset.channels || '').split(/\s+/);
        el.classList.toggle('hidden', !channels.includes(channel));
    });
}

function showKindFields() {
    const kind = document.getElementById('alert-rule-kind').value;
    document.querySelectorAll('.alert-kind-fields').forEach((el) => {
        const kinds = (el.dataset.kinds || '').split(/\s+/);
        el.classList.toggle('hidden', !kinds.includes(kind));
    });
}

function alertEscape(value) {
    return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[ch]));
}

function resetDestForm() {
    document.getElementById('alert-dest-id').value = '';
    document.getElementById('alert-dest-name').value = '';
    document.getElementById('alert-dest-channel').value = 'slack';
    document.getElementById('alert-dest-webhook').value = '';
    document.getElementById('alert-dest-bot-token').value = '';
    document.getElementById('alert-dest-chat-id').value = '';
    document.getElementById('alert-dest-url').value = '';
    document.getElementById('alert-dest-bearer').value = '';
    document.getElementById('alert-dest-header-name').value = '';
    document.getElementById('alert-dest-header-value').value = '';
    document.getElementById('alert-dest-enabled').checked = true;
    document.getElementById('alert-dest-channel').disabled = false;
    showChannelFields();
}

function resetRuleForm() {
    document.getElementById('alert-rule-id').value = '';
    document.getElementById('alert-rule-name').value = '';
    document.getElementById('alert-rule-kind').value = 'policy_duration';
    document.getElementById('alert-rule-kind').disabled = false;
    document.getElementById('alert-rule-duration-hours').value = '24';
    document.getElementById('alert-rule-threshold').value = '32';
    document.getElementById('alert-rule-duration-days').value = '3';
    document.getElementById('alert-rule-safeguards').value = '';
    document.getElementById('alert-rule-enabled').checked = true;
    alertSelectedPolicies = [];
    renderPolicyChips();
    setSelectedValues('alert-rule-platforms', []);
    setSelectedValues('alert-rule-fleets', []);
    setSelectedValues('alert-rule-labels', []);
    setSelectedValues('alert-rule-levels', []);
    setSelectedValues('alert-rule-severities', []);
    showKindFields();
}

function renderPolicyChips() {
    const root = document.getElementById('alert-policy-chips');
    const byId = Object.fromEntries((alertCatalog.policies || []).map((p) => [String(p.policy_id), p]));
    root.innerHTML = alertSelectedPolicies.map((id) => {
        const p = byId[String(id)];
        const label = p ? p.policy_name : `#${id}`;
        return `<span class="alert-chip">${alertEscape(label)} <button type="button" data-id="${id}" aria-label="Remove">&times;</button></span>`;
    }).join('');
    root.querySelectorAll('button').forEach((btn) => {
        btn.addEventListener('click', () => {
            alertSelectedPolicies = alertSelectedPolicies.filter((id) => String(id) !== btn.dataset.id);
            renderPolicyChips();
        });
    });
}

function setupPolicySearch() {
    const input = document.getElementById('alert-policy-search');
    const suggest = document.getElementById('alert-policy-suggest');
    input.addEventListener('input', () => {
        const q = input.value.trim().toLowerCase();
        if (!q) {
            suggest.classList.remove('open');
            suggest.innerHTML = '';
            return;
        }
        const selected = new Set(alertSelectedPolicies.map(String));
        const hits = (alertCatalog.policies || [])
            .filter((p) => !selected.has(String(p.policy_id)))
            .filter((p) => p.policy_name.toLowerCase().includes(q) || String(p.policy_id) === q)
            .slice(0, 20);
        suggest.innerHTML = hits.map((p) =>
            `<button type="button" data-id="${p.policy_id}">${alertEscape(p.policy_name)}</button>`
        ).join('') || '<button type="button" disabled>No matches</button>';
        suggest.classList.add('open');
        suggest.querySelectorAll('button[data-id]').forEach((btn) => {
            btn.addEventListener('click', () => {
                alertSelectedPolicies = [...alertSelectedPolicies, Number(btn.dataset.id)];
                input.value = '';
                suggest.classList.remove('open');
                renderPolicyChips();
            });
        });
    });
}

function destPayload() {
    const channel = document.getElementById('alert-dest-channel').value;
    const config = {};
    if (channel === 'slack' || channel === 'discord') {
        config.webhook_url = document.getElementById('alert-dest-webhook').value.trim();
    } else if (channel === 'telegram') {
        config.bot_token = document.getElementById('alert-dest-bot-token').value.trim();
        config.chat_id = document.getElementById('alert-dest-chat-id').value.trim();
    } else {
        config.url = document.getElementById('alert-dest-url').value.trim();
        config.bearer_token = document.getElementById('alert-dest-bearer').value.trim();
        config.header_name = document.getElementById('alert-dest-header-name').value.trim();
        config.header_value = document.getElementById('alert-dest-header-value').value.trim();
    }
    return {
        name: document.getElementById('alert-dest-name').value.trim(),
        channel,
        enabled: document.getElementById('alert-dest-enabled').checked,
        config,
    };
}

function rulePayload() {
    const kind = document.getElementById('alert-rule-kind').value;
    const config = {};
    if (kind === 'policy_duration' || kind === 'scoped_duration') {
        config.policy_ids = alertSelectedPolicies.slice();
        config.duration_hours = Number(document.getElementById('alert-rule-duration-hours').value);
    }
    if (kind === 'scoped_duration' || kind === 'compliance_threshold') {
        config.platforms = selectedValues('alert-rule-platforms');
        config.fleets = selectedValues('alert-rule-fleets');
        config.labels = selectedValues('alert-rule-labels');
    }
    if (kind === 'scoped_duration') {
        config.levels = selectedValues('alert-rule-levels');
        config.severities = selectedValues('alert-rule-severities');
    }
    if (kind === 'compliance_threshold') {
        config.threshold_percent = Number(document.getElementById('alert-rule-threshold').value);
        config.duration_days = Number(document.getElementById('alert-rule-duration-days').value);
    }
    if (kind === 'label_safeguard') {
        config.label = document.getElementById('alert-rule-label').value;
        config.policy_ids = alertSelectedPolicies.slice();
        config.safeguard_ids = document.getElementById('alert-rule-safeguards').value
            .split(',').map((s) => s.trim()).filter(Boolean);
    }
    return {
        name: document.getElementById('alert-rule-name').value.trim(),
        kind,
        enabled: document.getElementById('alert-rule-enabled').checked,
        destination_id: document.getElementById('alert-rule-dest').value,
        config,
    };
}

async function saveAlertDestination(event) {
    event.preventDefault();
    const id = document.getElementById('alert-dest-id').value;
    const path = id ? `/alerts/destinations/${id}` : '/alerts/destinations';
    const method = id ? 'PUT' : 'POST';
    const data = await alertFetch(path, {
        method,
        headers: alertHeaders(true),
        body: JSON.stringify(destPayload()),
    });
    if (!data) return;
    showSuccess(id ? 'Destination updated' : 'Destination created');
    document.getElementById('alert-dest-form').classList.add('hidden');
    await loadAlertManager();
}

async function saveAlertRule(event) {
    event.preventDefault();
    const id = document.getElementById('alert-rule-id').value;
    const path = id ? `/alerts/rules/${id}` : '/alerts/rules';
    const method = id ? 'PUT' : 'POST';
    const data = await alertFetch(path, {
        method,
        headers: alertHeaders(true),
        body: JSON.stringify(rulePayload()),
    });
    if (!data) return;
    showSuccess(id ? 'Rule updated' : 'Rule created');
    document.getElementById('alert-rule-form').classList.add('hidden');
    await loadAlertManager();
}

async function previewAlertRule() {
    const data = await alertFetch('/alerts/rules/preview', {
        method: 'POST',
        headers: alertHeaders(true),
        body: JSON.stringify(rulePayload()),
    });
    if (!data) return;
    const preview = document.getElementById('alert-preview');
    if (!data.would_fire) {
        preview.textContent = 'Would not fire against current stored results.';
        return;
    }
    const body = (data.body || []).join('\n');
    preview.textContent = `${data.subject}\n\n${body}`;
}

async function testAlertDestination(id) {
    const data = await alertFetch(`/alerts/destinations/${id}/test`, {
        method: 'POST',
        headers: alertHeaders(true),
        body: JSON.stringify({ dry_run: true }),
    });
    if (!data) return;
    const preview = document.getElementById('alert-preview');
    const req = data.request || {};
    preview.textContent = `${data.subject || ''}\n\n${data.text || ''}\n\n${req.method || 'POST'} ${req.url || ''}\n${JSON.stringify(req.json || {}, null, 2)}`;
    showSuccess('Dry-run payload rendered (not sent)');
}

function editAlertDestination(id) {
    const d = alertDestinations.find((x) => x.destination_id === id);
    if (!d) return;
    resetDestForm();
    document.getElementById('alert-dest-id').value = d.destination_id;
    document.getElementById('alert-dest-name').value = d.name;
    document.getElementById('alert-dest-channel').value = d.channel;
    document.getElementById('alert-dest-channel').disabled = true;
    document.getElementById('alert-dest-enabled').checked = d.enabled;
    const cfg = d.config || {};
    document.getElementById('alert-dest-webhook').value = cfg.webhook_url || '';
    document.getElementById('alert-dest-bot-token').value = '';
    document.getElementById('alert-dest-chat-id').value = cfg.chat_id || '';
    document.getElementById('alert-dest-url').value = cfg.url || '';
    document.getElementById('alert-dest-header-name').value = cfg.header_name || '';
    showChannelFields();
    document.getElementById('alert-dest-form').classList.remove('hidden');
}

async function deleteAlertDestination(id) {
    if (!confirm('Delete this destination?')) return;
    const data = await alertFetch(`/alerts/destinations/${id}`, {
        method: 'DELETE',
        headers: alertHeaders(),
    });
    if (!data) return;
    showSuccess('Destination deleted');
    await loadAlertManager();
}

async function editAlertRule(id) {
    const data = await alertFetch(`/alerts/rules/${id}`);
    if (!data) return;
    resetRuleForm();
    document.getElementById('alert-rule-id').value = data.rule_id;
    document.getElementById('alert-rule-name').value = data.name;
    document.getElementById('alert-rule-kind').value = data.kind;
    document.getElementById('alert-rule-kind').disabled = true;
    document.getElementById('alert-rule-dest').value = data.destination_id;
    document.getElementById('alert-rule-enabled').checked = data.enabled;
    const cfg = data.config || {};
    if (cfg.duration_hours) document.getElementById('alert-rule-duration-hours').value = String(cfg.duration_hours);
    if (cfg.threshold_percent != null) document.getElementById('alert-rule-threshold').value = cfg.threshold_percent;
    if (cfg.duration_days) document.getElementById('alert-rule-duration-days').value = cfg.duration_days;
    if (cfg.label) document.getElementById('alert-rule-label').value = cfg.label;
    if (cfg.safeguard_ids) document.getElementById('alert-rule-safeguards').value = cfg.safeguard_ids.join(', ');
    alertSelectedPolicies = (cfg.policy_ids || []).slice();
    renderPolicyChips();
    setSelectedValues('alert-rule-platforms', cfg.platforms);
    setSelectedValues('alert-rule-fleets', cfg.fleets);
    setSelectedValues('alert-rule-labels', cfg.labels);
    setSelectedValues('alert-rule-levels', cfg.levels);
    setSelectedValues('alert-rule-severities', cfg.severities);
    showKindFields();
    document.getElementById('alert-rule-form').classList.remove('hidden');
}

async function deleteAlertRule(id) {
    if (!confirm('Delete this rule?')) return;
    const data = await alertFetch(`/alerts/rules/${id}`, {
        method: 'DELETE',
        headers: alertHeaders(),
    });
    if (!data) return;
    showSuccess('Rule deleted');
    await loadAlertManager();
}

function setupAlertManager() {
    const destForm = document.getElementById('alert-dest-form');
    if (!destForm) return;
    document.getElementById('alert-dest-new').addEventListener('click', () => {
        resetDestForm();
        destForm.classList.remove('hidden');
    });
    document.getElementById('alert-dest-cancel').addEventListener('click', () => destForm.classList.add('hidden'));
    destForm.addEventListener('submit', saveAlertDestination);
    document.getElementById('alert-dest-channel').addEventListener('change', showChannelFields);

    const ruleForm = document.getElementById('alert-rule-form');
    document.getElementById('alert-rule-new').addEventListener('click', () => {
        resetRuleForm();
        ruleForm.classList.remove('hidden');
    });
    document.getElementById('alert-rule-cancel').addEventListener('click', () => ruleForm.classList.add('hidden'));
    ruleForm.addEventListener('submit', saveAlertRule);
    document.getElementById('alert-rule-kind').addEventListener('change', showKindFields);
    document.getElementById('alert-rule-preview').addEventListener('click', previewAlertRule);
    document.getElementById('alert-api-token').addEventListener('change', () => {
        setStoredApiToken(alertToken());
        loadAlertManager();
    });
    setupPolicySearch();
    showChannelFields();
    showKindFields();
}

window.loadAlertManager = loadAlertManager;
document.addEventListener('DOMContentLoaded', setupAlertManager);
