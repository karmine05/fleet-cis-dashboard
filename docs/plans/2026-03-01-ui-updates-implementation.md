# UI Updates Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add loading indicator, rename Team to Fleet, and update risk level logic with edge case handling.

**Architecture:** Frontend changes to HTML/CSS/JS plus one backend field addition.

**Tech Stack:** Vanilla JavaScript, Flask, PostgreSQL

---

## Task 1: Rename "Team" to "Fleet" in Filter

**Files:**
- Modify: `frontend/index.html:83-85`
- Modify: `frontend/index.html:421-427`

**Step 1: Update filter label**

Edit `frontend/index.html` lines 83-85:
```html
<label>Fleet</label>
<select id="team-filter">
    <option value="">All Fleets</option>
```

**Step 2: Update leaderboard title**

Edit `frontend/index.html` lines 421-427:
```html
<!-- Fleet Leaderboard -->
<div class="card strategy-leaderboard-card">
    <div class="card-header">
        <h3><i class="fas fa-ranking-star"></i> Fleet Leaderboard</h3>
```

**Step 3: Commit**

```bash
git add frontend/index.html
git commit -m "feat: rename Team filter to Fleet"
```

---

## Task 2: Add total_policy_results to Backend

**Files:**
- Modify: `backend/app.py:531-541`

**Step 1: Add field to response**

Edit `backend/app.py` after line 540 (inside the return jsonify):
```python
return jsonify({
    "total_devices": total_dev,
    "compliant_devices": compliant_dev,
    "non_compliant_devices": non_compliant_dev,
    "compliance_percentage": pass_rate,
    "total_policies": total_pol,
    "policies_passed": passed,
    "policies_failed": failed,
    "policy_pass_rate": pass_rate,
    "total_policy_results": passed + failed  # NEW FIELD
})
```

**Step 2: Commit**

```bash
git add backend/app.py
git commit -m "feat: add total_policy_results to compliance summary"
```

---

## Task 3: Update Risk Level Logic in Frontend

**Files:**
- Modify: `frontend/app.js:286-291`

**Step 1: Update risk level logic**

Replace lines 286-291 in `frontend/app.js`:
```javascript
// Risk level
let riskLevel = 'LOW';
// Edge case: no devices
if (total === 0) {
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
```

**Step 2: Commit**

```bash
git add frontend/app.js
git commit -m "feat: add edge case handling for risk level"
```

---

## Task 4: Add Loading Overlay

**Files:**
- Modify: `frontend/index.html`
- Modify: `frontend/styles.css`
- Modify: `frontend/app.js`

**Step 1: Add loading overlay HTML**

Add before `<div id="app">` in `frontend/index.html`:
```html
<div id="loading-overlay" class="loading-overlay hidden">
    <div class="loading-spinner"></div>
    <div class="loading-text">Loading...</div>
</div>
```

**Step 2: Add loading overlay CSS**

Add to end of `frontend/styles.css`:
```css
/* Loading Overlay */
.loading-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    z-index: 9999;
    backdrop-filter: blur(4px);
}

.loading-overlay.hidden {
    display: none;
}

.loading-spinner {
    width: 50px;
    height: 50px;
    border: 4px solid rgba(255, 255, 255, 0.2);
    border-top-color: var(--accent-color, #4f46e5);
    border-radius: 50%;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    to { transform: rotate(360deg); }
}

.loading-text {
    color: #fff;
    margin-top: 16px;
    font-size: 16px;
    font-weight: 500;
}
```

**Step 3: Add loading state functions**

Add at top of `frontend/app.js` (after currentFilters):
```javascript
function showLoading() {
    document.getElementById('loading-overlay')?.classList.remove('hidden');
}

function hideLoading() {
    document.getElementById('loading-overlay')?.classList.add('hidden');
}
```

**Step 4: Add loading calls to init()**

Find `async function init()` and add `showLoading()` at the start, `hideLoading()` after the Promise.all:
```javascript
async function init() {
    showLoading();  // ADD THIS
    await populateFilters();
    await updateDashboard();
    setupEventListeners();
    setupTooltip();
    setupInfoTooltips();
    updateSyncStatus();
    setInterval(updateSyncStatus, 30000);
    hideLoading();  // ADD THIS
}
```

**Step 5: Add loading to updateDashboard()**

Find `async function updateDashboard()` and add loading calls around the fetch:
```javascript
async function updateDashboard() {
    showLoading();  // ADD THIS
    // ... existing code ...
    try {
        const [summaryResp, heatmapResp, auditResp, strategyResp] = await Promise.all([
            // ... existing fetches ...
        ]);
        // ... existing code ...
    } catch (error) {
        console.error('Error updating dashboard:', error);
    }
    hideLoading();  // ADD THIS
}
```

**Step 6: Commit**

```bash
git add frontend/index.html frontend/styles.css frontend/app.js
git commit -m "feat: add loading overlay for data fetching"
```

---

## Plan complete

Two execution options:

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

Which approach?
