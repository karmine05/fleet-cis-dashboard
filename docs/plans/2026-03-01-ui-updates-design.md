# Design: UI Updates for Fleet CIS Dashboard

**Date:** 2026-03-01  
**Status:** Approved

## Overview

Three UI updates for the Fleet CIS Compliance Dashboard:
1. Rename "Team" filter/label to "Fleet"
2. Update Risk Level logic to handle edge cases
3. Add loading indicator for slow data loads

---

## Change 1: Rename "Team" to "Fleet"

### Files Modified
- `frontend/index.html`
- `frontend/app.js`

### Implementation
- Update filter label from "Team" to "Fleet" in HTML
- Update any static text references in JavaScript

---

## Change 2: Risk Level Logic Update

### Logic
```
IF total_devices == 0 → "UNAVAILABLE"
ELSE IF (policy_results == 0 OR no_d3fend_mapping) → "HIGH"
ELSE IF compliance_rate < 50 → "CRITICAL"
ELSE IF compliance_rate < 70 → "HIGH"
ELSE IF compliance_rate < 85 → "MEDIUM"
ELSE → "LOW"
```

### Backend Changes
Add new endpoint or modify existing `/api/compliance/summary` to return:
- `total_devices` (already exists)
- `total_policy_results` (new - count of policy results for filtered hosts)

### Frontend Changes
Modify `updateSummary()` in `frontend/app.js` to implement the above logic.

---

## Change 3: Loading Indicator

### Implementation
Add full-screen loading overlay:

**HTML** (`frontend/index.html`):
```html
<div id="loading-overlay" class="loading-overlay">
    <div class="loading-spinner"></div>
    <div class="loading-text">Loading...</div>
</div>
```

**CSS** (`frontend/styles.css`):
- `.loading-overlay`: fixed position, full viewport, semi-transparent dark background
- `.loading-spinner`: CSS spinner animation
- `.loading-text`: centered text below spinner
- Hidden by default, shown when loading

**JavaScript** (`frontend/app.js`):
- Show overlay at start of `init()` and `updateDashboard()`
- Hide overlay after all Promise.all() calls complete
- Also show during filter changes and view switches

---

## Files to Modify

| File | Changes |
|------|---------|
| `frontend/index.html` | Add loading overlay HTML, update "Team" label |
| `frontend/styles.css` | Add loading overlay styles |
| `frontend/app.js` | Update risk logic, add loading state management |
| `backend/app.py` | Add `total_policy_results` to compliance summary endpoint |
