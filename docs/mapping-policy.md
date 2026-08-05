# Mapping Policy — CIS Safeguards → D3FEND → ATT&CK

## Identity

1. **Policy identity** comes from [fleet_policies](https://github.com/karmine05/fleet_policies) tags joined by exact policy name.
2. **Primary CIS key** is `cis_safeguard_ids` (e.g. `CIS8.4`), not OS benchmark section numbers.
3. **D3FEND** and **ATT&CK** are derived in the dashboard from curated maps + tight policy-name rules.

## ATT&CK rules

| Status | Meaning | UI |
|--------|---------|-----|
| `mapped` | One or more ATT&CK techniques with rationale | Shown under primary T-ID (multi in tooltip) |
| `not_applicable` | Defensive/process control with no honest T-link | “No ATT&CK link” |
| `needs_review` | Temporary backlog | “Needs review” |
| `unmapped` | Unknown — treat as a bug | “Unmapped” |

### Multi-technique

- Prefer `attack_ids: ["T…", …]` (primary first).
- Keep `attack_id` as the primary for backward compatibility.
- Architecture matrix and filters consider all IDs; heat-map MITRE group uses **primary**.

### Poison guard

No single technique may cover **>25%** of catalog policies without a `mapping_coarse` flag and written rationale.  
Especially sensitive: CIS4.1 (large policy volume) — always multi-map.

### Forbidden

- Bulk-importing legacy `cis_to_d3fend_*.csv` attack columns without review.
- Broad keyword rules that rewrite whole safeguard families (e.g. bare `network` → Isolate).
- Inventing a unique T-code per OS recommendation for vanity 0% Unmapped.

## Sources (priority)

1. CIS Controls v8.1 safeguard intent + curated multi-map (`safeguard_d3fend.json`)
2. MITRE D3FEND related-attack edges (when D3FEND technique is solid)
3. Policy-**name** rules in `policy_catalog.py` (high precision only — match the policy title, never `cis_category` / `cis_subcategory` UI labels such as “Privacy & Security” or “Safari”)
4. CIS Navigator / CTID methodology for revisions

### Rule anti-patterns (do not reintroduce)

- Matching keyword rules against category/subcategory fields (poison whole OS sections)
- Bare `encrypt` regex (matches **unencrypted**)
- Broad keywords like bare `network` or bare `privacy`

## CIS4.1 is not a dump bucket

`CIS4.1` = *Establish and Maintain a Secure Configuration Process* (Govern).

Individual OS / GPO / privacy / location / Siri / driver checks **must not** use CIS4.1.
Use:

| Kind of check | Prefer |
|---------------|--------|
| Disable unnecessary features/services (privacy, Bonjour, sharing) | **CIS4.8** |
| Network MSS / source routing / ICS | **CIS4.5** / **CIS4.4** |
| Anti-exploit (SEHOP, SafeDll, ASR) | **CIS10.5** |
| Auth / WDigest / passwords | **CIS5.2** / **CIS6.x** |
| Patches / auto-update | **CIS7.3** |

Normalize with:

```bash
python3 scripts/normalize_safeguard_ids.py /path/to/fleet_policies
python3 scripts/apply_attack_maps.py
python3 scripts/audit_mitre_mapping.py
```

APIs resolve safeguard IDs via `resolve_policy_safeguards()` (catalog/overrides over stale DB).

## Files

| File | Role |
|------|------|
| `backend/data/safeguard_d3fend.json` | Safeguard → D3FEND + `attack_ids` + status |
| `backend/data/policy_catalog.json` | fleet_policies names + tags |
| `backend/data/safeguard_overrides.json` | Per-policy hard overrides |
| `backend/mitre_data.json` | Technique id → name + tactic (matrix) |
| `backend/policy_catalog.py` | Loaders, rules, finalize mapping |
| `scripts/normalize_safeguard_ids.py` | Retag fleet_policies YAML + rebuild catalog |
| `scripts/apply_attack_maps.py` | Curated multi-technique ATT&CK fill |
| `scripts/audit_mitre_mapping.py` | Coverage / poison gates |

## Verify

```bash
python3 scripts/audit_mitre_mapping.py
```

Target gates:

- ≥85% policies `mapped`
- ≤15% `unmapped`
- No technique >25% of policies (primary share)
- Every technique used is present in `mitre_data.json`
