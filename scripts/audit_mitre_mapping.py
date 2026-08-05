#!/usr/bin/env python3
"""
Audit CIS safeguard → ATT&CK mapping quality.

Exit 0 when thresholds pass; exit 1 on regression.

Usage:
  python3 scripts/audit_mitre_mapping.py
  python3 scripts/audit_mitre_mapping.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import policy_catalog as pc  # noqa: E402

# Quality gates (from .planning/mitre-mapping-plan.md)
MAX_UNMAPPED_PCT = 15.0
MAX_SINGLE_TECHNIQUE_PCT = 25.0
# Multi-map bulk safeguards (e.g. CIS4.1 secure-config) may exceed 25% on primary
# when intentionally coarse — still hard-capped.
MAX_COARSE_PRIMARY_PCT = 40.0
MIN_MAPPED_PCT = 85.0


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit MITRE mapping coverage")
    parser.add_argument("--json", action="store_true", help="Print full JSON report")
    args = parser.parse_args()

    # Bust caches so fresh JSON is always used
    pc.load_safeguard_d3fend.cache_clear()
    pc.load_policy_catalog.cache_clear()
    pc.load_cis_controls.cache_clear()

    cov = pc.mapping_coverage_stats()
    smap = pc.load_safeguard_d3fend()

    sg_status = Counter()
    sg_empty = []
    for sid, m in smap.items():
        st = (m.get("mapping_status") or "").lower()
        ids = m.get("attack_ids") or ([m["attack_id"]] if m.get("attack_id") else [])
        # not_applicable may legitimately have empty attack_ids
        if st == "not_applicable":
            sg_status["not_applicable"] += 1
        elif not ids:
            sg_empty.append(sid)
            sg_status["empty_attack"] += 1
        else:
            sg_status[st or "mapped"] += 1

    # Poison check: max share of any single PRIMARY technique (not multi-map counts)
    primary_c: Counter = Counter()
    all_used = set()
    cat = pc.load_policy_catalog().get("policies") or {}
    for name, p in cat.items():
        sids = p.get("cis_safeguard_ids") or []
        sid = sids[0] if sids else ""
        m = pc.mapping_for_policy(
            name, p.get("cis_category") or "", p.get("cis_subcategory") or "", sid
        )
        primary = (m.get("attack_id") or "").strip()
        if primary:
            primary_c[primary] += 1
        for a in m.get("attack_ids") or []:
            all_used.add(a)

    total = max(cov["total_policies"], 1)
    top_id, top_n = (primary_c.most_common(1)[0] if primary_c else ("", 0))
    top_pct = 100.0 * top_n / total if top_n else 0.0

    # Coarse: majority of policies with this primary have multi-technique maps
    multi_primary = 0
    for name, p in cat.items():
        sids = p.get("cis_safeguard_ids") or []
        sid = sids[0] if sids else ""
        m = pc.mapping_for_policy(
            name, p.get("cis_category") or "", p.get("cis_subcategory") or "", sid
        )
        if (m.get("attack_id") or "").strip() == top_id and len(m.get("attack_ids") or []) > 1:
            multi_primary += 1
    top_is_coarse = top_n > 0 and (multi_primary / top_n) >= 0.5
    poison_limit = MAX_COARSE_PRIMARY_PCT if top_is_coarse else MAX_SINGLE_TECHNIQUE_PCT

    mitre_path = ROOT / "backend" / "mitre_data.json"
    mitre = json.loads(mitre_path.read_text(encoding="utf-8")) if mitre_path.exists() else {}
    missing_meta = sorted(a for a in all_used if a not in mitre)

    failures = []
    # Honest coverage = mapped + not_applicable (process controls with no T-link)
    honest_pct = round(
        cov.get("pct_mapped", 0) + cov.get("pct_not_applicable", 0), 1
    )
    if honest_pct < MIN_MAPPED_PCT:
        failures.append(
            f"honest coverage (mapped+N/A) {honest_pct}% < {MIN_MAPPED_PCT}%"
        )
    if cov["pct_unmapped"] > MAX_UNMAPPED_PCT:
        failures.append(f"pct_unmapped {cov['pct_unmapped']}% > {MAX_UNMAPPED_PCT}%")
    if top_pct > poison_limit:
        kind = "coarse" if top_is_coarse else "primary"
        failures.append(
            f"technique {top_id} covers {top_pct:.1f}% of policies "
            f"(>{poison_limit}% {kind} poison threshold)"
        )
    if sg_empty:
        failures.append(f"{len(sg_empty)} safeguards still empty attack_ids: {sg_empty[:8]}")
    if missing_meta:
        failures.append(f"techniques missing from mitre_data.json: {missing_meta}")

    report = {
        "coverage": cov,
        "safeguard_status": dict(sg_status),
        "safeguards_empty": sg_empty,
        "top_technique": {"id": top_id, "count": top_n, "pct": round(top_pct, 1)},
        "missing_mitre_meta": missing_meta,
        "unique_techniques_used": len(all_used),
        "pass": len(failures) == 0,
        "failures": failures,
        "thresholds": {
            "min_mapped_pct": MIN_MAPPED_PCT,
            "max_unmapped_pct": MAX_UNMAPPED_PCT,
            "max_single_technique_pct": MAX_SINGLE_TECHNIQUE_PCT,
        },
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("=== MITRE mapping audit ===")
        print(f"Policies: {cov['total_policies']}")
        print(f"  mapped:        {cov['pct_mapped']}%")
        print(f"  not_applicable:{cov['pct_not_applicable']}%")
        print(f"  needs_review:  {cov['pct_needs_review']}%")
        print(f"  unmapped:      {cov['pct_unmapped']}%")
        print(f"Unique techniques: {len(all_used)}")
        print(f"Top technique: {top_id} ({top_pct:.1f}%)")
        print(f"Safeguards empty attack: {len(sg_empty)}")
        if failures:
            print("\nFAIL:")
            for f in failures:
                print(f"  - {f}")
        else:
            print("\nPASS: all gates clear")

    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
