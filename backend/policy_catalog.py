"""
Policy catalog from fleet_policies (tags + cis_safeguard_ids).

Source of truth: https://github.com/karmine05/fleet_policies
Fleet API does not return policy tags, so we join by exact policy name.
"""

from __future__ import annotations

import json
import logging
import os
import re
from functools import lru_cache
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


@lru_cache(maxsize=1)
def load_policy_catalog() -> Dict[str, Any]:
    path = os.path.join(DATA_DIR, "policy_catalog.json")
    if not os.path.exists(path):
        logger.warning("policy_catalog.json missing at %s", path)
        return {"policies": {}}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    policies = data.get("policies") or {}
    logger.info("Loaded policy catalog: %d policies", len(policies))
    return data


@lru_cache(maxsize=1)
def load_safeguard_d3fend() -> Dict[str, Any]:
    path = os.path.join(DATA_DIR, "safeguard_d3fend.json")
    if not os.path.exists(path):
        logger.warning("safeguard_d3fend.json missing")
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def load_cis_controls() -> Dict[str, Any]:
    path = os.path.join(DATA_DIR, "cis_controls_v8.json")
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def load_safeguard_overrides() -> Dict[str, Any]:
    """Per-policy hard overrides (mirrors normalized fleet_policies tags)."""
    path = os.path.join(DATA_DIR, "safeguard_overrides.json")
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_catalog_entry(policy_name: str) -> Optional[Dict[str, Any]]:
    """Exact name match against fleet_policies catalog."""
    if not policy_name:
        return None
    policies = load_policy_catalog().get("policies") or {}
    if policy_name in policies:
        return policies[policy_name]
    # light normalize: collapse whitespace
    norm = re.sub(r"\s+", " ", policy_name.strip())
    if norm in policies:
        return policies[norm]
    return None


def _normalize_sid_list(raw) -> List[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        items = raw
    else:
        items = re.split(r"[|;,\s]+", str(raw))
    out = []
    for s in items:
        s = str(s).strip()
        if not s or s in ("CISNone", "None", "none"):
            continue
        if not s.startswith("CIS"):
            s = "CIS" + s
        out.append(s)
    return out


def enrich_policy_from_catalog(policy_name: str, platform: str = "") -> Dict[str, Any]:
    """
    Return DB-ready enrichment fields for a Fleet policy name.

    Precedence:
      1. safeguard_overrides.json (dashboard hard fix)
      2. policy_catalog.json from fleet_policies tags
    """
    entry = get_catalog_entry(policy_name)
    override = load_safeguard_overrides().get(policy_name) or {}

    if not entry and not override:
        return {
            "cis_safeguard_ids": [],
            "benchmark": "",
            "control_slug": "",
            "cis_category": "",
            "cis_subcategory": "",
            "framework": "",
            "level": "",
            "tags": {},
            "mapping_source": "unmatched",
            "catalog_matched": False,
            "benchmark_section": "",
        }

    entry = entry or {}
    tags = dict(entry.get("tags") or {})
    sids = _normalize_sid_list(
        override.get("cis_safeguard_ids")
        if override.get("cis_safeguard_ids") is not None
        else entry.get("cis_safeguard_ids")
    )
    if override.get("cis_safeguard_ids") is not None:
        tags["cis_safeguard_ids"] = ",".join(sids) if sids else "CISNone"
    bench_section = (
        override.get("benchmark_section")
        or entry.get("benchmark_section")
        or tags.get("benchmark_section")
        or ""
    )
    if bench_section:
        tags["benchmark_section"] = bench_section

    return {
        "cis_safeguard_ids": sids,
        "benchmark": entry.get("benchmark") or "",
        "control_slug": entry.get("control") or "",
        "cis_category": override.get("cis_category") or entry.get("cis_category") or "",
        "cis_subcategory": entry.get("cis_subcategory") or "",
        "framework": entry.get("framework") or "",
        "level": entry.get("level") or "",
        "tags": tags,
        "mapping_source": "override+catalog" if override else "fleet_policies_catalog",
        "catalog_matched": True,
        "platform": entry.get("platform") or platform,
        "benchmark_section": bench_section,
    }


def _normalize_attack_ids(raw) -> List[str]:
    """Normalize attack_id / attack_ids to a de-duplicated list of T#### IDs."""
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = re.split(r"[|;,\s]+", raw)
    elif isinstance(raw, (list, tuple)):
        parts = list(raw)
    else:
        parts = [str(raw)]
    out: List[str] = []
    seen = set()
    for p in parts:
        a = str(p or "").strip().upper()
        if not a or a in ("UNMAPPED", "N/A", "NONE", "NA"):
            continue
        if not a.startswith("T"):
            continue
        if a not in seen:
            seen.add(a)
            out.append(a)
    return out


def _finalize_mapping(m: Dict[str, Any], sid: str = "") -> Dict[str, Any]:
    """Ensure attack_ids, primary attack_id, and mapping_status are coherent."""
    out = dict(m)
    if sid:
        out.setdefault("cis_safeguard_id", sid)
    ids = _normalize_attack_ids(out.get("attack_ids") if out.get("attack_ids") is not None else out.get("attack_id"))
    # If only attack_id present
    if not ids:
        ids = _normalize_attack_ids(out.get("attack_id"))
    out["attack_ids"] = ids
    out["attack_id"] = ids[0] if ids else ""

    status = (out.get("mapping_status") or "").strip().lower()
    if status not in ("mapped", "not_applicable", "needs_review", "unmapped"):
        if ids:
            status = "mapped"
        elif (out.get("d3fend_tactic") or "") not in ("", "Unmapped"):
            status = "needs_review"
        else:
            status = "unmapped"
    if status == "mapped" and not ids:
        status = "needs_review"
    out["mapping_status"] = status
    out.setdefault("mapping_confidence", "unmapped" if status == "unmapped" else "medium")
    out.setdefault("mapping_rationale", "")
    out.setdefault("mapping_source", "none")
    out.setdefault("title", sid or out.get("title") or "Unmapped")
    return out


def mapping_for_safeguard(safeguard_id: str) -> Dict[str, Any]:
    """D3FEND + ATT&CK (multi-technique) for a cis_safeguard_id."""
    if not safeguard_id:
        return _unmapped()
    sid = safeguard_id.strip()
    smap = load_safeguard_d3fend()
    if sid in smap:
        return _finalize_mapping(smap[sid], sid)
    alt = sid if sid.startswith("CIS") else f"CIS{sid}"
    if alt in smap:
        return _finalize_mapping(smap[alt], alt)
    return _unmapped(sid)


# Per-policy refinements (first match wins). Match POLICY NAME only —
# never category/subcategory (those labels are OS-benchmark UI sections
# like "Privacy & Security" / "Safari" and poison whole groups).
# Tuple: (d3fend_id, tactic, technique, attack_ids_list, confidence, status)
_POLICY_CAT_RULES = [
    (r"\bsip\b|system integrity protection|secure boot|gatekeeper|xprotect",
     ("D3-SCA", "Harden", "System Integrity", ["T1542", "T1562"], "high", "mapped")),
    # Do NOT use bare "encrypt" — it matches "unencrypted" (false positive).
    (r"\bbitlocker\b|\bfilevault\b|\bdm-crypt\b|\bencrypted\b|\bencryption\b|\bcipher\b",
     ("D3-FE", "Harden", "Data Encryption", ["T1005", "T1530", "T1552"], "high", "mapped")),
    (r"software update|os update|install.*update|security response|patch management|download new updates",
     ("D3-SU", "Harden", "Software Update", ["T1190", "T1210", "T1068"], "high", "mapped")),
    (r"password policy|passwd|lockout|pam\b|mfa|multi-factor|"
     r"password (age|length|complex|history|account)|"
     r"complex password|password must|password minimum|password (is |are )?configured",
     ("D3-UAP", "Harden", "Authentication Hardening", ["T1078", "T1110", "T1556"], "high", "mapped")),
    (r"screen saver|inactiv(e|ity)|session lock|lock screen|above lock|cortana above",
     ("D3-SCA", "Harden", "Session Lock", ["T1078", "T1021"], "high", "mapped")),
    (r"firewall|windows defender firewall|ufw\b|iptables|packet filter|network isolation",
     ("D3-NI", "Isolate", "Network Isolation", ["T1021", "T1046", "T1219"], "high", "mapped")),
    (r"\brdp\b|remote desktop|remote assistance",
     ("D3-NI", "Isolate", "Network Isolation", ["T1021", "T1219"], "medium", "mapped")),
    (r"audit (log|pol|setting)|event log|log management|syslog|journald|auditd|time sync|chrony|\bntp\b",
     ("D3-LME", "Detect", "Log Management", ["T1070", "T1562"], "high", "mapped")),
    (r"malware|windows defender|antivirus|\basr\b|attack surface|smartscreen",
     ("D3-PMAD", "Detect", "Malware Detection", ["T1204", "T1059", "T1105"], "medium", "mapped")),
    # Require browser product in the *name*, not benchmark subcategory "Safari".
    (r"\bsafari\b|\bchrome\b|\bedge\b|internet explorer|\bbrowser\b",
     ("D3-SCA", "Harden", "Browser Hardening", ["T1189", "T1204", "T1566"], "medium", "mapped")),
    (r"\bbackup\b|shadow copy|file history|time machine",
     ("D3-BA", "Restore", "Backup", ["T1490", "T1486"], "high", "mapped")),
    # Name-only privacy signals — not the OS section "Privacy & Security".
    (r"\btelemetry\b|diagnostic data|advertising id|ad tracking|analytics|"
     r"share mac analytics|location services|limit ad tracking|"
     r"improve siri|share with app developers",
     ("D3-SCA", "Harden", "Privacy Configuration", ["T1518", "T1082"], "medium", "mapped")),
]


def mapping_for_policy(
    policy_name: str = "",
    cis_category: str = "",
    cis_subcategory: str = "",
    safeguard_id: str = "",
) -> Dict[str, Any]:
    """
    Policy-level D3FEND + ATT&CK mapping.

    Precedence (docs/mapping-policy.md):
      1. Safeguard-level curated map (safeguard_d3fend.json)
      2. Tight policy-NAME rules only (refine when name is more specific)
      3. Unmapped / needs_review

    cis_category / cis_subcategory are accepted for API compatibility but
    must not drive keyword rules (benchmark UI labels are too broad).
    """
    _ = (cis_category, cis_subcategory)  # reserved; do not match against
    name_blob = (policy_name or "").lower()
    base = mapping_for_safeguard(safeguard_id) if safeguard_id else _unmapped(safeguard_id)
    base_status = (base.get("mapping_status") or "").lower()
    base_has_map = base_status == "mapped" and bool(base.get("attack_ids") or base.get("attack_id"))

    for pat, (d3, tac, tech, atks, conf, status) in _POLICY_CAT_RULES:
        if not re.search(pat, name_blob):
            continue
        ids = _normalize_attack_ids(atks)
        if not ids:
            ids = list(base.get("attack_ids") or [])
        # Refine: name rule may specialize D3FEND technique; keep multi-map
        # attack_ids when rule set is a subset/empty and base is solid.
        if base_has_map and not ids:
            ids = list(base.get("attack_ids") or [])
        return _finalize_mapping({
            **base,
            "d3fend_id": d3,
            "d3fend_tactic": tac,
            "d3fend_technique": tech,
            "attack_ids": ids,
            "attack_id": ids[0] if ids else "",
            "mapping_confidence": conf,
            "mapping_status": status if ids else "needs_review",
            "mapping_source": "policy_name_rules" if not base_has_map else "policy_name_rules+safeguard",
            "mapping_rationale": (
                f"Policy name rule matched on title; techniques "
                f"{', '.join(ids) or 'none'}"
            ),
            "cis_safeguard_id": safeguard_id or base.get("cis_safeguard_id", ""),
        }, safeguard_id or base.get("cis_safeguard_id", ""))

    if safeguard_id:
        return base
    return _unmapped()


def _unmapped(sid: str = "") -> Dict[str, Any]:
    return _finalize_mapping({
        "cis_safeguard_id": sid or "",
        "d3fend_id": "N/A",
        "d3fend_tactic": "Unmapped",
        "d3fend_technique": "Unmapped",
        "attack_id": "",
        "attack_ids": [],
        "mapping_confidence": "unmapped",
        "mapping_status": "unmapped",
        "mapping_source": "none",
        "mapping_rationale": "No safeguard or policy rule matched",
        "title": sid or "Unmapped",
    }, sid)


def primary_safeguard(ids: List[str]) -> str:
    if not ids:
        return ""
    return ids[0]


def resolve_policy_safeguards(
    policy_name: str,
    db_sids: Optional[List[str]] = None,
    platform: str = "",
) -> Dict[str, Any]:
    """
    Prefer fleet_policies catalog / overrides over stale DB columns.

    Sync writes catalog into DB, but tag fixes land in catalog first —
    APIs must not keep showing old CIS4.1 dumps until the next full sync.
    """
    enrich = enrich_policy_from_catalog(policy_name, platform=platform)
    catalog_sids = list(enrich.get("cis_safeguard_ids") or [])
    raw_db = db_sids or []
    if isinstance(raw_db, str):
        raw_db = _normalize_sid_list(raw_db)
    else:
        raw_db = _normalize_sid_list(list(raw_db))

    if catalog_sids:
        sids = catalog_sids
        source = enrich.get("mapping_source") or "catalog"
    else:
        sids = raw_db
        source = "database"

    return {
        "cis_safeguard_ids": sids,
        "primary": primary_safeguard(sids),
        "cis_category": enrich.get("cis_category") or "",
        "cis_subcategory": enrich.get("cis_subcategory") or "",
        "benchmark_section": enrich.get("benchmark_section") or "",
        "catalog_matched": bool(enrich.get("catalog_matched")),
        "source": source,
    }


def catalog_stats() -> Dict[str, Any]:
    cat = load_policy_catalog().get("policies") or {}
    with_sg = sum(1 for p in cat.values() if p.get("cis_safeguard_ids"))
    smap = load_safeguard_d3fend()
    sg_mapped = sum(1 for m in smap.values() if (m.get("attack_ids") or m.get("attack_id")))
    return {
        "policy_count": len(cat),
        "with_safeguard_ids": with_sg,
        "safeguard_map_size": len(smap),
        "safeguard_with_attack": sg_mapped,
        "cis_controls_size": len(load_cis_controls()),
    }


def mapping_coverage_stats() -> Dict[str, Any]:
    """Aggregate mapping_status across catalog policies (for KPI / audit)."""
    from collections import Counter

    cat = load_policy_catalog().get("policies") or {}
    status_c: Counter = Counter()
    attack_c: Counter = Counter()
    for name, p in cat.items():
        sids = p.get("cis_safeguard_ids") or []
        sid = sids[0] if sids else ""
        m = mapping_for_policy(
            policy_name=name,
            cis_category=p.get("cis_category") or "",
            cis_subcategory=p.get("cis_subcategory") or "",
            safeguard_id=sid,
        )
        status_c[m.get("mapping_status") or "unmapped"] += 1
        for a in m.get("attack_ids") or []:
            attack_c[a] += 1
    total = max(len(cat), 1)
    return {
        "total_policies": len(cat),
        "by_status": dict(status_c),
        "pct_mapped": round(100.0 * status_c.get("mapped", 0) / total, 1),
        "pct_not_applicable": round(100.0 * status_c.get("not_applicable", 0) / total, 1),
        "pct_needs_review": round(100.0 * status_c.get("needs_review", 0) / total, 1),
        "pct_unmapped": round(100.0 * status_c.get("unmapped", 0) / total, 1),
        "unique_techniques": len(attack_c),
        "top_techniques": attack_c.most_common(15),
    }
