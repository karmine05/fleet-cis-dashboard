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


def mapping_for_safeguard(safeguard_id: str) -> Dict[str, Any]:
    """D3FEND (+ optional ATT&CK) for a cis_safeguard_id."""
    if not safeguard_id:
        return _unmapped()
    sid = safeguard_id.strip()
    smap = load_safeguard_d3fend()
    if sid in smap:
        m = dict(smap[sid])
        m.setdefault("cis_safeguard_id", sid)
        return m
    # try without CIS prefix variants
    alt = sid if sid.startswith("CIS") else f"CIS{sid}"
    if alt in smap:
        m = dict(smap[alt])
        m.setdefault("cis_safeguard_id", alt)
        return m
    return _unmapped(sid)


# Per-policy refinements (first match wins). Keep patterns tight — broad
# keywords like bare "network" poison whole groups when mis-applied.
_POLICY_CAT_RULES = [
    (r"\bsip\b|system integrity protection|secure boot|gatekeeper|xprotect",
     ("D3-SCA", "Harden", "System Integrity", "", "high")),
    (r"bitlocker|filevault|dm-crypt|encrypt(ed|ion)?|cipher",
     ("D3-FE", "Harden", "Data Encryption", "T1005", "high")),
    (r"software update|os update|install.*update|security response|patch management",
     ("D3-SU", "Harden", "Software Update", "T1190", "high")),
    (r"password policy|passwd|lockout|pam\b|mfa|multi-factor|password (age|length|complex|history)",
     ("D3-UAP", "Harden", "Authentication Hardening", "T1078", "high")),
    (r"screen saver|inactiv(e|ity)|session lock|lock screen|above lock|cortana above",
     ("D3-SCA", "Harden", "Session Lock", "T1078", "high")),
    # Require explicit firewall / isolation language — not bare "network"
    (r"firewall|windows defender firewall|ufw\b|iptables|packet filter|network isolation",
     ("D3-NI", "Isolate", "Network Isolation", "T1021", "high")),
    (r"\brdp\b|remote desktop|remote assistance",
     ("D3-NI", "Isolate", "Network Isolation", "T1021", "medium")),
    (r"audit (log|pol|setting)|event log|log management|syslog|journald|auditd|time sync|chrony|\bntp\b",
     ("D3-LME", "Detect", "Log Management", "", "high")),
    (r"malware|windows defender|antivirus|\basr\b|attack surface|smartscreen",
     ("D3-PMAD", "Detect", "Malware Detection", "T1204", "medium")),
    (r"\bsafari\b|\bchrome\b|\bedge\b|internet explorer|browser",
     ("D3-SCA", "Harden", "Browser Hardening", "T1189", "medium")),
    (r"backup|shadow copy|file history|time machine",
     ("D3-BA", "Restore", "Backup", "T1490", "high")),
    (r"privacy|telemetry|diagnostic data|advertising id|analytics",
     ("D3-SCA", "Harden", "Privacy Configuration", "", "medium")),
]


def mapping_for_policy(
    policy_name: str = "",
    cis_category: str = "",
    cis_subcategory: str = "",
    safeguard_id: str = "",
) -> Dict[str, Any]:
    """
    Policy-level D3FEND mapping: category/name rules first, then safeguard aggregate.
    """
    blob = f"{policy_name} {cis_category} {cis_subcategory}".lower()
    for pat, (d3, tac, tech, atk, conf) in _POLICY_CAT_RULES:
        if re.search(pat, blob):
            base = mapping_for_safeguard(safeguard_id) if safeguard_id else _unmapped(safeguard_id)
            return {
                **base,
                "d3fend_id": d3,
                "d3fend_tactic": tac,
                "d3fend_technique": tech,
                "attack_id": atk,
                "mapping_confidence": conf,
                "mapping_source": "policy_category_rules",
                "cis_safeguard_id": safeguard_id or base.get("cis_safeguard_id", ""),
            }
    if safeguard_id:
        return mapping_for_safeguard(safeguard_id)
    return _unmapped()


def _unmapped(sid: str = "") -> Dict[str, Any]:
    return {
        "cis_safeguard_id": sid or "",
        "d3fend_id": "N/A",
        "d3fend_tactic": "Unmapped",
        "d3fend_technique": "Unmapped",
        "attack_id": "",
        "mapping_confidence": "unmapped",
        "mapping_source": "none",
        "title": sid or "Unmapped",
    }


def primary_safeguard(ids: List[str]) -> str:
    if not ids:
        return ""
    return ids[0]


def catalog_stats() -> Dict[str, Any]:
    cat = load_policy_catalog().get("policies") or {}
    with_sg = sum(1 for p in cat.values() if p.get("cis_safeguard_ids"))
    return {
        "policy_count": len(cat),
        "with_safeguard_ids": with_sg,
        "safeguard_map_size": len(load_safeguard_d3fend()),
        "cis_controls_size": len(load_cis_controls()),
    }
