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


def enrich_policy_from_catalog(policy_name: str, platform: str = "") -> Dict[str, Any]:
    """
    Return DB-ready enrichment fields for a Fleet policy name.
    """
    entry = get_catalog_entry(policy_name)
    if not entry:
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
        }

    return {
        "cis_safeguard_ids": list(entry.get("cis_safeguard_ids") or []),
        "benchmark": entry.get("benchmark") or "",
        "control_slug": entry.get("control") or "",
        "cis_category": entry.get("cis_category") or "",
        "cis_subcategory": entry.get("cis_subcategory") or "",
        "framework": entry.get("framework") or "",
        "level": entry.get("level") or "",
        "tags": entry.get("tags") or {},
        "mapping_source": "fleet_policies_catalog",
        "catalog_matched": True,
        "platform": entry.get("platform") or platform,
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
