#!/usr/bin/env python3
"""
Build backend/data/policy_catalog.json from a fleet_policies checkout.

Usage:
  python scripts/build_policy_catalog.py /path/to/fleet_policies
  python scripts/build_policy_catalog.py  # defaults to /tmp/fleet_policies
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

ROOT_DEFAULT = Path("/tmp/fleet_policies/CIS-8.1")
OUT_DIR = Path(__file__).resolve().parents[1] / "backend" / "data"


def parse_tag_string(tags_raw) -> dict:
    if tags_raw is None:
        return {}
    if isinstance(tags_raw, dict):
        return {str(k): str(v) for k, v in tags_raw.items()}
    if isinstance(tags_raw, list):
        tags_str = ",".join(str(x) for x in tags_raw)
    else:
        tags_str = str(tags_raw)
    tags_str = re.sub(r"\s+", " ", tags_str).strip()
    tags = {}
    for p in re.split(r",\s*(?=[a-zA-Z0-9_]+:)", tags_str):
        if ":" in p:
            k, v = p.split(":", 1)
            tags[k.strip()] = v.strip()
    return tags


def split_safeguards(sids) -> list:
    if not sids:
        return []
    out = []
    for s in re.split(r"[|;,\s]+", str(sids)):
        s = s.strip()
        if not s or s in ("CISNone", "None", "none", "null"):
            continue
        if re.match(r"^\d", s):
            s = "CIS" + s
        if not s.startswith("CIS"):
            s = "CIS" + s
        out.append(s)
    return out


def build_catalog(cis_root: Path) -> dict:
    catalog = {}
    for y in sorted(cis_root.rglob("*.yaml")):
        text = y.read_text(encoding="utf-8", errors="replace")
        for doc in re.split(r"\n---\s*\n", text):
            doc = doc.strip()
            if not doc or "kind: policy" not in doc:
                continue
            try:
                data = yaml.safe_load(doc)
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            spec = data.get("spec") or {}
            name = spec.get("name")
            if not name:
                continue
            tags = parse_tag_string(spec.get("tags"))
            catalog[name] = {
                "name": name,
                "platform": spec.get("platform") or tags.get("platform") or "",
                "description": (spec.get("description") or "")[:2000],
                "tags": tags,
                "cis_safeguard_ids": split_safeguards(tags.get("cis_safeguard_ids", "")),
                "benchmark": tags.get("benchmark") or "",
                "control": tags.get("control") or "",
                "cis_category": tags.get("cis_category") or "",
                "cis_subcategory": tags.get("cis_subcategory") or "",
                "level": tags.get("level") or "",
                "critical": str(tags.get("critical", "")).lower() == "true",
                "framework": tags.get("framework") or "",
                "source_file": str(y.relative_to(cis_root)),
            }
    return catalog


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT_DEFAULT
    if (root / "CIS-8.1").is_dir():
        root = root / "CIS-8.1"
    if not root.is_dir():
        print(f"Not found: {root}", file=sys.stderr)
        sys.exit(1)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    catalog = build_catalog(root)
    payload = {
        "version": 1,
        "source": "https://github.com/karmine05/fleet_policies",
        "policy_count": len(catalog),
        "policies": catalog,
    }
    out = OUT_DIR / "policy_catalog.json"
    out.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    with_sg = sum(1 for p in catalog.values() if p["cis_safeguard_ids"])
    print(f"Wrote {out} — {len(catalog)} policies, {with_sg} with cis_safeguard_ids")


if __name__ == "__main__":
    main()
