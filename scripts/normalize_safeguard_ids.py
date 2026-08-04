#!/usr/bin/env python3
"""
Normalize cis_safeguard_ids in fleet_policies to official CIS Controls v8.1 IDs.

Also writes:
  - backend/data/policy_catalog.json (rebuilt from fixed YAML)
  - backend/data/safeguard_id_fixes.json (change log)
  - backend/data/safeguard_overrides.json (dashboard hard overrides by policy name)

Usage:
  python scripts/normalize_safeguard_ids.py /path/to/fleet_policies
"""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

try:
    import yaml
except ImportError:
    print("pip install pyyaml", file=sys.stderr)
    sys.exit(1)

DASH = Path(__file__).resolve().parents[1]
OFFICIAL = json.loads((DASH / "backend/data/cis_controls_v8.json").read_text())
# Parsed catalog is incomplete (~56 of full v8.1). Accept any CIS Controls-shaped
# ID (CIS<control>.<safeguard> only — not deep benchmark paths like CIS4.10.20.1).
_CONTROLS_SHAPE = re.compile(r"^CIS\d{1,2}\.\d{1,2}$")
OFFICIAL_IDS = set(OFFICIAL.keys()) | {
    f"CIS{c}.{s}" for c in range(1, 19) for s in range(1, 15)
}
OFFICIAL_IDS = {s for s in OFFICIAL_IDS if _CONTROLS_SHAPE.match(s)}

# First match wins. Prefer specific technical signals over broad category titles.
RULES: list[tuple[str, list[str]]] = [
    # Integrity / SIP / secure boot — before "authentication" in parent titles
    (r"\bsip\b|system integrity protection|secure boot|gatekeeper|xprotect|firmware",
     ["CIS10.1", "CIS4.1", "CIS2.3"]),
    (r"file integrity|aide\b|\bfim\b|integrity check",
     ["CIS3.3", "CIS3.4", "CIS8.2"]),
    # Encryption (before "password" on BitLocker password prompts)
    (r"bitlocker|filevault|dm-crypt|encrypt|cipher|apfs.*encrypt|volume.*encrypt",
     ["CIS3.6", "CIS3.11"] if "CIS3.11" in OFFICIAL_IDS else ["CIS3.6"]),
    # Patch / updates
    (r"software update|os update|install.*update|patch|security response|auto-?download.*update",
     ["CIS7.3", "CIS7.4", "CIS7.1"]),
    # Authn / passwords / lockout (after encryption)
    (r"password|passwd|lockout|pam\b|mfa|multi-factor|authenticator|kerberos|ntlm|smart.?card",
     ["CIS5.2", "CIS4.3", "CIS5.4"]),
    (r"logon|login window|interactive logon|account lock",
     ["CIS5.2", "CIS4.3"]),
    # Network
    (r"firewall|packet filter|network isolation|ipsec|network protection|rdp|remote desktop|\bssh\b|\bsmb\b|port filter",
     ["CIS4.5", "CIS4.4", "CIS12.1"]),
    # Logging / audit
    (r"audit(ing|ed)?|event log|log management|syslog|journald|auditd|logging",
     ["CIS8.2", "CIS8.5", "CIS8.3"]),
    (r"time sync|ntp\b|chrony|timesync|time synchronization",
     ["CIS8.4"] if "CIS8.4" in OFFICIAL_IDS else ["CIS8.2"]),
    # Accounts / privileges
    (r"\broot\b|guest account|administrator account|user right|privilege|uac\b|local group|sudoers|account management",
     ["CIS5.4", "CIS5.1", "CIS5.3", "CIS4.7"]),
    # Session lock
    (r"screen saver|inactiv|session lock|lock screen|above lock|device lock|require password after",
     ["CIS4.3"]),
    # Malware
    (r"malware|defender|antivirus|asr\b|attack surface|smartscreen|exploit guard",
     ["CIS10.1", "CIS10.2", "CIS10.3"]),
    # Backup
    (r"backup|restore|recovery|shadow copy",
     ["CIS11.2", "CIS11.1", "CIS11.3", "CIS11.4"]),
    # Browser
    (r"safari|chrome|edge|browser|internet explorer",
     ["CIS9.1", "CIS9.2", "CIS4.1"]),
    # Removable media / DMA / drivers
    (r"removable|usb\b|external media",
     ["CIS10.3", "CIS4.1"]),
    (r"\bdma\b|device installation|driver install",
     ["CIS4.1"]),
    # Privacy / consumer fluff
    (r"privacy|telemetry|diagnostic|cortana|consumer experience|advertising|spotlight suggestions",
     ["CIS4.1"]),
    # Scripting
    (r"powershell|macro|office|script execution",
     ["CIS2.3", "CIS4.1"]),
    # Inventory
    (r"inventory|asset inventory",
     ["CIS1.1", "CIS1.2"]),
    # Data protection generic
    (r"data protection|sensitive data|pii",
     ["CIS3.3", "CIS3.4", "CIS3.1"]),
    # Secure configuration / services
    (r"unnecessary service|disable.*service|secure configuration|harden",
     ["CIS4.8", "CIS4.1"] if "CIS4.8" in OFFICIAL_IDS else ["CIS4.1"]),
    (r"application",
     ["CIS2.3", "CIS2.1", "CIS4.1"]),
]


def pick_official(cands: list[str]) -> list[str]:
    out = []
    for c in cands:
        # skip IDs missing from our parsed Controls set
        if c in OFFICIAL_IDS and c not in out:
            out.append(c)
    return out


def normalize_list(raw) -> list[str]:
    if not raw:
        return []
    out = []
    for s in re.split(r"[|;,\s]+", str(raw)):
        s = s.strip().strip("'\"")
        if not s or s in ("CISNone", "None", "none", "null"):
            continue
        if not s.startswith("CIS"):
            s = "CIS" + s
        out.append(s)
    return out


def parse_tag_string(tags_raw) -> dict:
    if tags_raw is None:
        return {}
    if isinstance(tags_raw, dict):
        return {str(k): str(v) for k, v in tags_raw.items()}
    s = re.sub(r"\s+", " ", str(tags_raw)).strip()
    tags = {}
    for p in re.split(r",\s*(?=[a-zA-Z0-9_]+:)", s):
        if ":" in p:
            k, v = p.split(":", 1)
            tags[k.strip()] = v.strip()
    return tags


def is_bad_official(sg: str, blob: str) -> bool:
    """True if an official ID is used with clearly wrong semantics."""
    if sg.startswith("CIS1.") and not re.search(r"inventory|asset inventory", blob):
        if re.search(
            r"update|patch|lock|password|cortana|session|browser|firewall|privacy|telemetry",
            blob,
        ):
            return True
    # CIS5.x account tags on pure encryption without account language
    if sg.startswith("CIS5.") and re.search(r"encrypt|bitlocker|filevault|apfs", blob):
        if not re.search(r"password|account|user|authent|logon", blob):
            return True
    return False


def choose_safeguards(name: str, tags: dict, slug_map: dict) -> tuple[list[str], str]:
    cat = tags.get("cis_category", "")
    sub = tags.get("cis_subcategory", "")
    blob = f"{name} {cat} {sub} {tags.get('control', '')}".lower()
    old = normalize_list(tags.get("cis_safeguard_ids", ""))

    old_official = [s for s in old if s in OFFICIAL_IDS]
    if old_official and not any(is_bad_official(s, blob) for s in old_official):
        return old_official, "keep_official_tag"

    for pat, cands in RULES:
        if re.search(pat, blob):
            picked = pick_official(cands)
            if picked:
                return picked[:1], f"rule:{pat[:40]}"

    slug = tags.get("control", "")
    if slug and slug in slug_map:
        sg = slug_map[slug]
        if sg in OFFICIAL_IDS:
            return [sg], "section_map"
        m = re.match(r"CIS(\d+)\.(\d+)", sg)
        if m:
            parent = f"CIS{m.group(1)}.{m.group(2)}"
            if parent in OFFICIAL_IDS:
                return [parent], "section_map_parent"

    return ["CIS4.1"], "default_secure_config"


def load_slug_map(fp_root: Path) -> dict:
    slug_map = {}
    for sm in fp_root.rglob("*-section-map.csv"):
        with sm.open(newline="", encoding="utf-8", errors="replace") as f:
            r = csv.DictReader(f, skipinitialspace=True)
            if r.fieldnames:
                r.fieldnames = [h.strip() for h in r.fieldnames]
            for row in r:
                slug = (row.get("control") or "").strip()
                sg = (row.get("cis_safeguard_id") or "").strip().strip("'")
                if not slug or not sg:
                    continue
                if not sg.startswith("CIS"):
                    sg = "CIS" + sg
                slug_map[slug] = sg
    return slug_map


def rebuild_tags_string(tags: dict) -> str:
    preferred = [
        "framework",
        "benchmark",
        "level",
        "platform",
        "category",
        "requirement",
        "critical",
        "control",
        "cis_category",
        "cis_subcategory",
        "cis_safeguard_ids",
        "benchmark_section",
    ]
    ordered = []
    seen = set()
    for k in preferred:
        if k in tags and tags[k] is not None and tags[k] != "":
            ordered.append(f"{k}:{tags[k]}")
            seen.add(k)
    for k, v in tags.items():
        if k not in seen and v is not None and v != "":
            ordered.append(f"{k}:{v}")
    return ", ".join(ordered)


def process_fleet_policies(fp_root: Path) -> tuple[list, Counter]:
    if (fp_root / "CIS-8.1").is_dir():
        fp_root = fp_root / "CIS-8.1"
    slug_map = load_slug_map(fp_root)
    changes = []
    stats = Counter()

    for ypath in sorted(fp_root.rglob("*.yaml")):
        text = ypath.read_text(encoding="utf-8")
        docs = re.split(r"\n---\s*\n", text)
        new_docs = []
        for doc in docs:
            if "kind: policy" not in doc or not doc.strip():
                new_docs.append(doc)
                continue
            try:
                data = yaml.safe_load(doc)
            except Exception:
                new_docs.append(doc)
                stats["yaml_parse_fail"] += 1
                continue
            if not isinstance(data, dict) or not data.get("spec"):
                new_docs.append(doc)
                continue

            spec = data["spec"]
            name = spec.get("name") or ""
            tags = parse_tag_string(spec.get("tags"))
            old = normalize_list(tags.get("cis_safeguard_ids", ""))
            new_sgs, reason = choose_safeguards(name, tags, slug_map)
            stats[reason] += 1

            m = re.search(r"CIS\s+([\d]+(?:\.[\d]+)*)", name)
            if m:
                tags["benchmark_section"] = m.group(1)

            old_join = ",".join(old) if old else "CISNone"
            new_join = ",".join(new_sgs) if new_sgs else "CISNone"
            tags["cis_safeguard_ids"] = new_join

            if old_join != new_join:
                changes.append(
                    {
                        "file": str(ypath.relative_to(fp_root)),
                        "name": name,
                        "old": old_join,
                        "new": new_join,
                        "reason": reason,
                        "category": tags.get("cis_category", ""),
                    }
                )

            new_tags = rebuild_tags_string(tags)

            def repl(_m, _tags=new_tags):
                return f"{_m.group(1)}tags: {_tags}\n"

            new_doc, nsub = re.subn(
                r"^([ \t]*)tags:\s*.*(?:\n\1[ \t]+.*)*\n?",
                repl,
                doc,
                count=1,
                flags=re.M,
            )
            if nsub == 0:
                new_docs.append(doc)
                stats["rewrite_failed"] += 1
            else:
                new_docs.append(new_doc)
                stats["rewritten"] += 1

        body = new_docs[0]
        for d in new_docs[1:]:
            body = body.rstrip() + "\n---\n" + d.lstrip("\n")
        ypath.write_text(body if body.endswith("\n") else body + "\n", encoding="utf-8")

    return changes, stats


def rebuild_catalog(fp_root: Path) -> dict:
    if (fp_root / "CIS-8.1").is_dir():
        fp_root = fp_root / "CIS-8.1"
    catalog = {}
    for y in sorted(fp_root.rglob("*.yaml")):
        text = y.read_text(encoding="utf-8")
        for doc in re.split(r"\n---\s*\n", text):
            if "kind: policy" not in doc:
                continue
            try:
                data = yaml.safe_load(doc)
            except Exception:
                continue
            if not isinstance(data, dict) or not data.get("spec"):
                continue
            spec = data["spec"]
            name = spec.get("name")
            if not name:
                continue
            tags = parse_tag_string(spec.get("tags"))
            sids = normalize_list(tags.get("cis_safeguard_ids", ""))
            catalog[name] = {
                "name": name,
                "platform": spec.get("platform") or tags.get("platform") or "",
                "description": (spec.get("description") or "")[:2000],
                "tags": tags,
                "cis_safeguard_ids": sids,
                "benchmark": tags.get("benchmark") or "",
                "control": tags.get("control") or "",
                "cis_category": tags.get("cis_category") or "",
                "cis_subcategory": tags.get("cis_subcategory") or "",
                "level": tags.get("level") or "",
                "critical": str(tags.get("critical", "")).lower() == "true",
                "framework": tags.get("framework") or "",
                "benchmark_section": tags.get("benchmark_section") or "",
                "source_file": str(y.relative_to(fp_root)),
            }
    return catalog


def rebuild_safeguard_d3fend(catalog: dict) -> dict:
    """Refresh D3FEND map using fixed safeguards + category rules."""
    # Reuse existing generator logic lightly
    FUNC = {
        "Identify": ("D3-AI", "Model", "Asset Inventory", ""),
        "Protect": ("D3-SCA", "Harden", "Protective Configuration", ""),
        "Detect": ("D3-LME", "Detect", "Detection Engineering", ""),
        "Respond": ("D3-IRA", "Evict", "Incident Response", ""),
        "Recover": ("D3-BA", "Restore", "Backup and Recovery", ""),
        "Govern": ("D3-AMI", "Model", "Governance Policy", ""),
    }
    CAT_RULES = [
        # Specific technical signals first (before broad "authentication" category titles)
        (r"\bsip\b|system integrity protection|secure boot|gatekeeper|xprotect",
         ("D3-SCA", "Harden", "System Integrity", "", "high")),
        (r"file integrity|aide\b|\bfim\b",
         ("D3-FIM", "Detect", "File Integrity Monitoring", "", "high")),
        (r"bitlocker|encryption|filevault|crypt",
         ("D3-FE", "Harden", "Data Encryption", "T1005", "high")),
        (r"patch|software update|os update",
         ("D3-SU", "Harden", "Software Update", "T1190", "high")),
        (r"password|passwd|lockout|pam\b|mfa|multi-factor|kerberos|ntlm",
         ("D3-UAP", "Harden", "Authentication Hardening", "T1078", "high")),
        (r"logon|login window|interactive logon",
         ("D3-UAP", "Harden", "Authentication Hardening", "T1078", "high")),
        (r"firewall|network isolation|packet|rdp|ssh\b|smb\b",
         ("D3-NI", "Isolate", "Network Isolation", "T1021", "high")),
        (r"audit|log management|logging|event log|syslog",
         ("D3-LME", "Detect", "Log Management", "", "high")),
        (r"backup|restore|recovery",
         ("D3-BA", "Restore", "Backup", "T1490", "high")),
        (r"account|privilege|uac|administrator|guest account",
         ("D3-UAP", "Harden", "Account Hardening", "T1078", "medium")),
        (r"session|screen saver|lock screen|above lock",
         ("D3-SCA", "Harden", "Session Lock", "T1078", "medium")),
        (r"browser|safari|chrome|edge",
         ("D3-SCA", "Harden", "Browser Hardening", "T1189", "medium")),
        (r"malware|defender|antivirus|asr",
         ("D3-PMAD", "Detect", "Malware Detection", "T1204", "medium")),
        (r"inventory|asset inventory",
         ("D3-AI", "Model", "Asset Inventory", "T1082", "medium")),
    ]

    smap = {}
    for meta in catalog.values():
        blob = f"{meta.get('name','')} {meta.get('cis_category','')} {meta.get('cis_subcategory','')}".lower()
        for sid in meta.get("cis_safeguard_ids") or []:
            mapped = None
            for pat, (d3, tac, tech, atk, conf) in CAT_RULES:
                if re.search(pat, blob):
                    mapped = {
                        "cis_safeguard_id": sid,
                        "d3fend_id": d3,
                        "d3fend_tactic": tac,
                        "d3fend_technique": tech,
                        "attack_id": atk,
                        "mapping_confidence": conf,
                        "mapping_source": "category_rules",
                        "title": OFFICIAL.get(sid, {}).get("title") or meta.get("cis_category") or sid,
                        "security_function": OFFICIAL.get(sid, {}).get("security_function"),
                    }
                    break
            if not mapped and sid in OFFICIAL:
                func = OFFICIAL[sid]["security_function"]
                d3, tac, tech, atk = FUNC.get(func, ("D3-SCA", "Harden", "Protective Configuration", ""))
                mapped = {
                    "cis_safeguard_id": sid,
                    "d3fend_id": d3,
                    "d3fend_tactic": tac,
                    "d3fend_technique": tech,
                    "attack_id": atk,
                    "mapping_confidence": "medium",
                    "mapping_source": f"cis_function:{func}",
                    "title": OFFICIAL[sid]["title"],
                    "security_function": func,
                }
            if not mapped:
                mapped = {
                    "cis_safeguard_id": sid,
                    "d3fend_id": "D3-SCA",
                    "d3fend_tactic": "Harden",
                    "d3fend_technique": "Protective Configuration",
                    "attack_id": "",
                    "mapping_confidence": "low",
                    "mapping_source": "default",
                    "title": meta.get("cis_category") or sid,
                }
            prev = smap.get(sid)
            rank = {"high": 3, "medium": 2, "low": 1}
            if not prev or rank.get(mapped["mapping_confidence"], 0) > rank.get(
                prev.get("mapping_confidence"), 0
            ):
                smap[sid] = mapped
    return smap


def main():
    fp = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        "/Users/beast/Documents/workspace/fleet_policies"
    )
    if not fp.exists():
        print(f"Not found: {fp}", file=sys.stderr)
        sys.exit(1)

    changes, stats = process_fleet_policies(fp)
    catalog = rebuild_catalog(fp)
    smap = rebuild_safeguard_d3fend(catalog)

    out = DASH / "backend/data"
    out.mkdir(parents=True, exist_ok=True)
    (out / "policy_catalog.json").write_text(
        json.dumps(
            {
                "version": 2,
                "source": "https://github.com/karmine05/fleet_policies",
                "policy_count": len(catalog),
                "policies": catalog,
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    (out / "safeguard_d3fend.json").write_text(json.dumps(smap, indent=2), encoding="utf-8")

    # Dashboard hard overrides: policy name → official IDs (mirrors catalog after fix)
    overrides = {
        name: {
            "cis_safeguard_ids": meta["cis_safeguard_ids"],
            "benchmark_section": meta.get("benchmark_section")
            or meta.get("tags", {}).get("benchmark_section", ""),
            "cis_category": meta.get("cis_category", ""),
        }
        for name, meta in catalog.items()
    }
    (out / "safeguard_overrides.json").write_text(json.dumps(overrides, indent=2), encoding="utf-8")
    (out / "safeguard_id_fixes.json").write_text(
        json.dumps({"stats": dict(stats), "change_count": len(changes), "changes": changes}, indent=2),
        encoding="utf-8",
    )

    # Verify
    good = sum(
        1
        for m in catalog.values()
        if m["cis_safeguard_ids"] and all(s in OFFICIAL_IDS for s in m["cis_safeguard_ids"])
    )
    print("stats", dict(stats))
    print("changes", len(changes))
    print("catalog", len(catalog), "official_ok", good)
    print("sample fixes:")
    for c in changes[:12]:
        print(f"  {c['old']:18} -> {c['new']:10} {c['name'][:60]}")


if __name__ == "__main__":
    main()
