#!/usr/bin/env python3
"""
Apply curated multi-technique ATT&CK maps onto safeguard_d3fend.json.

Run after normalize_safeguard_ids.py (which rebuilds D3FEND skeleton).
Does not invent OS-check→T-code 1:1 maps; fills CIS Controls v8.1 safeguard rows.

Usage:
  python3 scripts/apply_attack_maps.py
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

DASH = Path(__file__).resolve().parents[1]
DATA = DASH / "backend" / "data"

# Official-ish multi-technique maps (primary first).
# Status: mapped | not_applicable | needs_review
MAP: dict[str, tuple[list[str], str, str, str]] = {
    "CIS1.1": (["T1082", "T1018", "T1046"], "mapped", "high",
               "Asset inventory counters host/network discovery"),
    "CIS1.2": (["T1200", "T1195"], "mapped", "medium",
               "Unauthorized assets / supply-chain hardware surface"),
    "CIS2.1": (["T1518", "T1082"], "mapped", "high",
               "Software inventory counters software discovery"),
    "CIS2.2": (["T1190", "T1210"], "mapped", "medium",
               "Supported software reduces known exploit surface"),
    "CIS2.3": (["T1204", "T1059", "T1105"], "mapped", "high",
               "Removing unauthorized software reduces user execution & tooling"),
    "CIS2.5": (["T1204", "T1059", "T1105"], "mapped", "medium",
               "Allowlisting authorized software (v8.1 2.5)"),
    "CIS2.9": (["T1518", "T1082"], "mapped", "low",
               "Software inventory family (benchmark-tagged)"),
    "CIS2.10": (["T1542", "T1495"], "mapped", "medium",
                "Power/firmware related configs"),
    "CIS2.13": (["T1078", "T1133"], "mapped", "medium",
                "Login/session surface hardening"),
    "CIS2.14": (["T1534", "T1566"], "mapped", "low",
                "Consumer services surface"),
    "CIS3.2": (["T1213", "T1005", "T1083"], "mapped", "medium",
               "Data inventory supports detecting collection targets"),
    "CIS3.3": (["T1222", "T1005", "T1083"], "mapped", "high",
               "ACLs counter permission mod & local data access"),
    "CIS3.4": (["T1070", "T1565"], "mapped", "medium",
               "Retention limits adversary dwell & data manipulation window"),
    "CIS3.5": (["T1485", "T1070"], "mapped", "medium",
               "Secure disposal counters data destruction"),
    "CIS3.6": (["T1005", "T1530", "T1552"], "mapped", "high",
               "Device encryption counters local collection & credential theft"),
    "CIS3.10": (["T1005", "T1041", "T1567"], "mapped", "medium",
                "Data protection family"),
    "CIS3.11": (["T1005", "T1530"], "mapped", "medium",
                "Data protection family"),
    "CIS3.14": (["T1485", "T1070"], "mapped", "medium",
                "Data disposal family"),
    # Pure process / govern controls — no honest single ATT&CK technique link
    "CIS4.1": ([], "not_applicable", "not_applicable",
               "Secure configuration *process* (Govern) — no technical T-link"),
    "CIS4.2": ([], "not_applicable", "not_applicable",
               "Network secure-config *process* (Govern) — no technical T-link"),
    "CIS4.3": (["T1078", "T1021"], "mapped", "high",
               "Session lock reduces unattended account use"),
    "CIS4.4": (["T1021", "T1046", "T1219"], "mapped", "high",
               "Server firewall limits lateral movement"),
    "CIS4.5": (["T1021", "T1046", "T1219"], "mapped", "high",
               "Endpoint firewall / network hardening"),
    "CIS4.6": (["T1562", "T1078", "T1059"], "mapped", "medium",
               "Securely manage enterprise assets and software"),
    "CIS4.7": (["T1078", "T1136"], "mapped", "high",
               "Default account management"),
    "CIS4.8": (["T1562", "T1548", "T1112", "T1204"], "mapped", "medium",
               "Disable unnecessary services/features — multi-technique by design"),
    "CIS4.9": (["T1071", "T1568"], "mapped", "medium",
               "Trusted DNS reduces C2/resolution abuse"),
    "CIS5.1": (["T1078", "T1136", "T1087"], "mapped", "high",
               "Account inventory"),
    "CIS5.2": (["T1078", "T1110", "T1552"], "mapped", "high",
               "Unique passwords / auth hardening"),
    "CIS5.3": (["T1078", "T1136"], "mapped", "medium",
               "Disable dormant accounts"),
    "CIS5.4": (["T1078", "T1548", "T1134"], "mapped", "high",
               "Admin separation"),
    "CIS5.5": (["T1078", "T1136"], "mapped", "medium",
               "Service account inventory family"),
    "CIS5.6": (["T1078", "T1136"], "mapped", "high",
               "Disable root/guest-class accounts"),
    "CIS5.7": (["T1078", "T1021"], "mapped", "medium",
               "Admin lateral login restrictions"),
    "CIS5.8": (["T1078", "T1136"], "mapped", "medium",
               "Account hygiene family"),
    "CIS5.9": (["T1078", "T1136"], "mapped", "high",
               "Guest account removal"),
    "CIS5.10": (["T1078", "T1110"], "mapped", "medium",
                "Account lockout family"),
    "CIS5.11": (["T1078", "T1548"], "mapped", "medium",
                "Privileged account family"),
    "CIS6.1": ([], "not_applicable", "not_applicable",
               "Access granting *process* (Govern) — no technical T-link"),
    "CIS6.2": ([], "not_applicable", "not_applicable",
               "Access revoking *process* (Govern) — no technical T-link"),
    "CIS6.3": (["T1078", "T1110", "T1556"], "mapped", "high",
               "MFA for externally exposed apps"),
    "CIS6.4": (["T1078", "T1021", "T1110"], "mapped", "high",
               "MFA for remote access"),
    "CIS6.5": (["T1078", "T1548", "T1110"], "mapped", "high",
               "MFA for administrative access"),
    "CIS6.6": (["T1078", "T1556"], "mapped", "medium",
               "Access control family"),
    "CIS6.7": (["T1078", "T1556"], "mapped", "medium",
               "Access control family"),
    "CIS6.8": (["T1078", "T1021"], "mapped", "medium",
               "Remote access control family"),
    "CIS6.9": (["T1078", "T1556"], "mapped", "medium",
               "Access control family"),
    "CIS6.10": (["T1078", "T1134"], "mapped", "medium",
                "Access control family"),
    "CIS6.11": (["T1078", "T1548"], "mapped", "medium",
                "Access control family"),
    "CIS6.12": (["T1078", "T1556"], "mapped", "medium",
                "Access control family"),
    "CIS6.13": (["T1078", "T1021"], "mapped", "medium",
                "Access control family"),
    "CIS6.14": (["T1078", "T1136"], "mapped", "medium",
                "Access control family"),
    "CIS7.3": (["T1190", "T1210", "T1068"], "mapped", "high",
               "OS patching reduces exploit paths"),
    "CIS7.1": ([], "not_applicable", "not_applicable",
               "Establish patch management *process* — no technical T-link"),
    "CIS7.2": (["T1190", "T1068"], "mapped", "high",
               "Application patch management"),
    "CIS7.4": (["T1190", "T1210"], "mapped", "medium",
               "Automated application patch"),
    "CIS8.1": ([], "not_applicable", "not_applicable",
               "Audit log management *process* (Govern) — no technical T-link"),
    "CIS8.2": (["T1070", "T1562", "T1005"], "mapped", "high",
               "Collect audit logs"),
    "CIS8.3": (["T1070", "T1485"], "mapped", "high",
               "Adequate log storage"),
    "CIS8.4": (["T1070", "T1562"], "mapped", "high",
               "Time sync / standard log content family"),
    "CIS8.5": (["T1070", "T1059", "T1003"], "mapped", "high",
               "Detailed audit logging"),
    "CIS9.1": (["T1189", "T1204", "T1566"], "mapped", "high",
               "Supported browsers/email clients"),
    "CIS9.2": (["T1566", "T1204"], "mapped", "medium",
               "Email client hardening family"),
    "CIS10.1": (["T1204", "T1059", "T1105"], "mapped", "high",
               "Anti-malware"),
    "CIS10.2": (["T1204", "T1059"], "mapped", "medium",
               "Anti-malware configuration family"),
    "CIS10.3": (["T1091", "T1204"], "mapped", "medium",
               "Removable media / USB abuse"),
    "CIS10.5": (["T1204", "T1059", "T1548", "T1547"], "mapped", "high",
               "Anti-exploitation features (SEHOP, ASR, DEP, etc.)"),
    "CIS11.2": (["T1490", "T1486"], "mapped", "high",
               "Automated backups"),
    "CIS11.1": (["T1490", "T1486"], "mapped", "high",
               "Backup process"),
    "CIS12.1": (["T1190", "T1210", "T1046"], "mapped", "high",
               "Up-to-date network infrastructure"),
    "CIS13.7": (["T1046", "T1048", "T1071"], "mapped", "medium",
               "Network monitoring family"),
    "CIS14.9": ([], "not_applicable", "not_applicable",
               "Security awareness training — no technical T-link"),
    "CIS15.1": (["T1199", "T1195"], "mapped", "medium",
               "Service provider inventory"),
    "CIS15.2": (["T1199", "T1195"], "mapped", "low",
               "Service provider family"),
}

# Techniques that may appear in MAP — ensure mitre_data has them
EXTRA_MITRE = {
    "T1091": {"name": "Replication Through Removable Media", "tactic": "Lateral Movement"},
    "T1200": {"name": "Hardware Additions", "tactic": "Initial Access"},
    "T1568": {"name": "Dynamic Resolution", "tactic": "Command and Control"},
}


def main() -> int:
    sd_path = DATA / "safeguard_d3fend.json"
    cc_path = DATA / "cis_controls_v8.json"
    mitre_path = DASH / "backend" / "mitre_data.json"

    sd = json.loads(sd_path.read_text(encoding="utf-8"))
    cc = json.loads(cc_path.read_text(encoding="utf-8")) if cc_path.exists() else {}

    filled = 0
    for sid, entry in list(sd.items()):
        e = deepcopy(entry)
        c = cc.get(sid) or {}
        if c.get("title"):
            e["title"] = c["title"].strip()
        if c.get("security_function"):
            e["security_function"] = c["security_function"]

        if sid in MAP:
            ids, status, conf, rationale = MAP[sid]
            e["attack_ids"] = ids
            e["attack_id"] = ids[0] if ids else ""
            e["mapping_status"] = status
            e["mapping_confidence"] = conf
            e["mapping_rationale"] = rationale
            e["mapping_source"] = "cis_v8_attack_curated"
            filled += 1
        else:
            atk = (e.get("attack_id") or "").strip()
            ids = e.get("attack_ids") or ([atk] if atk else [])
            ids = [a for a in ids if a]
            e["attack_ids"] = ids
            e["attack_id"] = ids[0] if ids else ""
            if ids:
                e["mapping_status"] = e.get("mapping_status") or "mapped"
            else:
                e["mapping_status"] = "needs_review"
                e["mapping_confidence"] = "unmapped"
                e["mapping_rationale"] = e.get("mapping_rationale") or "No curated ATT&CK link yet"
        e["cis_safeguard_id"] = sid
        sd[sid] = e

    sd_path.write_text(json.dumps(sd, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # Expand mitre_data for any new IDs
    mitre = json.loads(mitre_path.read_text(encoding="utf-8")) if mitre_path.exists() else {}
    used = set()
    for e in sd.values():
        for a in e.get("attack_ids") or []:
            used.add(a)
    for tid, meta in EXTRA_MITRE.items():
        if tid not in mitre:
            mitre[tid] = meta
    # stub any missing used techniques
    for tid in sorted(used):
        if tid not in mitre:
            mitre[tid] = {"name": tid, "tactic": "Unknown"}
    mitre_path.write_text(json.dumps(mitre, indent=2) + "\n", encoding="utf-8")

    empty = [
        sid for sid, e in sd.items()
        if not e.get("attack_ids")
        and (e.get("mapping_status") or "").lower() not in ("not_applicable",)
    ]
    na = sum(1 for e in sd.values() if (e.get("mapping_status") or "").lower() == "not_applicable")
    print(
        f"safeguards={len(sd)} curated_filled={filled} "
        f"not_applicable={na} empty_attack={len(empty)} techniques_used={len(used)}"
    )
    if empty:
        print("empty (needs_review):", empty[:12])
    return 0 if not empty else 1


if __name__ == "__main__":
    raise SystemExit(main())
