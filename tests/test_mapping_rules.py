"""Unit tests for policy_catalog mapping rules and finalize logic."""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))

import policy_catalog as pc  # noqa: E402


class MappingRulesTests(unittest.TestCase):
    def setUp(self) -> None:
        pc.load_safeguard_d3fend.cache_clear()
        pc.load_policy_catalog.cache_clear()
        pc.load_safeguard_overrides.cache_clear()

    def test_encrypt_regex_does_not_match_unencrypted(self) -> None:
        name = (
            "CIS 49.14 (L1) Ensure 'Microsoft network client: "
            "Send unencrypted password to third-party SMB servers' "
            "is set to 'Disabled' (Automated)"
        )
        m = pc.mapping_for_policy(name, "Local Policies", "", "CIS5.2")
        self.assertNotEqual(m.get("d3fend_technique"), "Data Encryption")
        self.assertNotEqual(m.get("mapping_source"), "policy_name_rules")
        # Auth safeguard (override path) → authentication hardening
        self.assertEqual(m.get("d3fend_technique"), "Authentication Hardening")

    def test_rules_match_policy_name_not_subcategory(self) -> None:
        # Subcategory "Safari" must not rewrite a non-browser title to Browser Hardening
        name = "CIS 6.3.2 (L2) Audit History and Remove History Items (Manual)"
        m = pc.mapping_for_policy(name, "Applications", "Safari", "CIS8.2")
        self.assertEqual(m.get("d3fend_technique"), "Log Management")
        self.assertIn("cis_v8", (m.get("mapping_source") or ""))

    def test_browser_in_name_still_matches(self) -> None:
        name = "CIS 6.3.5 (L2) Audit Hide IP Address in Safari Setting (Manual)"
        m = pc.mapping_for_policy(name, "Applications", "Safari", "CIS8.2")
        self.assertEqual(m.get("d3fend_technique"), "Browser Hardening")
        self.assertIn("policy_name_rules", m.get("mapping_source") or "")

    def test_sip_refines_malware_safeguard(self) -> None:
        name = (
            "CIS 5.1.2 (L1) Ensure System Integrity Protection Status "
            "(SIP) Is Enabled (Automated)"
        )
        m = pc.mapping_for_policy(name, "", "", "CIS10.1")
        self.assertEqual(m.get("d3fend_technique"), "System Integrity")

    def test_filevault_encryption(self) -> None:
        name = "CIS 2.6.6 (L1) Ensure FileVault Is Enabled (Automated)"
        m = pc.mapping_for_policy(name, "System Settings", "Privacy & Security", "CIS3.6")
        self.assertEqual(m.get("d3fend_technique"), "Data Encryption")

    def test_privacy_section_does_not_hijack_gatekeeper(self) -> None:
        name = "CIS 2.6.5 (L1) Ensure Gatekeeper Is Enabled (Automated)"
        m = pc.mapping_for_policy(
            name, "System Settings", "Privacy & Security", "CIS10.1"
        )
        self.assertEqual(m.get("d3fend_technique"), "System Integrity")
        self.assertNotEqual(m.get("d3fend_technique"), "Privacy Configuration")

    def test_not_applicable_clears_attack_ids(self) -> None:
        out = pc._finalize_mapping(
            {
                "mapping_status": "not_applicable",
                "attack_ids": ["T1562"],
                "attack_id": "T1562",
                "d3fend_tactic": "Model",
                "d3fend_technique": "Governance Policy",
            },
            "CIS4.1",
        )
        self.assertEqual(out["mapping_status"], "not_applicable")
        self.assertEqual(out["attack_ids"], [])
        self.assertEqual(out["attack_id"], "")

    def test_process_safeguards_are_not_applicable(self) -> None:
        """Curated process/govern IDs must not invent ATT&CK techniques."""
        process_ids = ("CIS4.1", "CIS4.2", "CIS6.1", "CIS6.2", "CIS7.1", "CIS8.1", "CIS14.9")
        smap = pc.load_safeguard_d3fend()
        for sid in process_ids:
            if sid not in smap:
                continue
            m = pc.mapping_for_safeguard(sid)
            self.assertEqual(
                m.get("mapping_status"),
                "not_applicable",
                msg=f"{sid} should be not_applicable",
            )
            self.assertEqual(m.get("attack_ids") or [], [], msg=f"{sid} must have no T-ids")

    def test_normalize_attack_ids_dedupes(self) -> None:
        ids = pc._normalize_attack_ids("T1078, T1110; T1078 unmapped")
        self.assertEqual(ids, ["T1078", "T1110"])

    def test_unmapped_empty_safeguard(self) -> None:
        m = pc.mapping_for_policy("Totally Unknown Policy XYZ", "", "", "")
        self.assertEqual(m.get("mapping_status"), "unmapped")


if __name__ == "__main__":
    unittest.main()
