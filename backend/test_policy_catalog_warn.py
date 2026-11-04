import unittest
from unittest import mock

import policy_catalog


class UnmappedWarnOnceTest(unittest.TestCase):
    def setUp(self):
        policy_catalog._UNMAPPED_WARNED.clear()

    def test_warns_once_per_unmapped_id(self):
        with mock.patch.object(policy_catalog, "load_safeguard_d3fend", return_value={}), \
                mock.patch.object(policy_catalog, "logger") as log:
            first = policy_catalog.mapping_for_safeguard("CIS99.99")
            second = policy_catalog.mapping_for_safeguard("CIS99.99")
        self.assertEqual(first, second)
        self.assertEqual(log.warning.call_count, 1)

    def test_stops_warning_at_cap(self):
        with mock.patch.object(policy_catalog, "load_safeguard_d3fend", return_value={}), \
                mock.patch.object(policy_catalog, "_MAX_UNMAPPED_WARNINGS", 1), \
                mock.patch.object(policy_catalog, "logger") as log:
            policy_catalog.mapping_for_safeguard("CIS1")
            policy_catalog.mapping_for_safeguard("CIS2")
        self.assertEqual(log.warning.call_count, 1)
        self.assertEqual(policy_catalog._UNMAPPED_WARNED, {"CIS1"})


if __name__ == "__main__":
    unittest.main()
