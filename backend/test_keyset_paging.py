"""Run: cd backend && python -m unittest test_keyset_paging"""
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlparse

import sync_fleet_data as s


class FakeFleet:
    """A Fleet /hosts list that loses host 2 right after the first page is served."""

    def __init__(self, ids, honor_after=True):
        self.ids, self.calls, self.honor_after = list(ids), 0, honor_after

    def get(self, url, **kwargs):
        q = parse_qs(urlparse(url).query)
        per_page = int(q["per_page"][0])
        rows = sorted(self.ids)
        if self.honor_after and "after" in q:
            rows = [i for i in rows if i > int(q["after"][0])]
        page = rows[:per_page]
        self.calls += 1
        if self.calls == 1:
            self.ids.remove(2)  # host 2 is fixed / removed mid-scan
        resp = mock.Mock(status_code=200)
        resp.json.return_value = {"hosts": [{"id": i} for i in page]}
        return resp


class KeysetPaging(unittest.TestCase):
    def test_host_removed_mid_scan_does_not_hide_another(self):
        fleet = FakeFleet(range(1, 8))  # 7 hosts, pages of 3
        with mock.patch.object(s, "POLICY_HOSTS_PER_PAGE", 3), \
             mock.patch.object(s.requests, "get", side_effect=fleet.get):
            ok, rows = s.fetch_policy_hosts(42, "fail")
        self.assertTrue(ok)
        # Offset paging would have skipped host 4 (it moved to position 3 of page 0).
        self.assertEqual(sorted(r[1] for r in rows), [1, 2, 3, 4, 5, 6, 7])

    def test_cursor_ignored_by_fleet_fails_instead_of_looping(self):
        fleet = FakeFleet(range(1, 8), honor_after=False)
        with mock.patch.object(s, "POLICY_HOSTS_PER_PAGE", 3), \
             mock.patch.object(s.requests, "get", side_effect=fleet.get), \
             mock.patch.object(s, "record_fetch_error"):
            ok, _ = s.fetch_policy_hosts(42, "fail")
        self.assertFalse(ok)
        self.assertLessEqual(fleet.calls, 2)


if __name__ == "__main__":
    unittest.main()
