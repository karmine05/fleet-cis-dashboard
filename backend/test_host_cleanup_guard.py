"""Run: cd backend && python -m unittest test_host_cleanup_guard"""
import unittest
from unittest import mock

import sync_fleet_data


class ConfirmHostsDeleted(unittest.TestCase):
    def test_only_404_counts_as_deleted(self):
        # 1: gone (404). 2: live but skipped by offset paging (200). 3: Fleet error (500).
        codes = {1: 404, 2: 200, 3: 500}

        def fake_get(url, **kwargs):
            resp = mock.Mock(status_code=codes[int(url.rsplit("/", 1)[1])])
            resp.raise_for_status.side_effect = None if resp.status_code < 400 else Exception("HTTP 500")
            return resp

        with mock.patch.object(sync_fleet_data.requests, "get", side_effect=fake_get), \
             mock.patch.object(sync_fleet_data, "record_fetch_error") as recorded:
            self.assertEqual(sync_fleet_data.confirm_hosts_deleted([1, 2, 3]), [1])
        recorded.assert_called_once()


if __name__ == "__main__":
    unittest.main()
