"""Run: cd backend && python -m unittest test_sync_guards"""
import unittest
from contextlib import contextmanager
from unittest import mock

import requests

import sync_fleet_data


def _lock_conn(acquired):
    conn = mock.MagicMock()
    cur = conn.cursor.return_value.__enter__.return_value
    cur.fetchone.return_value = (acquired,)
    return conn, cur


class SyncLock(unittest.TestCase):
    def _run(self, acquired):
        conn, cur = _lock_conn(acquired)

        @contextmanager
        def fake_conn():
            yield conn

        with mock.patch.object(sync_fleet_data.db, "get_db_connection", fake_conn), \
             mock.patch.object(sync_fleet_data.db, "get_db_cursor") as db_cursor, \
             mock.patch.object(sync_fleet_data, "_sync_data_locked") as body:
            sync_fleet_data.sync_data()
        return cur, db_cursor, body

    def test_lock_not_acquired_skips_before_metadata_insert(self):
        cur, db_cursor, body = self._run(False)
        body.assert_not_called()
        db_cursor.assert_not_called()  # no sync_metadata INSERT, no init_db
        sqls = [c.args[0] for c in cur.execute.call_args_list]
        self.assertEqual(len(sqls), 1)
        self.assertIn("pg_try_advisory_lock", sqls[0])

    def test_lock_acquired_runs_and_unlocks_on_same_connection(self):
        cur, _, body = self._run(True)
        body.assert_called_once()
        sqls = [c.args[0] for c in cur.execute.call_args_list]
        self.assertIn("pg_advisory_unlock", sqls[-1])


def _http_404(body):
    resp = mock.Mock(status_code=404, text=body)
    return requests.HTTPError("404 Client Error", response=resp)


class PolicyPage404(unittest.TestCase):
    def test_plain_404_raises_without_refetch(self):
        with mock.patch.object(sync_fleet_data, "_fetch_policy_page",
                               side_effect=_http_404('{"message":"Resource Not Found"}')), \
             mock.patch.object(sync_fleet_data, "_refetch_page_one_each") as refetch, \
             mock.patch.object(sync_fleet_data, "record_fetch_error"):
            with self.assertRaises(requests.HTTPError):
                sync_fleet_data._fetch_team_policy_pages(7)
        refetch.assert_not_called()

    def test_software_installer_404_still_recovers(self):
        err = _http_404('{"message":"SoftwareInstaller was not found in the datastore"}')

        def fake_page(team_id, page, per_page):
            if page == 0:
                raise err
            return [], []  # empty page ends pagination

        def fake_refetch(team_id, page, own, inherited):
            own[1] = {"id": 1}

        with mock.patch.object(sync_fleet_data, "_fetch_policy_page", side_effect=fake_page), \
             mock.patch.object(sync_fleet_data, "_refetch_page_one_each", side_effect=fake_refetch) as refetch, \
             mock.patch.object(sync_fleet_data, "record_fetch_error"):
            own, inherited, fully_ok = sync_fleet_data._fetch_team_policy_pages(7)
        refetch.assert_called_once()
        self.assertEqual(list(own), [1])
        self.assertFalse(fully_ok)


if __name__ == "__main__":
    unittest.main()
