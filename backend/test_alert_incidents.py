"""Run: cd backend && python -m unittest test_alert_incidents"""
import unittest
from contextlib import contextmanager
from unittest import mock

from alerting import runner, store


class DisabledRuleIncidents(unittest.TestCase):
    def test_open_incident_of_disabled_rule_is_resolved(self):
        disabled = mock.Mock(enabled=False, rule_id="r1")
        stale = mock.Mock(rule_id="r1", incident_id="i1")
        with mock.patch.object(store, "list_rules", return_value=[disabled]), \
             mock.patch.object(store, "list_open_incidents", return_value=[stale]), \
             mock.patch.object(store, "resolve_incident") as resolve, \
             mock.patch.object(store, "load_snapshot") as load_snapshot:
            self.assertEqual(runner.run_evaluation(now="now"), [])
        resolve.assert_called_once_with("i1", "now")
        load_snapshot.assert_not_called()


class UpdateRuleIncidents(unittest.TestCase):
    def test_update_resolves_open_incidents_in_same_cursor(self):
        cur = mock.Mock()
        cur.fetchone.return_value = {"rule_id": "r1"}

        @contextmanager
        def fake_cursor(commit=False):
            self.assertTrue(commit)
            yield cur

        payload = {"name": "n", "enabled": True, "destination_id": "d2", "config": {}}
        with mock.patch.object(store.db, "get_db_cursor", side_effect=fake_cursor) as get_cursor, \
             mock.patch.object(store, "_rule_from_row", return_value="rule"):
            self.assertEqual(store.update_rule("r1", payload), "rule")
        get_cursor.assert_called_once()
        resolve_sql, update_sql = (call.args[0] for call in cur.execute.call_args_list)
        self.assertIn("UPDATE alert_incidents", resolve_sql)
        self.assertIn("status = 'resolved'", resolve_sql)
        self.assertIn("UPDATE alert_rules", update_sql)


if __name__ == "__main__":
    unittest.main()
