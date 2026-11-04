"""Run: cd backend && python -m unittest test_prune_labels"""
import unittest

from sync_fleet_data import prune_labels


class FakeCursor:
    def __init__(self, rowcount=0):
        self.calls, self.rowcount = [], rowcount

    def execute(self, sql, params=None):
        self.calls.append((sql, params))


class PruneLabels(unittest.TestCase):
    def test_deletes_labels_missing_from_fleet(self):
        cur = FakeCursor(rowcount=1)
        self.assertEqual(prune_labels(cur, [{'id': 6}, {'id': 7}], fetch_failed=False), 1)
        sql, params = cur.calls[0]
        self.assertIn("DELETE FROM fleet_labels", sql)
        self.assertEqual(params, ([6, 7],))

    def test_never_prunes_after_failed_or_empty_fetch(self):
        for labels, failed in (([{'id': 6}], True), ([], False)):
            cur = FakeCursor(rowcount=99)
            self.assertEqual(prune_labels(cur, labels, fetch_failed=failed), 0)
            self.assertEqual(cur.calls, [])


if __name__ == "__main__":
    unittest.main()
