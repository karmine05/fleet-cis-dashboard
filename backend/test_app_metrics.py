"""Run: cd backend && python -m unittest test_app_metrics"""
import os
import unittest
from datetime import datetime, timedelta
from unittest import mock

# Importing app with DATABASE_URL set seeds config_settings; tests must not write to the DB.
os.environ.pop("DATABASE_URL", None)
import app  # noqa: E402


class CacheKey(unittest.TestCase):
    def key(self, qs):
        with app.app.test_request_context(qs):
            return app._cache_key("ep", "g1", "-")

    def test_scope_arg_in_key(self):
        self.assertEqual(self.key("/?team=a"), "fleetcis:v1:ep:g1:-:team=a")

    def test_unknown_arg_does_not_change_key(self):
        self.assertEqual(self.key("/?team=a&junk=1"), self.key("/?team=a"))
        self.assertEqual(self.key("/?junk=1"), self.key("/"))

    def test_arg_order_and_empty_values(self):
        self.assertEqual(self.key("/?label=x&team=a"), self.key("/?team=a&label=x"))
        self.assertEqual(self.key("/?team=&platform=darwin"), self.key("/?platform=darwin"))


class TechniqueTrends(unittest.TestCase):
    def setUp(self):
        p1 = mock.patch.object(app, "HISTORY_TREND_MIN_SAMPLE", 5)
        p2 = mock.patch.object(app, "MITRE_DATA", {"T1": {"name": "One", "tactic": "TA"}})
        p1.start(); p2.start()
        self.addCleanup(p1.stop); self.addCleanup(p2.stop)

    def test_gains_losses_and_filters(self):
        rows = [
            {"policy_id": 1, "observed_pairs": 10, "first_fail": 5, "last_fail": 2},  # T1 +30
            {"policy_id": 2, "observed_pairs": 10, "first_fail": 0, "last_fail": 4},  # T2 -40
            {"policy_id": 3, "observed_pairs": 3, "first_fail": 3, "last_fail": 0},   # T3 below sample
            {"policy_id": 4, "observed_pairs": 10, "first_fail": 9, "last_fail": 0},  # unmapped
            {"policy_id": 5, "observed_pairs": 10, "first_fail": 2, "last_fail": 2},  # T4 unchanged
        ]
        gains, losses = app.technique_trends(rows, {1: ["T1"], 2: ["T2"], 3: ["T3"], 5: ["T4"]})
        self.assertEqual([g["id"] for g in gains], ["T1"])
        self.assertEqual(gains[0]["change"], "+30.0%")
        self.assertEqual(gains[0]["name"], "One")
        self.assertEqual((gains[0]["baseline_rate"], gains[0]["current_rate"], gains[0]["sample_size"]), (50.0, 80.0, 10))
        self.assertEqual([l["id"] for l in losses], ["T2"])
        self.assertEqual(losses[0]["change_pp"], -40.0)
        self.assertEqual(losses[0]["name"], "T2")  # falls back to the id without MITRE metadata

    def test_multi_technique_policy_counts_in_each(self):
        rows = [{"policy_id": 1, "observed_pairs": 5, "first_fail": 5, "last_fail": 0}]
        gains, _ = app.technique_trends(rows, {1: ["T1", "T9"]})
        self.assertEqual(sorted(g["id"] for g in gains), ["T1", "T9"])
        self.assertTrue(all(g["change_pp"] == 100.0 for g in gains))


class ClassifyTeamTrend(unittest.TestCase):
    def test_threshold(self):
        cases = [(0.5, "up"), (3.0, "up"), (0.4, "stable"), (0, "stable"), (-0.4, "stable"), (-0.5, "down")]
        for delta, want in cases:
            with self.subTest(delta=delta):
                self.assertEqual(app.classify_team_trend(delta), want)


class FakeCursor:
    def __init__(self, bounds, rows):
        self.bounds, self.rows, self.executed = bounds, rows, []

    def execute(self, sql, params):
        self.executed.append((sql, params))

    def fetchone(self):
        return self.bounds

    def fetchall(self):
        return self.rows


class HistoryScoreSeries(unittest.TestCase):
    def test_no_history(self):
        cur = FakeCursor({"first_seen": None, "last_seen": None}, [])
        self.assertEqual(app.history_score_series(cur, "SELECT 1", []), [])
        self.assertEqual(len(cur.executed), 1)

    def test_per_minute_buckets_merge_and_skip_empty(self):
        t0 = datetime(2026, 11, 4, 10, 0)
        rows = [
            {"bucket": t0 - timedelta(minutes=5), "measured": 0, "passing": 0},  # skipped
            {"bucket": t0, "measured": 4, "passing": 2},
            {"bucket": t0 + timedelta(minutes=1), "measured": 4, "passing": 3},  # same sync, replaces previous
            {"bucket": t0 + timedelta(hours=2), "measured": 5, "passing": 5},
        ]
        cur = FakeCursor({"first_seen": t0, "last_seen": t0 + timedelta(hours=2)}, rows)
        out = app.history_score_series(cur, "SELECT id FROM fleet_hosts WHERE team_name = %s", ["a"])
        self.assertEqual(out, [
            {"label": "Nov 04 10:01 UTC", "score": 75.0},
            {"label": "Nov 04 12:00 UTC", "score": 100.0},
        ])
        self.assertEqual(cur.executed[1][1], ["minute", app.HISTORY_TREND_DAYS, "a"])

    def test_per_day_and_thinning(self):
        t0 = datetime(2026, 10, 1)
        rows = [{"bucket": t0 + timedelta(days=i), "measured": 10, "passing": i % 11} for i in range(60)]
        cur = FakeCursor({"first_seen": t0, "last_seen": t0 + timedelta(days=59)}, rows)
        out = app.history_score_series(cur, "SELECT 1", [])
        self.assertEqual(cur.executed[1][1][0], "day")
        self.assertEqual(len(out), app.ROADMAP_MAX_POINTS)
        self.assertEqual(out[0], {"label": "Oct 01", "score": 0.0})
        self.assertEqual(out[-1]["label"], (t0 + timedelta(days=59)).strftime("%b %d"))


if __name__ == "__main__":
    unittest.main()
