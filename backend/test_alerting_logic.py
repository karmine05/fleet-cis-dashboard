"""Run: cd backend && python -m unittest test_alerting_logic"""
import unittest
from datetime import datetime, timedelta, timezone

from alerting import evaluate
from alerting.models import HistoryRow, Result, Snapshot
from alerting.ssrf import UnsafeWebhookUrl, _ip_blocked, validate_webhook_url

T0 = datetime(2026, 11, 1, tzinfo=timezone.utc)


def at(hours):
    return T0 + timedelta(hours=hours)


class WebhookGuard(unittest.TestCase):
    def test_non_public_addresses_are_blocked(self):
        for ip in ("127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254",
                   "100.100.100.200", "::1", "::ffff:10.0.0.1", "fd00::1", "0.0.0.0"):
            self.assertTrue(_ip_blocked(ip), ip)
        self.assertFalse(_ip_blocked("8.8.8.8"))

    def test_hostname_resolving_inside_is_rejected(self):
        with self.assertRaises(UnsafeWebhookUrl):
            validate_webhook_url("https://hooks.example/x", resolver=lambda h: ["93.184.216.34", "10.0.0.5"])
        self.assertEqual(validate_webhook_url("https://hooks.example/x", resolver=lambda h: ["93.184.216.34"]),
                         "https://hooks.example/x")


class HistoryLookups(unittest.TestCase):
    # pair (1, 1): fail at 0h, pass at 5h, fail again at 10h (current)
    history = [HistoryRow(1, 1, "fail", at(0)), HistoryRow(1, 1, "pass", at(5)), HistoryRow(1, 1, "fail", at(10))]
    current = Result(1, 1, "fail", at(10))

    def snap(self, now_h):
        return Snapshot.build(at(now_h), [], [], [self.current], self.history)

    def test_status_at_picks_the_last_change_at_or_before(self):
        s = self.snap(20)
        self.assertIsNone(evaluate._status_at(s, 1, 1, at(-1)))
        self.assertEqual(evaluate._status_at(s, 1, 1, at(4)), "fail")
        self.assertEqual(evaluate._status_at(s, 1, 1, at(5)), "pass")
        self.assertEqual(evaluate._status_at(s, 1, 1, at(12)), "fail")

    def test_continuous_fail_counts_from_the_last_fail(self):
        s = self.snap(20)
        self.assertTrue(evaluate._is_continuous_fail(self.current, s, timedelta(hours=8)))
        self.assertFalse(evaluate._is_continuous_fail(self.current, s, timedelta(hours=12)))


if __name__ == "__main__":
    unittest.main()
