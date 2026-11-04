"""Run: cd backend && python -m unittest test_alert_formatters"""
import unittest
from datetime import datetime, timezone

from alerting.formatters import format_discord, format_telegram
from alerting.models import AlertEvent, Destination

# A 2,000-host alert: long subject (catalog policy names reach 244 chars) and thousands of lines.
BIG = AlertEvent(
    rule_id="r", rule_name="R" * 1500, kind="scoped_duration", fingerprint="f",
    subject="host-01: " + "Ensure a very long CIS policy name " * 10 + "failing 1d",
    body_lines=tuple(f"policy {i} failing on host-{i}" for i in range(2000)),
    details={"host_count": 2000}, fired_at=datetime(2026, 11, 4, tzinfo=timezone.utc))


class PlatformLimits(unittest.TestCase):
    def test_telegram_text_fits_4096(self):
        body = format_telegram(BIG, Destination("d", "t", "telegram", True, {"bot_token": "x", "chat_id": "1"})).json_body
        self.assertLessEqual(len(body["text"]), 4096)
        self.assertTrue(body["text"].startswith(BIG.subject[:50]))

    def test_discord_parts_fit_their_limits(self):
        body = format_discord(BIG, Destination("d", "t", "discord", True, {"webhook_url": "https://x"})).json_body
        embed = body["embeds"][0]
        self.assertLessEqual(len(body["content"]), 2000)
        self.assertLessEqual(len(embed["title"]), 256)
        self.assertTrue(all(len(f["value"]) <= 1024 for f in embed["fields"]))
        total = len(embed["title"]) + len(embed["description"]) + sum(len(f["name"]) + len(f["value"]) for f in embed["fields"])
        self.assertLessEqual(total, 6000)  # Discord's per-embed total

    def test_short_messages_are_unchanged(self):
        small = AlertEvent("r", "R", "k", "f", "subject", ("line",), {}, BIG.fired_at)
        body = format_telegram(small, Destination("d", "t", "telegram", True, {"bot_token": "x", "chat_id": "1"})).json_body
        self.assertEqual(body["text"], small.text)


if __name__ == "__main__":
    unittest.main()
