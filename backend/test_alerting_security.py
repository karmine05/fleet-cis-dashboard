"""Run: cd backend && python -m unittest test_alerting_security"""
import unittest
from datetime import datetime, timezone
from unittest import mock

from alerting import http
from alerting.formatters import format_slack, format_telegram, public_outbound
from alerting.models import AlertEvent, Destination
from alerting.ssrf import UnsafeWebhookUrl
from alerting.validate import merge_secret

EVENT = AlertEvent("r", "R", "k", "f", "subject", ("line",), {}, datetime(2026, 11, 4, tzinfo=timezone.utc))


class PostJsonSsrf(unittest.TestCase):
    def test_hostname_resolving_private_is_refused(self):
        with mock.patch("alerting.ssrf.default_resolver", return_value=["10.0.0.1"]) as resolver, \
                mock.patch("requests.Session") as session, mock.patch("requests.request") as request:
            with self.assertRaises(UnsafeWebhookUrl):
                http.post_json("POST", "https://hooks.example.com/x", {}, {"a": 1})
        resolver.assert_called_once_with("hooks.example.com")
        session.assert_not_called()
        request.assert_not_called()

    def test_literal_private_ip_is_refused(self):
        with mock.patch("alerting.ssrf.default_resolver") as resolver, mock.patch("requests.Session") as session:
            with self.assertRaises(UnsafeWebhookUrl):
                http.post_json("POST", "http://169.254.169.254/latest", {}, {})
        resolver.assert_not_called()
        session.assert_not_called()


class PublicOutboundRedaction(unittest.TestCase):
    def test_telegram_token_hidden(self):
        token = "123456:SECRET-bot-token"
        dest = Destination("d", "t", "telegram", True, {"bot_token": token, "chat_id": "42"})
        out = public_outbound(format_telegram(EVENT, dest))
        self.assertNotIn(token, repr(out))
        self.assertNotIn("SECRET", repr(out))
        self.assertTrue(out["url"].endswith("/bot***/sendMessage"))

    def test_slack_secret_path_hidden(self):
        url = "https://hooks.slack.com/services/T000/B000/SECRETPATH"
        dest = Destination("d", "s", "slack", True, {"webhook_url": url})
        out = public_outbound(format_slack(EVENT, dest))
        self.assertNotIn("SECRETPATH", repr(out))
        self.assertNotIn("/services/", repr(out))
        self.assertEqual(out["url"], "https://hooks.slack.com/***")


class MergeSecret(unittest.TestCase):
    def test_semantics(self):
        cases = [
            ("***", "old", "old"),       # placeholder echoed back by the UI keeps the stored secret
            ("  ***  ", "old", "old"),
            ("", "old", "old"),
            ("   ", "old", "old"),
            (None, "old", "old"),
            ("new", "old", "new"),
            (5, "old", 5),
        ]
        for new, old, want in cases:
            with self.subTest(new=new):
                self.assertEqual(merge_secret(new, old), want)


if __name__ == "__main__":
    unittest.main()
