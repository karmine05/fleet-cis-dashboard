"""Run: cd backend && python -m unittest test_alert_runner"""
import unittest
from unittest import mock

from alerting import runner, store


class RunEvaluation(unittest.TestCase):
    def test_no_enabled_rules_skips_the_snapshot(self):
        disabled = mock.Mock(enabled=False)
        with mock.patch.object(store, "list_rules", return_value=[disabled]), \
             mock.patch.object(store, "load_snapshot") as load_snapshot:
            self.assertEqual(runner.run_evaluation(), [])
        load_snapshot.assert_not_called()


class DeliveryErrors(unittest.TestCase):
    def test_connection_error_text_never_carries_the_webhook_path(self):
        import requests
        secret = "/services/T000/B000/s3cr3tTok3n"
        exc = requests.exceptions.ConnectionError(
            f"HTTPSConnectionPool(host='hooks.slack.com', port=443): Max retries exceeded with url: {secret}")
        text = runner.delivery_error_text(exc)
        self.assertNotIn("s3cr3tTok3n", text)
        self.assertIn("ConnectionError", text)

    def test_url_safety_errors_stay_readable(self):
        from alerting.ssrf import UnsafeWebhookUrl
        self.assertIn("private", runner.delivery_error_text(UnsafeWebhookUrl("must not target a private address")))


if __name__ == "__main__":
    unittest.main()
