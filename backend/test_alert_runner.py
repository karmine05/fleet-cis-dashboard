"""Run: cd backend && python -m unittest test_alert_runner"""
import unittest
from unittest import mock

from alerting import runner, store


class RunEvaluation(unittest.TestCase):
    def test_no_enabled_rules_skips_the_snapshot(self):
        disabled = mock.Mock(enabled=False)
        with mock.patch.object(store, "list_rules", return_value=[disabled]), \
             mock.patch.object(store, "list_open_incidents", return_value=[]), \
             mock.patch.object(store, "resolve_incident"), \
             mock.patch.object(store, "load_snapshot") as load_snapshot:
            self.assertEqual(runner.run_evaluation(), [])
        load_snapshot.assert_not_called()


class UndeliveredIncidents(unittest.TestCase):
    def test_open_incident_never_delivered_is_retried(self):
        from alerting.models import ACTION_SUPPRESS
        rule = mock.Mock(rule_id="r1", destination_id="d1")
        decision = mock.Mock(action=ACTION_SUPPRESS, rule=rule, fingerprint="f", event=mock.Mock())
        dest = mock.Mock(enabled=True)
        for status, expect in ((None, True), ("failed", True), ("sent", False)):
            incident = mock.Mock(rule_id="r1", fingerprint="f", incident_id="i1", last_delivery_status=status)
            with mock.patch.object(runner, "deliver") as deliver:
                runner.apply_decisions([decision], {"d1": dest}, [incident], None, None, mock.Mock())
            self.assertEqual(deliver.called, expect, status)


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
