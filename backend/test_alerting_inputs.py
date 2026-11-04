"""Run: cd backend && python -m unittest test_alerting_inputs"""
import unittest
from unittest import mock

from alerting import http
from alerting.validate import PayloadError, parse_destination_payload, parse_rule_payload

DEST_ID = "6f1c2b9e-3d4a-4b5c-8e7f-0a1b2c3d4e5f"
PUBLIC_RESOLVER = lambda host: ["93.184.216.34"]  # noqa: E731


class FakeRaw:
    """Endless body: counts bytes handed out so the test can prove the read is bounded."""

    def __init__(self):
        self.served = 0

    def read1(self, amt=None, decode_content=None):
        chunk = b"x" * (amt or 1_000_000)
        self.served += len(chunk)
        return chunk

    def read(self, amt=None, decode_content=None):
        return self.read1(amt or 1_000_000, decode_content)


class PostJsonBoundedRead(unittest.TestCase):
    def test_huge_body_is_capped(self):
        raw = FakeRaw()
        response = mock.MagicMock(status_code=200, raw=raw)
        response.__enter__.return_value = response
        type(response).text = mock.PropertyMock(side_effect=AssertionError("full body read"))
        session = mock.MagicMock()
        session.__enter__.return_value = session
        session.request.return_value = response
        with mock.patch("alerting.ssrf.default_resolver", return_value=["93.184.216.34"]), \
                mock.patch("requests.Session", return_value=session):
            status, text = http.post_json("POST", "https://hooks.example.com/x", {}, {"a": 1})
        self.assertEqual(status, 200)
        self.assertLessEqual(len(text), http.RESPONSE_SNIPPET)
        self.assertLessEqual(raw.served, http.RESPONSE_SNIPPET)
        kwargs = session.request.call_args.kwargs
        self.assertTrue(kwargs["stream"])
        self.assertFalse(kwargs["allow_redirects"])
        self.assertEqual(kwargs["headers"]["Host"], "hooks.example.com")
        response.__exit__.assert_called_once()


class RuleDestinationId(unittest.TestCase):
    def _body(self, dest):
        return {"name": "r", "kind": "policy_duration", "destination_id": dest,
                "config": {"policy_ids": [1], "duration_hours": 24}}

    def test_non_uuid_rejected(self):
        for bad in ("abc", "1", "6f1c2b9e-zzzz"):
            with self.assertRaises(PayloadError):
                parse_rule_payload(self._body(bad))

    def test_uuid_accepted(self):
        self.assertEqual(parse_rule_payload(self._body(DEST_ID.upper()))["destination_id"], DEST_ID)


class WebhookHeaderClear(unittest.TestCase):
    EXISTING = {"name": "d", "channel": "webhook",
                "config": {"url": "https://hooks.example.com/x", "header_name": "X-Key", "header_value": "s3cret"}}

    def _parse(self, config):
        body = {"name": "d", "channel": "webhook", "config": {"url": "", "bearer_token": "", **config}}
        return parse_destination_payload(body, self.EXISTING, resolver=PUBLIC_RESOLVER)["config"]

    def test_clearing_name_drops_stored_value(self):
        config = self._parse({"header_name": "", "header_value": ""})
        self.assertNotIn("header_name", config)
        self.assertNotIn("header_value", config)

    def test_empty_name_with_new_value_still_rejected(self):
        with self.assertRaises(PayloadError):
            self._parse({"header_name": "", "header_value": "new"})

    def test_both_provided_kept(self):
        config = self._parse({"header_name": "X-Other", "header_value": "v2"})
        self.assertEqual((config["header_name"], config["header_value"]), ("X-Other", "v2"))

    def test_blank_value_keeps_stored_secret(self):
        config = self._parse({"header_name": "X-Key", "header_value": ""})
        self.assertEqual(config["header_value"], "s3cret")


if __name__ == "__main__":
    unittest.main()
