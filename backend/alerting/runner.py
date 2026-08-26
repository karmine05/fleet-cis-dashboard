"""Evaluate enabled rules against stored results and deliver fires."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Callable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from alerting.evaluate import evaluate_rules
from alerting.formatters import format_outbound, public_outbound
from alerting.http import DEFAULT_TIMEOUT_SECONDS, post_json
from alerting.models import (
    ACTION_FIRE,
    ACTION_RESOLVE,
    ACTION_SUPPRESS,
    CHANNEL_TELEGRAM,
    TELEGRAM_API_HOST,
    Destination,
    EvaluationDecision,
    OpenIncident,
    Rule,
    Snapshot,
)
from alerting.ssrf import UnsafeWebhookUrl, validate_webhook_url

logger = logging.getLogger(__name__)

Transport = Callable[[str, str, dict, dict, int], Tuple[int, str]]


def run_evaluation(
    now: Optional[datetime] = None,
    transport: Optional[Transport] = None,
) -> List[EvaluationDecision]:
    """Load snapshot + rules from Postgres, evaluate, persist, send."""
    from alerting import store

    now = now or datetime.now(timezone.utc)
    transport = transport or post_json
    snapshot = store.load_snapshot(now)
    rules = [rule for rule in store.list_rules() if rule.enabled]
    destinations = {
        dest.destination_id: dest
        for dest in store.list_destinations(include_secrets=True)
    }
    open_incidents = store.list_open_incidents()
    decisions = evaluate_rules(
        rules,
        snapshot,
        {(item.rule_id, item.fingerprint) for item in open_incidents},
    )
    apply_decisions(
        decisions,
        destinations,
        open_incidents,
        now,
        transport,
        store,
    )
    return decisions


def apply_decisions(
    decisions: Sequence[EvaluationDecision],
    destinations: dict,
    open_incidents: Sequence[OpenIncident],
    now: datetime,
    transport: Transport,
    store_mod,
) -> None:
    open_by_key = {(item.rule_id, item.fingerprint): item for item in open_incidents}
    for decision in decisions:
        dest = destinations.get(decision.rule.destination_id)
        if decision.action == ACTION_FIRE:
            if dest is None or not dest.enabled or decision.event is None:
                continue
            incident_id = store_mod.open_incident(
                decision.rule.rule_id,
                decision.fingerprint,
                decision.event.subject,
                dict(decision.event.details),
                now,
            )
            deliver(incident_id, dest, decision.event, transport, store_mod)
        elif decision.action == ACTION_SUPPRESS:
            incident = open_by_key.get((decision.rule.rule_id, decision.fingerprint))
            if incident is None:
                continue
            store_mod.touch_incident(incident.incident_id, now)
            if (
                incident.last_delivery_status == "failed"
                and dest is not None
                and dest.enabled
                and decision.event is not None
            ):
                deliver(incident.incident_id, dest, decision.event, transport, store_mod)
        elif decision.action == ACTION_RESOLVE:
            incident = open_by_key.get((decision.rule.rule_id, decision.fingerprint))
            if incident is None:
                continue
            store_mod.resolve_incident(incident.incident_id, now)


def deliver(incident_id, destination: Destination, event, transport: Transport, store_mod) -> None:
    outbound = format_outbound(event, destination)
    public = public_outbound(outbound)
    try:
        _assert_send_url(destination, outbound.url)
        status_code, body = transport(
            outbound.method,
            outbound.url,
            dict(outbound.headers),
            dict(outbound.json_body),
            DEFAULT_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        logger.warning("alert delivery failed: %s", exc)
        store_mod.record_delivery(
            incident_id,
            destination.destination_id,
            "failed",
            public["url"],
            public["json"],
            error_message=f"{type(exc).__name__}: {exc}",
        )
        return
    ok = 200 <= int(status_code) < 300
    store_mod.record_delivery(
        incident_id,
        destination.destination_id,
        "sent" if ok else "failed",
        public["url"],
        public["json"],
        http_status=int(status_code),
        error_message=None if ok else (body or f"HTTP {status_code}"),
    )


def dry_run_send(destination: Destination, event) -> dict:
    outbound = format_outbound(event, destination)
    _assert_send_url(destination, outbound.url)
    return {
        "dry_run": True,
        "channel": destination.channel,
        "request": public_outbound(outbound),
        "subject": event.subject,
        "text": event.text,
    }


def preview_rule(rule: Rule, snapshot: Snapshot, destination: Optional[Destination]) -> dict:
    from alerting.evaluate import evaluate_rule

    event = evaluate_rule(rule, snapshot)
    payload = {
        "would_fire": event is not None,
        "subject": event.subject if event else None,
        "body": list(event.body_lines) if event else [],
        "details": dict(event.details) if event else {},
        "request": None,
    }
    if event is not None and destination is not None:
        outbound = format_outbound(event, destination)
        payload["request"] = public_outbound(outbound)
    return payload


def _assert_send_url(destination: Destination, url: str) -> None:
    if destination.channel == CHANNEL_TELEGRAM:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname != TELEGRAM_API_HOST:
            raise UnsafeWebhookUrl("telegram URL host is not api.telegram.org")
        if not parsed.path.endswith("/sendMessage"):
            raise UnsafeWebhookUrl("telegram URL path is invalid")
        return
    validate_webhook_url(url)
