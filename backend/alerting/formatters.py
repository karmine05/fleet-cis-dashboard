"""Channel adapters. Each returns method/url/headers/json for an injectable transport."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from alerting.models import (
    CHANNEL_DISCORD,
    CHANNEL_SLACK,
    CHANNEL_TELEGRAM,
    CHANNEL_WEBHOOK,
    TELEGRAM_API_HOST,
    AlertEvent,
    Destination,
    OutboundRequest,
)

DISCORD_EMBED_COLOR = 0xE53935
JSON_CONTENT_TYPE = {"Content-Type": "application/json"}


def format_outbound(event: AlertEvent, destination: Destination) -> OutboundRequest:
    channel = destination.channel
    if channel == CHANNEL_SLACK:
        return format_slack(event, destination)
    if channel == CHANNEL_DISCORD:
        return format_discord(event, destination)
    if channel == CHANNEL_TELEGRAM:
        return format_telegram(event, destination)
    if channel == CHANNEL_WEBHOOK:
        return format_webhook(event, destination)
    raise ValueError(f"unsupported channel: {channel}")


def format_slack(event: AlertEvent, destination: Destination) -> OutboundRequest:
    url = str(destination.config.get("webhook_url") or "")
    return OutboundRequest(
        method="POST",
        url=url,
        headers=dict(JSON_CONTENT_TYPE),
        json_body={"text": event.text},
    )


def format_discord(event: AlertEvent, destination: Destination) -> OutboundRequest:
    url = str(destination.config.get("webhook_url") or "")
    fields = _discord_fields(event)
    embed = {
        "title": event.subject,
        "description": "\n".join(event.body_lines)[:4000],
        "color": DISCORD_EMBED_COLOR,
        "fields": fields,
        "timestamp": _iso(event.fired_at),
    }
    return OutboundRequest(
        method="POST",
        url=url,
        headers=dict(JSON_CONTENT_TYPE),
        json_body={
            "content": event.subject,
            "embeds": [embed],
        },
    )


def format_telegram(event: AlertEvent, destination: Destination) -> OutboundRequest:
    token = str(destination.config.get("bot_token") or "")
    chat_id = str(destination.config.get("chat_id") or "")
    url = f"https://{TELEGRAM_API_HOST}/bot{token}/sendMessage"
    return OutboundRequest(
        method="POST",
        url=url,
        headers=dict(JSON_CONTENT_TYPE),
        json_body={
            "chat_id": chat_id,
            "text": event.text,
        },
    )


def format_webhook(event: AlertEvent, destination: Destination) -> OutboundRequest:
    cfg = destination.config
    url = str(cfg.get("url") or "")
    headers = dict(JSON_CONTENT_TYPE)
    bearer = str(cfg.get("bearer_token") or "").strip()
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    header_name = str(cfg.get("header_name") or "").strip()
    header_value = str(cfg.get("header_value") or "")
    if header_name:
        headers[header_name] = header_value
    body = {
        "subject": event.subject,
        "text": event.text,
        "rule": {
            "id": event.rule_id,
            "name": event.rule_name,
            "kind": event.kind,
        },
        "details": dict(event.details),
        "fired_at": _iso(event.fired_at),
    }
    return OutboundRequest(
        method="POST",
        url=url,
        headers=headers,
        json_body=body,
    )


def sample_event(now: datetime | None = None) -> AlertEvent:
    """Fixed-shape event for destination test-send / dry-run."""
    fired = now or datetime.now(timezone.utc)
    subject = "Test: CIS FileVault failed on 3 hosts for 24h"
    body = (
        "Rule: Test send",
        "Kind: policy_duration",
        "Scope: Fleet=all; Platform=all; Label=all",
        "Duration: 24h",
        "Failing policies: 1",
        "  - 101 CIS 2.6.6 Ensure FileVault Is Enabled (L1, Critical) [3.6] — 3 hosts",
        "Hosts: 3 (host-a, host-b, host-c)",
        f"Window: {_iso(fired)} → {_iso(fired)}",
    )
    return AlertEvent(
        rule_id="00000000-0000-0000-0000-000000000000",
        rule_name="Test send",
        kind="policy_duration",
        fingerprint="test",
        subject=subject,
        body_lines=body,
        details={
            "kind": "policy_duration",
            "rule_name": "Test send",
            "host_count": 3,
            "fail_count": 3,
            "policy_count": 1,
        },
        fired_at=fired,
    )


def _discord_fields(event: AlertEvent) -> list:
    details = event.details or {}
    fields = [
        {"name": "Rule", "value": event.rule_name, "inline": True},
        {"name": "Kind", "value": event.kind, "inline": True},
    ]
    host_count = details.get("host_count")
    if host_count is not None:
        fields.append(
            {"name": "Hosts", "value": str(host_count), "inline": True}
        )
    if details.get("compliance_percent") is not None:
        fields.append(
            {
                "name": "Compliance",
                "value": f"{details['compliance_percent']}%",
                "inline": True,
            }
        )
    return fields


def _iso(ts: datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).isoformat()


def public_outbound(outbound: OutboundRequest) -> Mapping[str, Any]:
    """API response shape: same payload, secrets stripped from URL/headers."""
    headers = {}
    for key, value in (outbound.headers or {}).items():
        if key.lower() == "content-type":
            headers[key] = value
        else:
            headers[key] = "***"
    return {
        "method": outbound.method,
        "url": _redact_url(outbound.url),
        "headers": headers,
        "json": dict(outbound.json_body),
    }


def _redact_url(url: str) -> str:
    marker = f"https://{TELEGRAM_API_HOST}/bot"
    if url.startswith(marker) and url.endswith("/sendMessage"):
        return f"{marker}***/sendMessage"
    if "://" not in url:
        return "***"
    scheme, rest = url.split("://", 1)
    host = rest.split("/", 1)[0]
    return f"{scheme}://{host}/***"
