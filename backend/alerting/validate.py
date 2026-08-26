"""Validate destination and rule payloads. Pure — no Flask, no DB."""

from __future__ import annotations

import re
from typing import Any, Callable, Mapping, Optional, Sequence

from alerting.models import (
    CHANNELS,
    CHANNEL_DISCORD,
    CHANNEL_SLACK,
    CHANNEL_TELEGRAM,
    CHANNEL_WEBHOOK,
    DURATION_DAYS_MAX,
    DURATION_DAYS_MIN,
    DURATION_HOURS_MAX,
    DURATION_HOURS_MIN,
    KIND_COMPLIANCE_THRESHOLD,
    KIND_LABEL_SAFEGUARD,
    KIND_POLICY_DURATION,
    KIND_SCOPED_DURATION,
    KINDS,
)
from alerting.ssrf import UnsafeWebhookUrl, validate_webhook_url

NAME_MAX = 120
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*$")
FORBIDDEN_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "content-type",
        "connection",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "keep-alive",
        "proxy-authorization",
    }
)
SECRET_KEYS = frozenset(
    {"webhook_url", "bot_token", "bearer_token", "header_value", "url"}
)
PLACEHOLDER_SECRET = "***"


class PayloadError(ValueError):
    """Request body failed validation."""


def parse_destination_payload(
    body: Any,
    existing: Optional[Mapping[str, Any]] = None,
    resolver: Optional[Callable[[str], Sequence[str]]] = None,
) -> dict:
    if not isinstance(body, dict):
        raise PayloadError("destination must be a JSON object")
    name = _required_name(body.get("name"), existing)
    channel = _channel(body, existing)
    enabled = _optional_bool(body, "enabled", existing, default=True)
    raw_config = body.get("config")
    if raw_config is None:
        raw_config = dict((existing or {}).get("config") or {})
    if not isinstance(raw_config, dict):
        raise PayloadError("config must be a JSON object")
    previous = dict((existing or {}).get("config") or {})
    config = _channel_config(channel, raw_config, previous, resolver)
    return {"name": name, "channel": channel, "enabled": enabled, "config": config}


def parse_rule_payload(body: Any, existing: Optional[Mapping[str, Any]] = None) -> dict:
    if not isinstance(body, dict):
        raise PayloadError("rule must be a JSON object")
    name = _required_name(body.get("name"), existing)
    kind = _kind(body, existing)
    enabled = _optional_bool(body, "enabled", existing, default=True)
    destination_id = body.get("destination_id")
    if destination_id is None and existing is not None:
        destination_id = existing.get("destination_id")
    destination_id = str(destination_id or "").strip()
    if not destination_id:
        raise PayloadError("destination_id is required")
    raw_config = body.get("config")
    if raw_config is None:
        raw_config = dict((existing or {}).get("config") or {})
    if not isinstance(raw_config, dict):
        raise PayloadError("config must be a JSON object")
    config = _rule_config(kind, raw_config)
    return {
        "name": name,
        "kind": kind,
        "enabled": enabled,
        "destination_id": destination_id,
        "config": config,
    }


def redact_config(channel: str, config: Mapping[str, Any]) -> dict:
    cfg = dict(config or {})
    public = {}
    if channel in (CHANNEL_SLACK, CHANNEL_DISCORD):
        url = str(cfg.get("webhook_url") or "")
        public["webhook_url_set"] = bool(url)
        public["webhook_url"] = _redact_url(url) if url else ""
    elif channel == CHANNEL_TELEGRAM:
        token = str(cfg.get("bot_token") or "")
        public["bot_token_set"] = bool(token)
        public["bot_token"] = _redact_token(token) if token else ""
        public["chat_id"] = str(cfg.get("chat_id") or "")
    elif channel == CHANNEL_WEBHOOK:
        url = str(cfg.get("url") or "")
        public["url_set"] = bool(url)
        public["url"] = _redact_url(url) if url else ""
        public["bearer_token_set"] = bool(cfg.get("bearer_token"))
        header_name = str(cfg.get("header_name") or "")
        public["header_name"] = header_name
        public["header_value_set"] = bool(cfg.get("header_value"))
    return public


def merge_secret(new_value: Any, old_value: Any) -> Any:
    if new_value is None:
        return old_value
    if not isinstance(new_value, str):
        return new_value
    stripped = new_value.strip()
    if stripped == "" or PLACEHOLDER_SECRET in stripped:
        return old_value
    return new_value


def _channel_config(channel, raw, previous, resolver) -> dict:
    if channel in (CHANNEL_SLACK, CHANNEL_DISCORD):
        url = merge_secret(raw.get("webhook_url"), previous.get("webhook_url"))
        if not url:
            raise PayloadError("webhook_url is required")
        try:
            url = validate_webhook_url(str(url), resolver=resolver)
        except UnsafeWebhookUrl as exc:
            raise PayloadError(str(exc)) from exc
        return {"webhook_url": url}
    if channel == CHANNEL_TELEGRAM:
        token = merge_secret(raw.get("bot_token"), previous.get("bot_token"))
        chat_id = raw.get("chat_id", previous.get("chat_id"))
        token = str(token or "").strip()
        chat_id = str(chat_id or "").strip()
        if not token:
            raise PayloadError("bot_token is required")
        if any(ch in token for ch in "/ \n\r\t"):
            raise PayloadError("bot_token is invalid")
        if not chat_id:
            raise PayloadError("chat_id is required")
        return {"bot_token": token, "chat_id": chat_id}
    if channel == CHANNEL_WEBHOOK:
        url = merge_secret(raw.get("url"), previous.get("url"))
        if not url:
            raise PayloadError("url is required")
        try:
            url = validate_webhook_url(str(url), resolver=resolver)
        except UnsafeWebhookUrl as exc:
            raise PayloadError(str(exc)) from exc
        bearer = merge_secret(raw.get("bearer_token"), previous.get("bearer_token"))
        bearer = str(bearer or "").strip()
        header_name = str(raw.get("header_name", previous.get("header_name") or "") or "").strip()
        header_value = merge_secret(raw.get("header_value"), previous.get("header_value"))
        header_value = str(header_value or "")
        if header_name:
            if not HEADER_NAME_RE.match(header_name) or header_name.lower() in FORBIDDEN_HEADERS:
                raise PayloadError("header_name is not allowed")
            if not header_value:
                raise PayloadError("header_value is required when header_name is set")
        elif header_value:
            raise PayloadError("header_name is required when header_value is set")
        config = {"url": url}
        if bearer:
            config["bearer_token"] = bearer
        if header_name:
            config["header_name"] = header_name
            config["header_value"] = header_value
        return config
    raise PayloadError(f"unsupported channel: {channel}")


def _rule_config(kind: str, raw: Mapping[str, Any]) -> dict:
    if kind == KIND_POLICY_DURATION:
        policy_ids = _policy_ids(raw.get("policy_ids"), required=True)
        duration_hours = _duration_hours(raw.get("duration_hours"))
        return {"policy_ids": policy_ids, "duration_hours": duration_hours}
    if kind == KIND_SCOPED_DURATION:
        policy_ids = _policy_ids(raw.get("policy_ids"), required=False)
        duration_hours = _duration_hours(raw.get("duration_hours"))
        config = {
            "policy_ids": policy_ids,
            "duration_hours": duration_hours,
            "platforms": _str_list(raw.get("platforms")),
            "fleets": _str_list(raw.get("fleets")),
            "labels": _str_list(raw.get("labels")),
            "levels": _str_list(raw.get("levels")),
            "severities": _str_list(raw.get("severities")),
        }
        return config
    if kind == KIND_COMPLIANCE_THRESHOLD:
        threshold = _percent(raw.get("threshold_percent"))
        duration_days = _duration_days(raw.get("duration_days"))
        return {
            "threshold_percent": threshold,
            "duration_days": duration_days,
            "platforms": _str_list(raw.get("platforms")),
            "fleets": _str_list(raw.get("fleets")),
            "labels": _str_list(raw.get("labels")),
        }
    if kind == KIND_LABEL_SAFEGUARD:
        label = str(raw.get("label") or "").strip()
        if not label:
            raise PayloadError("label is required")
        policy_ids = _policy_ids(raw.get("policy_ids"), required=False)
        safeguard_ids = _str_list(raw.get("safeguard_ids"))
        if not policy_ids and not safeguard_ids:
            raise PayloadError("policy_ids or safeguard_ids is required")
        return {
            "label": label,
            "policy_ids": policy_ids,
            "safeguard_ids": safeguard_ids,
        }
    raise PayloadError(f"unsupported kind: {kind}")


def _required_name(value, existing) -> str:
    if value is None and existing is not None:
        value = existing.get("name")
    name = str(value or "").strip()
    if not name:
        raise PayloadError("name is required")
    if len(name) > NAME_MAX:
        raise PayloadError(f"name must be at most {NAME_MAX} characters")
    return name


def _channel(body, existing) -> str:
    channel = body.get("channel")
    if channel is None and existing is not None:
        channel = existing.get("channel")
    channel = str(channel or "").strip()
    if channel not in CHANNELS:
        raise PayloadError("channel must be slack, discord, telegram, or webhook")
    if existing is not None and existing.get("channel") and existing["channel"] != channel:
        raise PayloadError("channel cannot be changed")
    return channel


def _kind(body, existing) -> str:
    kind = body.get("kind")
    if kind is None and existing is not None:
        kind = existing.get("kind")
    kind = str(kind or "").strip()
    if kind not in KINDS:
        raise PayloadError("kind is not supported")
    if existing is not None and existing.get("kind") and existing["kind"] != kind:
        raise PayloadError("kind cannot be changed")
    return kind


def _optional_bool(body, key, existing, default) -> bool:
    if key in body:
        value = body[key]
        if not isinstance(value, bool):
            raise PayloadError(f"{key} must be a boolean")
        return value
    if existing is not None and key in existing:
        return bool(existing[key])
    return default


def _policy_ids(raw, required: bool) -> list:
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise PayloadError("policy_ids must be a list")
    out = []
    seen = set()
    for item in raw:
        try:
            pid = int(item)
        except (TypeError, ValueError) as exc:
            raise PayloadError("policy_ids must be integers") from exc
        if pid < 1:
            raise PayloadError("policy_ids must be positive")
        if pid not in seen:
            seen.add(pid)
            out.append(pid)
    if required and not out:
        raise PayloadError("policy_ids is required")
    return out


def _str_list(raw) -> list:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise PayloadError("expected a list of strings")
    out = []
    seen = set()
    for item in raw:
        text = str(item).strip()
        if not text:
            continue
        key = text.lower()
        if key not in seen:
            seen.add(key)
            out.append(text)
    return out


def _duration_hours(raw) -> int:
    hours = _int_field(raw, "duration_hours")
    if hours < DURATION_HOURS_MIN or hours > DURATION_HOURS_MAX:
        raise PayloadError(
            f"duration_hours must be between {DURATION_HOURS_MIN} and {DURATION_HOURS_MAX}"
        )
    return hours


def _duration_days(raw) -> int:
    days = _int_field(raw, "duration_days")
    if days < DURATION_DAYS_MIN or days > DURATION_DAYS_MAX:
        raise PayloadError(
            f"duration_days must be between {DURATION_DAYS_MIN} and {DURATION_DAYS_MAX}"
        )
    return days


def _percent(raw) -> float:
    if raw is None:
        raise PayloadError("threshold_percent is required")
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise PayloadError("threshold_percent must be numeric") from exc
    if value != value or value < 0 or value > 100:
        raise PayloadError("threshold_percent must be between 0 and 100")
    return value


def _int_field(raw, name: str) -> int:
    if raw is None:
        raise PayloadError(f"{name} is required")
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise PayloadError(f"{name} must be an integer") from exc
    if isinstance(raw, bool):
        raise PayloadError(f"{name} must be an integer")
    return value


def _redact_url(url: str) -> str:
    if "://" not in url:
        return PLACEHOLDER_SECRET
    scheme, rest = url.split("://", 1)
    host = rest.split("/", 1)[0]
    return f"{scheme}://{host}/{PLACEHOLDER_SECRET}"


def _redact_token(token: str) -> str:
    if ":" in token:
        left, _right = token.split(":", 1)
        return f"{left}:{PLACEHOLDER_SECRET}"
    return PLACEHOLDER_SECRET
