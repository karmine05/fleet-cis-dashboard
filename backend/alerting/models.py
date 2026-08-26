"""Immutable types for alert evaluation and delivery."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Optional, Tuple

KIND_POLICY_DURATION = "policy_duration"
KIND_SCOPED_DURATION = "scoped_duration"
KIND_COMPLIANCE_THRESHOLD = "compliance_threshold"
KIND_LABEL_SAFEGUARD = "label_safeguard"

KINDS = frozenset(
    {
        KIND_POLICY_DURATION,
        KIND_SCOPED_DURATION,
        KIND_COMPLIANCE_THRESHOLD,
        KIND_LABEL_SAFEGUARD,
    }
)

CHANNEL_SLACK = "slack"
CHANNEL_DISCORD = "discord"
CHANNEL_TELEGRAM = "telegram"
CHANNEL_WEBHOOK = "webhook"

CHANNELS = frozenset(
    {CHANNEL_SLACK, CHANNEL_DISCORD, CHANNEL_TELEGRAM, CHANNEL_WEBHOOK}
)

ACTION_FIRE = "fire"
ACTION_SUPPRESS = "suppress"
ACTION_RESOLVE = "resolve"
ACTION_NONE = "none"

DURATION_HOURS_MIN = 24
DURATION_HOURS_MAX = 24 * 30
DURATION_DAYS_MIN = 1
DURATION_DAYS_MAX = 30

TELEGRAM_API_HOST = "api.telegram.org"


@dataclass(frozen=True)
class Host:
    host_id: int
    hostname: str
    platform: str
    team_name: str
    label_names: frozenset


@dataclass(frozen=True)
class Policy:
    policy_id: int
    policy_name: str
    level: str
    severity: str
    safeguard_ids: Tuple[str, ...]


@dataclass(frozen=True)
class Result:
    policy_id: int
    host_id: int
    status: str
    checked_at: datetime


@dataclass(frozen=True)
class HistoryRow:
    policy_id: int
    host_id: int
    status: str
    checked_at: datetime


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    kind: str
    enabled: bool
    destination_id: str
    config: Mapping[str, Any]
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


@dataclass(frozen=True)
class Destination:
    destination_id: str
    name: str
    channel: str
    enabled: bool
    config: Mapping[str, Any]
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


@dataclass(frozen=True)
class OpenIncident:
    incident_id: str
    rule_id: str
    fingerprint: str
    last_delivery_status: Optional[str] = None


@dataclass(frozen=True)
class AlertEvent:
    rule_id: str
    rule_name: str
    kind: str
    fingerprint: str
    subject: str
    body_lines: Tuple[str, ...]
    details: Mapping[str, Any]
    fired_at: datetime

    @property
    def text(self) -> str:
        if not self.body_lines:
            return self.subject
        return self.subject + "\n\n" + "\n".join(self.body_lines)


@dataclass(frozen=True)
class EvaluationDecision:
    action: str
    rule: Rule
    fingerprint: str
    event: Optional[AlertEvent]


@dataclass(frozen=True)
class OutboundRequest:
    method: str
    url: str
    headers: Mapping[str, str]
    json_body: Mapping[str, Any]


@dataclass(frozen=True)
class Snapshot:
    now: datetime
    hosts: Mapping[int, Host]
    policies: Mapping[int, Policy]
    results: Tuple[Result, ...]
    history_index: Mapping[Tuple[int, int], Tuple[HistoryRow, ...]]
    current_index: Mapping[Tuple[int, int], Result]

    @classmethod
    def build(cls, now, hosts, policies, results, history) -> "Snapshot":
        result_tuple = tuple(results)
        host_map = {h.host_id: h for h in hosts}
        policy_map = {p.policy_id: p for p in policies}
        index: dict = {}
        for row in history:
            index.setdefault((row.policy_id, row.host_id), []).append(row)
        frozen_index = {
            key: tuple(sorted(rows, key=lambda r: r.checked_at))
            for key, rows in index.items()
        }
        current_index = {(r.policy_id, r.host_id): r for r in result_tuple}
        return cls(
            now=now,
            hosts=host_map,
            policies=policy_map,
            results=result_tuple,
            history_index=frozen_index,
            current_index=current_index,
        )
