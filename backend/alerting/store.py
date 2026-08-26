"""Postgres access for destinations, rules, incidents, deliveries, and snapshots."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Sequence
from uuid import UUID

import db
from alerting.models import (
    Destination,
    HistoryRow,
    Host,
    OpenIncident,
    Policy,
    Result,
    Rule,
    Snapshot,
)
from psycopg2 import IntegrityError, extras

from alerting.validate import redact_config

HISTORY_LOOKBACK_DAYS = 31


class NotFound(LookupError):
    pass


class DestinationInUse(Exception):
    pass


class UnknownDestination(Exception):
    pass


def _as_id(value: Any) -> str:
    if isinstance(value, UUID):
        return str(value)
    return str(value)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return _as_utc(value).isoformat()


def list_destinations(include_secrets: bool = False) -> List[Destination]:
    with db.get_db_cursor() as cur:
        cur.execute(
            """
            SELECT destination_id, name, channel, enabled, config, created_at, updated_at
            FROM alert_destinations
            ORDER BY name
            """
        )
        rows = cur.fetchall()
    dests = [_destination_from_row(row) for row in rows]
    if include_secrets:
        return dests
    return [
        Destination(
            destination_id=d.destination_id,
            name=d.name,
            channel=d.channel,
            enabled=d.enabled,
            config=redact_config(d.channel, d.config),
            created_at=d.created_at,
            updated_at=d.updated_at,
        )
        for d in dests
    ]


def get_destination(destination_id: str, include_secrets: bool = False) -> Destination:
    with db.get_db_cursor() as cur:
        cur.execute(
            """
            SELECT destination_id, name, channel, enabled, config, created_at, updated_at
            FROM alert_destinations
            WHERE destination_id = %s
            """,
            (destination_id,),
        )
        row = cur.fetchone()
    if not row:
        raise NotFound("destination not found")
    dest = _destination_from_row(row)
    if include_secrets:
        return dest
    return Destination(
        destination_id=dest.destination_id,
        name=dest.name,
        channel=dest.channel,
        enabled=dest.enabled,
        config=redact_config(dest.channel, dest.config),
        created_at=dest.created_at,
        updated_at=dest.updated_at,
    )


def insert_destination(payload: dict) -> Destination:
    with db.get_db_cursor(commit=True) as cur:
        cur.execute(
            """
            INSERT INTO alert_destinations (name, channel, enabled, config)
            VALUES (%s, %s, %s, %s)
            RETURNING destination_id, name, channel, enabled, config, created_at, updated_at
            """,
            (
                payload["name"],
                payload["channel"],
                payload["enabled"],
                extras.Json(payload["config"]),
            ),
        )
        row = cur.fetchone()
    return _destination_from_row(row)


def update_destination(destination_id: str, payload: dict) -> Destination:
    with db.get_db_cursor(commit=True) as cur:
        cur.execute(
            """
            UPDATE alert_destinations
            SET name = %s, enabled = %s, config = %s, updated_at = NOW()
            WHERE destination_id = %s
            RETURNING destination_id, name, channel, enabled, config, created_at, updated_at
            """,
            (
                payload["name"],
                payload["enabled"],
                extras.Json(payload["config"]),
                destination_id,
            ),
        )
        row = cur.fetchone()
    if not row:
        raise NotFound("destination not found")
    return _destination_from_row(row)


def delete_destination(destination_id: str) -> None:
    with db.get_db_cursor(commit=True) as cur:
        cur.execute(
            "SELECT 1 FROM alert_rules WHERE destination_id = %s LIMIT 1",
            (destination_id,),
        )
        if cur.fetchone():
            raise DestinationInUse("destination is referenced by one or more rules")
        cur.execute(
            "DELETE FROM alert_destinations WHERE destination_id = %s RETURNING destination_id",
            (destination_id,),
        )
        if not cur.fetchone():
            raise NotFound("destination not found")


def list_rules() -> List[Rule]:
    with db.get_db_cursor() as cur:
        cur.execute(
            """
            SELECT rule_id, name, kind, enabled, destination_id, config, created_at, updated_at
            FROM alert_rules
            ORDER BY name
            """
        )
        rows = cur.fetchall()
    return [_rule_from_row(row) for row in rows]


def get_rule(rule_id: str) -> Rule:
    with db.get_db_cursor() as cur:
        cur.execute(
            """
            SELECT rule_id, name, kind, enabled, destination_id, config, created_at, updated_at
            FROM alert_rules
            WHERE rule_id = %s
            """,
            (rule_id,),
        )
        row = cur.fetchone()
    if not row:
        raise NotFound("rule not found")
    return _rule_from_row(row)


def insert_rule(payload: dict) -> Rule:
    try:
        with db.get_db_cursor(commit=True) as cur:
            cur.execute(
                """
                INSERT INTO alert_rules (name, kind, enabled, destination_id, config)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING rule_id, name, kind, enabled, destination_id, config, created_at, updated_at
                """,
                (
                    payload["name"],
                    payload["kind"],
                    payload["enabled"],
                    payload["destination_id"],
                    extras.Json(payload["config"]),
                ),
            )
            row = cur.fetchone()
        return _rule_from_row(row)
    except IntegrityError as exc:
        raise UnknownDestination("destination not found") from exc


def update_rule(rule_id: str, payload: dict) -> Rule:
    with db.get_db_cursor(commit=True) as cur:
        cur.execute(
            """
            UPDATE alert_rules
            SET name = %s, enabled = %s, destination_id = %s, config = %s, updated_at = NOW()
            WHERE rule_id = %s
            RETURNING rule_id, name, kind, enabled, destination_id, config, created_at, updated_at
            """,
            (
                payload["name"],
                payload["enabled"],
                payload["destination_id"],
                extras.Json(payload["config"]),
                rule_id,
            ),
        )
        row = cur.fetchone()
    if not row:
        raise NotFound("rule not found")
    return _rule_from_row(row)


def delete_rule(rule_id: str) -> None:
    with db.get_db_cursor(commit=True) as cur:
        cur.execute(
            "DELETE FROM alert_rules WHERE rule_id = %s RETURNING rule_id",
            (rule_id,),
        )
        if not cur.fetchone():
            raise NotFound("rule not found")


def destination_exists(destination_id: str) -> bool:
    with db.get_db_cursor() as cur:
        cur.execute(
            "SELECT 1 FROM alert_destinations WHERE destination_id = %s",
            (destination_id,),
        )
        return cur.fetchone() is not None


def list_open_incidents() -> List[OpenIncident]:
    with db.get_db_cursor() as cur:
        cur.execute(
            """
            SELECT i.incident_id, i.rule_id, i.fingerprint,
                   (
                       SELECT d.status
                       FROM alert_deliveries d
                       WHERE d.incident_id = i.incident_id
                       ORDER BY d.attempted_at DESC
                       LIMIT 1
                   ) AS last_delivery_status
            FROM alert_incidents i
            WHERE i.status = 'open'
            """
        )
        rows = cur.fetchall()
    return [
        OpenIncident(
            incident_id=_as_id(row["incident_id"]),
            rule_id=_as_id(row["rule_id"]),
            fingerprint=row["fingerprint"],
            last_delivery_status=row.get("last_delivery_status"),
        )
        for row in rows
    ]


def list_incidents(limit: int = 50) -> List[dict]:
    with db.get_db_cursor() as cur:
        cur.execute(
            """
            SELECT incident_id, rule_id, fingerprint, status, subject, details,
                   fired_at, resolved_at, last_evaluated_at
            FROM alert_incidents
            ORDER BY fired_at DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
    return [
        {
            "incident_id": _as_id(row["incident_id"]),
            "rule_id": _as_id(row["rule_id"]),
            "fingerprint": row["fingerprint"],
            "status": row["status"],
            "subject": row["subject"],
            "details": row["details"] or {},
            "fired_at": _iso(row["fired_at"]),
            "resolved_at": _iso(row["resolved_at"]),
            "last_evaluated_at": _iso(row["last_evaluated_at"]),
        }
        for row in rows
    ]


def open_incident(rule_id: str, fingerprint: str, subject: str, details: dict, now: datetime) -> str:
    with db.get_db_cursor(commit=True) as cur:
        cur.execute(
            """
            INSERT INTO alert_incidents (
                rule_id, fingerprint, status, subject, details, fired_at, last_evaluated_at
            )
            VALUES (%s, %s, 'open', %s, %s, %s, %s)
            RETURNING incident_id
            """,
            (rule_id, fingerprint, subject, extras.Json(details), now, now),
        )
        return _as_id(cur.fetchone()["incident_id"])


def resolve_incident(incident_id: str, now: datetime) -> None:
    with db.get_db_cursor(commit=True) as cur:
        cur.execute(
            """
            UPDATE alert_incidents
            SET status = 'resolved', resolved_at = %s, last_evaluated_at = %s
            WHERE incident_id = %s AND status = 'open'
            """,
            (now, now, incident_id),
        )


def touch_incident(incident_id: str, now: datetime) -> None:
    with db.get_db_cursor(commit=True) as cur:
        cur.execute(
            """
            UPDATE alert_incidents
            SET last_evaluated_at = %s
            WHERE incident_id = %s
            """,
            (now, incident_id),
        )


def record_delivery(
    incident_id: str,
    destination_id: Optional[str],
    status: str,
    request_url: str,
    request_body: Any,
    http_status: Optional[int] = None,
    error_message: Optional[str] = None,
) -> None:
    with db.get_db_cursor(commit=True) as cur:
        cur.execute(
            """
            INSERT INTO alert_deliveries (
                incident_id, destination_id, status, http_status,
                error_message, request_url, request_body
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                incident_id,
                destination_id,
                status,
                http_status,
                error_message,
                request_url,
                extras.Json(request_body if request_body is not None else {}),
            ),
        )


def load_catalog() -> dict:
    with db.get_db_cursor() as cur:
        cur.execute(
            """
            SELECT policy_id, policy_name, level, severity, cis_safeguard_ids
            FROM cis_policies
            ORDER BY policy_name
            """
        )
        policies = [
            {
                "policy_id": row["policy_id"],
                "policy_name": row["policy_name"],
                "level": row["level"] or "",
                "severity": row["severity"] or "",
                "safeguard_ids": list(row["cis_safeguard_ids"] or []),
            }
            for row in cur.fetchall()
        ]
        cur.execute(
            "SELECT DISTINCT team_name FROM fleet_hosts WHERE team_name IS NOT NULL ORDER BY team_name"
        )
        fleets = [row["team_name"] for row in cur.fetchall()]
        cur.execute(
            "SELECT DISTINCT platform FROM fleet_hosts WHERE platform IS NOT NULL ORDER BY platform"
        )
        platforms = [row["platform"] for row in cur.fetchall()]
        cur.execute("SELECT label_name FROM fleet_labels ORDER BY label_name")
        labels = [row["label_name"] for row in cur.fetchall()]
    return {
        "policies": policies,
        "fleets": fleets,
        "platforms": platforms,
        "labels": labels,
        "levels": ["L1", "L2"],
        "severities": ["Critical", "Medium"],
    }


def load_snapshot(now: datetime) -> Snapshot:
    lookback = now - timedelta(days=HISTORY_LOOKBACK_DAYS)
    with db.get_db_cursor() as cur:
        cur.execute(
            """
            SELECT host_id, hostname, platform, team_name
            FROM fleet_hosts
            """
        )
        host_rows = cur.fetchall()
        cur.execute(
            """
            SELECT hl.host_id, fl.label_name
            FROM host_labels hl
            JOIN fleet_labels fl ON fl.label_id = hl.label_id
            """
        )
        label_rows = cur.fetchall()
        cur.execute(
            """
            SELECT policy_id, policy_name, level, severity, cis_safeguard_ids
            FROM cis_policies
            """
        )
        policy_rows = cur.fetchall()
        cur.execute(
            """
            SELECT policy_id, host_id, status, checked_at
            FROM policy_results
            """
        )
        result_rows = cur.fetchall()
        cur.execute(
            """
            SELECT policy_id, host_id, status, checked_at
            FROM policy_results_history
            WHERE checked_at >= %s
            """,
            (lookback,),
        )
        history_rows = cur.fetchall()

    labels_by_host: dict = {}
    for row in label_rows:
        labels_by_host.setdefault(row["host_id"], set()).add(row["label_name"])

    hosts = [
        Host(
            host_id=row["host_id"],
            hostname=row["hostname"] or str(row["host_id"]),
            platform=row["platform"] or "",
            team_name=row["team_name"] or "",
            label_names=frozenset(labels_by_host.get(row["host_id"], ())),
        )
        for row in host_rows
    ]
    policies = [
        Policy(
            policy_id=row["policy_id"],
            policy_name=row["policy_name"] or str(row["policy_id"]),
            level=row["level"] or "",
            severity=row["severity"] or "",
            safeguard_ids=tuple(row["cis_safeguard_ids"] or ()),
        )
        for row in policy_rows
    ]
    results = [
        Result(
            policy_id=row["policy_id"],
            host_id=row["host_id"],
            status=row["status"],
            checked_at=_as_utc(row["checked_at"]),
        )
        for row in result_rows
    ]
    history = [
        HistoryRow(
            policy_id=row["policy_id"],
            host_id=row["host_id"],
            status=row["status"],
            checked_at=_as_utc(row["checked_at"]),
        )
        for row in history_rows
    ]
    return Snapshot.build(now, hosts, policies, results, history)


def destination_to_public(dest: Destination, created_at=None, updated_at=None) -> dict:
    already_redacted = (
        "webhook_url_set" in dest.config
        or "url_set" in dest.config
        or "bot_token_set" in dest.config
    )
    config = dict(dest.config) if already_redacted else redact_config(dest.channel, dest.config)
    return {
        "destination_id": dest.destination_id,
        "name": dest.name,
        "channel": dest.channel,
        "enabled": dest.enabled,
        "config": config,
        "created_at": dest.created_at or (
            _iso(created_at) if isinstance(created_at, datetime) else created_at
        ),
        "updated_at": dest.updated_at or (
            _iso(updated_at) if isinstance(updated_at, datetime) else updated_at
        ),
    }


def rule_to_public(rule: Rule, created_at=None, updated_at=None) -> dict:
    return {
        "rule_id": rule.rule_id,
        "name": rule.name,
        "kind": rule.kind,
        "enabled": rule.enabled,
        "destination_id": rule.destination_id,
        "config": dict(rule.config),
        "created_at": rule.created_at or (
            _iso(created_at) if isinstance(created_at, datetime) else created_at
        ),
        "updated_at": rule.updated_at or (
            _iso(updated_at) if isinstance(updated_at, datetime) else updated_at
        ),
    }


def _destination_from_row(row) -> Destination:
    return Destination(
        destination_id=_as_id(row["destination_id"]),
        name=row["name"],
        channel=row["channel"],
        enabled=bool(row["enabled"]),
        config=dict(row["config"] or {}),
        created_at=_iso(row.get("created_at")),
        updated_at=_iso(row.get("updated_at")),
    )


def _rule_from_row(row) -> Rule:
    return Rule(
        rule_id=_as_id(row["rule_id"]),
        name=row["name"],
        kind=row["kind"],
        enabled=bool(row["enabled"]),
        destination_id=_as_id(row["destination_id"]),
        config=dict(row["config"] or {}),
        created_at=_iso(row.get("created_at")),
        updated_at=_iso(row.get("updated_at")),
    )
