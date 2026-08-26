"""Pure evaluators for the four alert kinds. No DB, no HTTP."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Tuple

from alerting.models import (
    ACTION_FIRE,
    ACTION_NONE,
    ACTION_RESOLVE,
    ACTION_SUPPRESS,
    AlertEvent,
    EvaluationDecision,
    Host,
    KIND_COMPLIANCE_THRESHOLD,
    KIND_LABEL_SAFEGUARD,
    KIND_POLICY_DURATION,
    KIND_SCOPED_DURATION,
    Policy,
    Result,
    Rule,
    Snapshot,
)


def fingerprint_for(rule: Rule) -> str:
    return f"{rule.kind}:{rule.rule_id}"


def evaluate_rule(rule: Rule, snapshot: Snapshot) -> Optional[AlertEvent]:
    """Return an AlertEvent when the rule's condition currently holds."""
    if rule.kind == KIND_POLICY_DURATION:
        return _evaluate_duration(rule, snapshot, scoped=False)
    if rule.kind == KIND_SCOPED_DURATION:
        return _evaluate_duration(rule, snapshot, scoped=True)
    if rule.kind == KIND_COMPLIANCE_THRESHOLD:
        return _evaluate_compliance(rule, snapshot)
    if rule.kind == KIND_LABEL_SAFEGUARD:
        return _evaluate_label_safeguard(rule, snapshot)
    return None


def decide(
    rule: Rule,
    snapshot: Snapshot,
    open_keys: Iterable[Tuple[str, str]],
) -> EvaluationDecision:
    """Map a rule evaluation onto fire / suppress / resolve / none."""
    open_set = set(open_keys)
    fp = fingerprint_for(rule)
    key = (rule.rule_id, fp)
    event = evaluate_rule(rule, snapshot)
    if event is not None:
        if key in open_set:
            return EvaluationDecision(ACTION_SUPPRESS, rule, fp, event)
        return EvaluationDecision(ACTION_FIRE, rule, fp, event)
    if key in open_set:
        return EvaluationDecision(ACTION_RESOLVE, rule, fp, None)
    return EvaluationDecision(ACTION_NONE, rule, fp, None)


def evaluate_rules(
    rules: Sequence[Rule],
    snapshot: Snapshot,
    open_keys: Iterable[Tuple[str, str]],
) -> List[EvaluationDecision]:
    open_set = set(open_keys)
    return [decide(rule, snapshot, open_set) for rule in rules]


def _evaluate_duration(
    rule: Rule, snapshot: Snapshot, scoped: bool
) -> Optional[AlertEvent]:
    cfg = dict(rule.config or {})
    policy_ids = _id_set(cfg.get("policy_ids"))
    duration_hours = int(cfg["duration_hours"])
    min_duration = timedelta(hours=duration_hours)
    platforms = _str_list(cfg.get("platforms")) if scoped else []
    fleets = _str_list(cfg.get("fleets")) if scoped else []
    labels = _str_list(cfg.get("labels")) if scoped else []
    levels = _str_list(cfg.get("levels")) if scoped else []
    severities = _str_list(cfg.get("severities")) if scoped else []

    if not scoped and not policy_ids:
        return None

    failing: List[Tuple[Policy, Host, Result]] = []
    for result in snapshot.results:
        if result.status != "fail":
            continue
        host = snapshot.hosts.get(result.host_id)
        policy = snapshot.policies.get(result.policy_id)
        if host is None or policy is None:
            continue
        if policy_ids and result.policy_id not in policy_ids:
            continue
        if scoped and not _host_in_scope(host, platforms, fleets, labels):
            continue
        if scoped and not _policy_matches_weights(policy, levels, severities):
            continue
        if not _is_continuous_fail(result, snapshot, min_duration):
            continue
        failing.append((policy, host, result))

    if not failing:
        return None

    window_start = snapshot.now - min_duration
    subject = _duration_subject(failing, duration_hours)
    details = _failure_details(
        rule,
        failing,
        snapshot.now,
        window_start,
        scope=_scope_dict(platforms, fleets, labels),
        extra={"duration_hours": duration_hours},
    )
    body = _failure_body(rule, details, duration_label=_hours_label(duration_hours))
    return AlertEvent(
        rule_id=rule.rule_id,
        rule_name=rule.name,
        kind=rule.kind,
        fingerprint=fingerprint_for(rule),
        subject=subject,
        body_lines=tuple(body),
        details=details,
        fired_at=snapshot.now,
    )


def _evaluate_compliance(rule: Rule, snapshot: Snapshot) -> Optional[AlertEvent]:
    cfg = dict(rule.config or {})
    threshold = float(cfg["threshold_percent"])
    duration_days = int(cfg["duration_days"])
    platforms = _str_list(cfg.get("platforms"))
    fleets = _str_list(cfg.get("fleets"))
    labels = _str_list(cfg.get("labels"))
    window_start = snapshot.now - timedelta(days=duration_days)

    samples: List[Tuple[datetime, float]] = []
    for offset in range(duration_days, -1, -1):
        at = snapshot.now - timedelta(days=offset)
        pct = _compliance_at(snapshot, at, platforms, fleets, labels)
        if pct is None or pct >= threshold:
            return None
        samples.append((at, pct))

    current_pct = samples[-1][1]
    host_count = _scoped_host_count(snapshot, platforms, fleets, labels)
    scope = _scope_dict(platforms, fleets, labels)
    scope_label = _scope_subject(scope)
    subject = (
        f"{scope_label} compliance {current_pct:.1f}% below {threshold:g}% "
        f"for {duration_days}d"
    )
    details = {
        "kind": rule.kind,
        "rule_name": rule.name,
        "scope": scope,
        "threshold_percent": threshold,
        "duration_days": duration_days,
        "compliance_percent": round(current_pct, 2),
        "host_count": host_count,
        "samples": [
            {"at": ts.isoformat(), "percent": round(pct, 2)} for ts, pct in samples
        ],
        "window_start": window_start.isoformat(),
        "window_end": snapshot.now.isoformat(),
        "fail_count": 0,
        "policies": [],
    }
    body = [
        f"Rule: {rule.name}",
        f"Kind: {rule.kind}",
        f"Scope: {_scope_line(scope)}",
        f"Threshold: {current_pct:.1f}% < {threshold:g}% for {duration_days}d",
        f"Hosts in scope: {host_count}",
        f"Window: {_fmt_time(window_start)} → {_fmt_time(snapshot.now)}",
    ]
    return AlertEvent(
        rule_id=rule.rule_id,
        rule_name=rule.name,
        kind=rule.kind,
        fingerprint=fingerprint_for(rule),
        subject=subject,
        body_lines=tuple(body),
        details=details,
        fired_at=snapshot.now,
    )


def _evaluate_label_safeguard(rule: Rule, snapshot: Snapshot) -> Optional[AlertEvent]:
    cfg = dict(rule.config or {})
    label = str(cfg.get("label") or "").strip()
    if not label:
        return None
    policy_ids = _id_set(cfg.get("policy_ids"))
    safeguard_ids = {_norm_sid(s) for s in (cfg.get("safeguard_ids") or []) if s}
    if not policy_ids and not safeguard_ids:
        return None

    failing: List[Tuple[Policy, Host, Result]] = []
    for result in snapshot.results:
        if result.status != "fail":
            continue
        host = snapshot.hosts.get(result.host_id)
        policy = snapshot.policies.get(result.policy_id)
        if host is None or policy is None:
            continue
        if not _has_label(host, label):
            continue
        matched = False
        if policy_ids and result.policy_id in policy_ids:
            matched = True
        if not matched and safeguard_ids:
            policy_sids = {_norm_sid(s) for s in policy.safeguard_ids}
            if safeguard_ids.intersection(policy_sids):
                matched = True
        if not matched:
            continue
        failing.append((policy, host, result))

    if not failing:
        return None

    subject = _label_subject(failing, label)
    details = _failure_details(
        rule,
        failing,
        snapshot.now,
        snapshot.now,
        scope=_scope_dict([], [], [label]),
        extra={"label": label, "safeguard_ids": sorted(safeguard_ids)},
    )
    body = _failure_body(rule, details, duration_label="current")
    return AlertEvent(
        rule_id=rule.rule_id,
        rule_name=rule.name,
        kind=rule.kind,
        fingerprint=fingerprint_for(rule),
        subject=subject,
        body_lines=tuple(body),
        details=details,
        fired_at=snapshot.now,
    )


def _is_continuous_fail(
    result: Result, snapshot: Snapshot, min_duration: timedelta
) -> bool:
    fail_since = result.checked_at
    now = snapshot.now
    if fail_since > now:
        return False
    if now - fail_since < min_duration:
        return False
    pair = (result.policy_id, result.host_id)
    for row in snapshot.history_index.get(pair, ()):
        if row.status == "pass" and fail_since <= row.checked_at <= now:
            return False
    return True


def _compliance_at(
    snapshot: Snapshot,
    at: datetime,
    platforms: Sequence[str],
    fleets: Sequence[str],
    labels: Sequence[str],
) -> Optional[float]:
    """Pass rows / (pass+fail) rows in scope at time `at`. Errors excluded."""
    passed = 0
    total = 0
    for result in snapshot.results:
        host = snapshot.hosts.get(result.host_id)
        if host is None:
            continue
        if not _host_in_scope(host, platforms, fleets, labels):
            continue
        status = _status_at(snapshot, result.policy_id, result.host_id, at)
        if status not in ("pass", "fail"):
            continue
        total += 1
        if status == "pass":
            passed += 1
    if total == 0:
        return None
    return 100.0 * passed / total


def _status_at(
    snapshot: Snapshot, policy_id: int, host_id: int, at: datetime
) -> Optional[str]:
    latest_status = None
    latest_ts = None
    pair = (policy_id, host_id)
    for row in snapshot.history_index.get(pair, ()):
        if row.checked_at <= at and (latest_ts is None or row.checked_at >= latest_ts):
            latest_ts = row.checked_at
            latest_status = row.status
    current = snapshot.current_index.get(pair)
    if current is not None and current.checked_at <= at:
        if latest_ts is None or current.checked_at >= latest_ts:
            latest_status = current.status
    return latest_status


def _host_in_scope(
    host: Host,
    platforms: Sequence[str],
    fleets: Sequence[str],
    labels: Sequence[str],
) -> bool:
    if platforms and not _ci_in(host.platform, platforms):
        return False
    if fleets and not _ci_in(host.team_name, fleets):
        return False
    if labels:
        host_labels = {n.lower() for n in host.label_names}
        if not any(label.lower() in host_labels for label in labels):
            return False
    return True


def _has_label(host: Host, label: str) -> bool:
    needle = label.lower()
    return any(name.lower() == needle for name in host.label_names)


def _policy_matches_weights(
    policy: Policy, levels: Sequence[str], severities: Sequence[str]
) -> bool:
    if levels:
        wanted = {_norm_level(item) for item in levels}
        if _norm_level(policy.level) not in wanted:
            return False
    if severities:
        wanted = {item.lower() for item in severities}
        if (policy.severity or "").lower() not in wanted:
            return False
    return True


def _scoped_host_count(
    snapshot: Snapshot,
    platforms: Sequence[str],
    fleets: Sequence[str],
    labels: Sequence[str],
) -> int:
    return sum(
        1
        for host in snapshot.hosts.values()
        if _host_in_scope(host, platforms, fleets, labels)
    )


def _duration_subject(
    failing: Sequence[Tuple[Policy, Host, Result]], duration_hours: int
) -> str:
    hosts = {host.host_id: host for _, host, _ in failing}
    policies = {policy.policy_id: policy for policy, _, _ in failing}
    label = _hours_label(duration_hours)
    if len(hosts) == 1 and len(policies) == 1:
        host = next(iter(hosts.values()))
        policy = next(iter(policies.values()))
        return f"{host.hostname}: {policy.policy_name} failing {label}"
    if len(policies) == 1:
        policy = next(iter(policies.values()))
        return f"{policy.policy_name} failed on {len(hosts)} hosts for {label}"
    return f"{len(policies)} policies failing on {len(hosts)} hosts for {label}"


def _label_subject(failing: Sequence[Tuple[Policy, Host, Result]], label: str) -> str:
    hosts = {host.host_id for _, host, _ in failing}
    policies = {policy.policy_id: policy for policy, _, _ in failing}
    if len(policies) == 1:
        policy = next(iter(policies.values()))
        if len(hosts) == 1:
            host = failing[0][1]
            return f"{label}: {host.hostname} failing {policy.policy_name}"
        return f"{label}: {len(hosts)} hosts failing {policy.policy_name}"
    return f"{label}: {len(hosts)} hosts failing {len(policies)} policies"


def _failure_details(
    rule: Rule,
    failing: Sequence[Tuple[Policy, Host, Result]],
    now: datetime,
    window_start: datetime,
    scope: Mapping[str, Any],
    extra: Optional[Mapping[str, Any]] = None,
) -> dict:
    by_policy: dict = {}
    for policy, host, _result in failing:
        entry = by_policy.setdefault(
            policy.policy_id,
            {
                "policy_id": policy.policy_id,
                "policy_name": policy.policy_name,
                "level": policy.level,
                "severity": policy.severity,
                "safeguard_ids": list(policy.safeguard_ids),
                "host_count": 0,
                "hostnames": [],
            },
        )
        entry["host_count"] += 1
        if host.hostname not in entry["hostnames"] and len(entry["hostnames"]) < 8:
            entry["hostnames"].append(host.hostname)
    host_count = len({host.host_id for _, host, _ in failing})
    details = {
        "kind": rule.kind,
        "rule_name": rule.name,
        "scope": dict(scope),
        "fail_count": len(failing),
        "host_count": host_count,
        "policy_count": len(by_policy),
        "policies": list(by_policy.values()),
        "window_start": window_start.isoformat(),
        "window_end": now.isoformat(),
    }
    if extra:
        details.update(extra)
    return details


def _failure_body(
    rule: Rule, details: Mapping[str, Any], duration_label: str
) -> List[str]:
    lines = [
        f"Rule: {rule.name}",
        f"Kind: {rule.kind}",
        f"Scope: {_scope_line(details.get('scope') or {})}",
        f"Duration: {duration_label}",
        f"Failing policies: {details.get('policy_count', 0)}",
    ]
    for policy in details.get("policies") or []:
        sids = ",".join(policy.get("safeguard_ids") or []) or "—"
        weight = ", ".join(
            part
            for part in (policy.get("level"), policy.get("severity"))
            if part
        ) or "—"
        lines.append(
            f"  - {policy['policy_id']} {policy['policy_name']} "
            f"({weight}) [{sids}] — {policy['host_count']} hosts"
        )
    sample = []
    for policy in details.get("policies") or []:
        for name in policy.get("hostnames") or []:
            if name not in sample:
                sample.append(name)
            if len(sample) >= 8:
                break
        if len(sample) >= 8:
            break
    extra = details.get("host_count", 0) - len(sample)
    host_line = ", ".join(sample) if sample else "—"
    if extra > 0:
        host_line += f", +{extra} more"
    lines.append(f"Hosts: {details.get('host_count', 0)} ({host_line})")
    lines.append(
        f"Window: {_fmt_iso(details.get('window_start'))} → "
        f"{_fmt_iso(details.get('window_end'))}"
    )
    return lines


def _scope_dict(
    platforms: Sequence[str], fleets: Sequence[str], labels: Sequence[str]
) -> dict:
    return {
        "fleets": list(fleets),
        "platforms": list(platforms),
        "labels": list(labels),
    }


def _scope_line(scope: Mapping[str, Any]) -> str:
    parts = []
    fleets = scope.get("fleets") or []
    platforms = scope.get("platforms") or []
    labels = scope.get("labels") or []
    parts.append("Fleet=" + (",".join(fleets) if fleets else "all"))
    parts.append("Platform=" + (",".join(platforms) if platforms else "all"))
    parts.append("Label=" + (",".join(labels) if labels else "all"))
    return "; ".join(parts)


def _scope_subject(scope: Mapping[str, Any]) -> str:
    bits = []
    for key in ("fleets", "platforms", "labels"):
        values = scope.get(key) or []
        if values:
            bits.append("/".join(values))
    return " / ".join(bits) if bits else "Fleet"


def _hours_label(hours: int) -> str:
    if hours % 24 == 0:
        return f"{hours // 24}d"
    return f"{hours}h"


def _id_set(raw: Any) -> set:
    if not raw:
        return set()
    out = set()
    for item in raw:
        out.add(int(item))
    return out


def _str_list(raw: Any) -> List[str]:
    if not raw:
        return []
    return [str(item).strip() for item in raw if str(item).strip()]


def _ci_in(value: str, options: Sequence[str]) -> bool:
    needle = (value or "").lower()
    return any(needle == option.lower() for option in options)


def _norm_level(raw: Any) -> str:
    text = str(raw or "").strip().upper()
    if text.startswith("L") and text[1:].isdigit():
        return text[1:]
    return text


def _norm_sid(raw: Any) -> str:
    text = str(raw or "").strip().upper().replace(" ", "")
    if text.startswith("CIS"):
        text = text[3:]
    return text


def _fmt_time(ts: datetime) -> str:
    aware = ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
    return aware.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _fmt_iso(value: Any) -> str:
    if not value:
        return "—"
    if isinstance(value, datetime):
        return _fmt_time(value)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return _fmt_time(parsed)
    except (TypeError, ValueError):
        return str(value)
