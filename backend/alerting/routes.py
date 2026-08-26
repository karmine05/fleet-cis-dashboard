"""Write-authenticated Alert Manager HTTP API."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from flask import jsonify, request

from alerting.formatters import sample_event
from alerting.models import Destination, Rule
from alerting.runner import dry_run_send, preview_rule
from alerting.ssrf import UnsafeWebhookUrl
from alerting.validate import PayloadError, parse_destination_payload, parse_rule_payload
from alerting import store


def register_alert_routes(app, require_write_auth, error_response):
    def _bad(message, status=400):
        return error_response(message, status)

    def _parse_uuid(raw: str) -> Optional[str]:
        try:
            return str(uuid.UUID(str(raw)))
        except (ValueError, TypeError, AttributeError):
            return None

    def _body():
        payload = request.get_json(silent=True)
        if payload is None:
            raise PayloadError("JSON body is required")
        return payload

    def _public_dest(dest: Destination, created_at=None, updated_at=None):
        return store.destination_to_public(dest, created_at, updated_at)

    def _public_rule(rule: Rule, created_at=None, updated_at=None):
        return store.rule_to_public(rule, created_at, updated_at)

    @app.route("/api/alerts/destinations", methods=["GET"])
    @require_write_auth
    def list_alert_destinations():
        dests = store.list_destinations(include_secrets=True)
        return jsonify({"destinations": [_public_dest(d) for d in dests]})

    @app.route("/api/alerts/destinations", methods=["POST"])
    @require_write_auth
    def create_alert_destination():
        try:
            payload = parse_destination_payload(_body())
            dest = store.insert_destination(payload)
            return jsonify(_public_dest(dest)), 201
        except PayloadError as exc:
            return _bad(str(exc))

    @app.route("/api/alerts/destinations/<destination_id>", methods=["GET"])
    @require_write_auth
    def get_alert_destination(destination_id):
        dest_id = _parse_uuid(destination_id)
        if not dest_id:
            return _bad("invalid destination_id")
        try:
            dest = store.get_destination(dest_id, include_secrets=True)
            return jsonify(_public_dest(dest))
        except store.NotFound:
            return _bad("destination not found", 404)

    @app.route("/api/alerts/destinations/<destination_id>", methods=["PUT"])
    @require_write_auth
    def update_alert_destination(destination_id):
        dest_id = _parse_uuid(destination_id)
        if not dest_id:
            return _bad("invalid destination_id")
        try:
            existing_dest = store.get_destination(dest_id, include_secrets=True)
            existing = {
                "name": existing_dest.name,
                "channel": existing_dest.channel,
                "enabled": existing_dest.enabled,
                "config": dict(existing_dest.config),
            }
            payload = parse_destination_payload(_body(), existing)
            dest = store.update_destination(dest_id, payload)
            return jsonify(_public_dest(dest))
        except store.NotFound:
            return _bad("destination not found", 404)
        except PayloadError as exc:
            return _bad(str(exc))

    @app.route("/api/alerts/destinations/<destination_id>", methods=["DELETE"])
    @require_write_auth
    def delete_alert_destination(destination_id):
        dest_id = _parse_uuid(destination_id)
        if not dest_id:
            return _bad("invalid destination_id")
        try:
            store.delete_destination(dest_id)
            return jsonify({"deleted": True})
        except store.NotFound:
            return _bad("destination not found", 404)
        except store.DestinationInUse as exc:
            return _bad(str(exc), 409)

    @app.route("/api/alerts/destinations/<destination_id>/test", methods=["POST"])
    @require_write_auth
    def test_alert_destination(destination_id):
        dest_id = _parse_uuid(destination_id)
        if not dest_id:
            return _bad("invalid destination_id")
        try:
            dest = store.get_destination(dest_id, include_secrets=True)
        except store.NotFound:
            return _bad("destination not found", 404)
        body = request.get_json(silent=True) or {}
        dry_run = body.get("dry_run", True)
        if not isinstance(dry_run, bool):
            return _bad("dry_run must be a boolean")
        event = sample_event()
        try:
            result = dry_run_send(dest, event)
        except (UnsafeWebhookUrl, ValueError) as exc:
            return _bad(str(exc))
        if dry_run:
            return jsonify(result)
        from alerting.formatters import format_outbound, public_outbound
        from alerting.http import post_json

        outbound = format_outbound(event, dest)
        public = public_outbound(outbound)
        try:
            status_code, text = post_json(
                outbound.method,
                outbound.url,
                dict(outbound.headers),
                dict(outbound.json_body),
            )
        except Exception as exc:
            return jsonify(
                {
                    "dry_run": False,
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "request": public,
                    "subject": event.subject,
                }
            ), 502
        ok = 200 <= int(status_code) < 300
        return jsonify(
            {
                "dry_run": False,
                "ok": ok,
                "http_status": int(status_code),
                "response": text,
                "request": public,
                "subject": event.subject,
            }
        ), (200 if ok else 502)

    @app.route("/api/alerts/rules", methods=["GET"])
    @require_write_auth
    def list_alert_rules():
        rules = store.list_rules()
        return jsonify({"rules": [_public_rule(r) for r in rules]})

    @app.route("/api/alerts/rules", methods=["POST"])
    @require_write_auth
    def create_alert_rule():
        try:
            payload = parse_rule_payload(_body())
            if not store.destination_exists(payload["destination_id"]):
                return _bad("destination not found", 400)
            rule = store.insert_rule(payload)
            return jsonify(_public_rule(rule)), 201
        except PayloadError as exc:
            return _bad(str(exc))
        except store.UnknownDestination:
            return _bad("destination not found", 400)

    @app.route("/api/alerts/rules/<rule_id>", methods=["GET"])
    @require_write_auth
    def get_alert_rule(rule_id):
        rid = _parse_uuid(rule_id)
        if not rid:
            return _bad("invalid rule_id")
        try:
            return jsonify(_public_rule(store.get_rule(rid)))
        except store.NotFound:
            return _bad("rule not found", 404)

    @app.route("/api/alerts/rules/<rule_id>", methods=["PUT"])
    @require_write_auth
    def update_alert_rule(rule_id):
        rid = _parse_uuid(rule_id)
        if not rid:
            return _bad("invalid rule_id")
        try:
            existing_rule = store.get_rule(rid)
            existing = {
                "name": existing_rule.name,
                "kind": existing_rule.kind,
                "enabled": existing_rule.enabled,
                "destination_id": existing_rule.destination_id,
                "config": dict(existing_rule.config),
            }
            payload = parse_rule_payload(_body(), existing)
            if not store.destination_exists(payload["destination_id"]):
                return _bad("destination not found", 400)
            rule = store.update_rule(rid, payload)
            return jsonify(_public_rule(rule))
        except store.NotFound:
            return _bad("rule not found", 404)
        except PayloadError as orig:
            return _bad(str(orig))

    @app.route("/api/alerts/rules/<rule_id>", methods=["DELETE"])
    @require_write_auth
    def delete_alert_rule(rule_id):
        rid = _parse_uuid(rule_id)
        if not rid:
            return _bad("invalid rule_id")
        try:
            store.delete_rule(rid)
            return jsonify({"deleted": True})
        except store.NotFound:
            return _bad("rule not found", 404)

    @app.route("/api/alerts/rules/preview", methods=["POST"])
    @require_write_auth
    def preview_alert_rule():
        try:
            payload = parse_rule_payload(_body())
        except PayloadError as exc:
            return _bad(str(exc))
        dest = None
        try:
            dest = store.get_destination(payload["destination_id"], include_secrets=True)
        except store.NotFound:
            dest = None
        rule = Rule(
            rule_id="00000000-0000-0000-0000-000000000000",
            name=payload["name"],
            kind=payload["kind"],
            enabled=True,
            destination_id=payload["destination_id"],
            config=payload["config"],
        )
        snapshot = store.load_snapshot(datetime.now(timezone.utc))
        return jsonify(preview_rule(rule, snapshot, dest))

    @app.route("/api/alerts/incidents", methods=["GET"])
    @require_write_auth
    def list_alert_incidents():
        return jsonify({"incidents": store.list_incidents()})

    @app.route("/api/alerts/catalog", methods=["GET"])
    @require_write_auth
    def alert_catalog():
        return jsonify(store.load_catalog())

    return app
