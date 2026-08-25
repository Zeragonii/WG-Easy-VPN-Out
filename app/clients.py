from __future__ import annotations

import ipaddress
import os

from flask import Blueprint, jsonify, render_template, request
from flask_login import login_required

from . import db
from .models import AppSetting, ClientAssignment, RoutingGroup
from .services.routing import RoutingEngine, RoutingEngineError
from .services.settings import SettingsService
from .services.wg_easy import WGEasyError, WGEasyService


bp = Blueprint("clients", __name__, url_prefix="/clients")


def _wg_easy_service() -> WGEasyService:
    settings = SettingsService(db, AppSetting)
    return WGEasyService(
        base_url=str(settings.get("wg_easy_url")),
        username=str(settings.get("wg_easy_username")),
        password=str(settings.get("wg_easy_password")),
        verify_tls=bool(settings.get("wg_easy_verify_tls")),
    )


def _groups():
    return db.session.execute(
        db.select(RoutingGroup).order_by(RoutingGroup.name.asc())
    ).scalars().all()


def _assignment_map():
    assignments = db.session.execute(
        db.select(ClientAssignment)
    ).scalars().all()
    return {
        assignment.external_id: assignment
        for assignment in assignments
    }


def _sync_existing_assignments(clients) -> bool:
    """
    Keep persisted assignment metadata aligned with WG-Easy.

    Client identity is the WG-Easy external ID. If its name or IPv4 changes,
    retain the routing group and update only the discovered metadata.
    """
    assignments = _assignment_map()
    changed = False
    routing_changed = False

    for client in clients:
        assignment = assignments.get(str(client.external_id))
        if assignment is None:
            continue

        if assignment.client_name != client.name:
            assignment.client_name = client.name
            changed = True

        try:
            ipv4 = str(ipaddress.IPv4Address(client.ipv4_address))
        except ipaddress.AddressValueError:
            continue

        if assignment.ipv4_address != ipv4:
            assignment.ipv4_address = ipv4
            changed = True
            routing_changed = True

    if changed:
        db.session.commit()

    if routing_changed:
        try:
            RoutingEngine().apply_assignment_sets(db, RoutingGroup)
        except RoutingEngineError:
            # Discovery should continue even if a set refresh fails; a manual
            # routing rebuild remains available in the UI.
            pass

    return routing_changed


def _client_payload(client, assignment):
    return {
        "id": client.external_id,
        "name": client.name,
        "ipv4_address": client.ipv4_address,
        "enabled": client.enabled,
        "connection_state": client.connection_state,
        "latest_handshake_at": client.latest_handshake_at,
        "handshake_age_seconds": client.handshake_age_seconds,
        "transfer_rx": client.transfer_rx,
        "transfer_tx": client.transfer_tx,
        "transfer_rx_display": client.transfer_rx_display,
        "transfer_tx_display": client.transfer_tx_display,
        "routing_group_id": assignment.routing_group_id if assignment else None,
    }


@bp.get("/")
@login_required
def index():
    try:
        clients = _wg_easy_service().get_clients()
        _sync_existing_assignments(clients)
        error = None
    except WGEasyError as exc:
        clients = []
        error = str(exc)

    assignments = _assignment_map()
    groups = _groups()

    return render_template(
        "clients.html",
        clients=clients,
        groups=groups,
        assignments=assignments,
        error=error,
    )


@bp.get("/api")
@login_required
def api():
    try:
        clients = _wg_easy_service().get_clients()
        _sync_existing_assignments(clients)
    except WGEasyError as exc:
        return jsonify({
            "ok": False,
            "error": str(exc),
            "clients": [],
        }), 502

    assignments = _assignment_map()

    return jsonify({
        "ok": True,
        "clients": [
            _client_payload(
                client,
                assignments.get(str(client.external_id)),
            )
            for client in clients
        ],
    })


@bp.post("/<external_id>/routing-group")
@login_required
def set_routing_group(external_id):
    body = request.get_json(silent=True) or {}
    group_id = body.get("routing_group_id")

    try:
        discovered = _wg_easy_service().get_clients()
    except WGEasyError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502

    client = next(
        (item for item in discovered if str(item.external_id) == str(external_id)),
        None,
    )
    if client is None:
        return jsonify({
            "ok": False,
            "error": "WG-Easy client no longer exists.",
        }), 404

    existing = db.session.execute(
        db.select(ClientAssignment).where(
            ClientAssignment.external_id == str(external_id)
        )
    ).scalar_one_or_none()

    # Null/empty means remove explicit policy and use ordinary host routing.
    if group_id in (None, "", "none"):
        if existing is not None:
            db.session.delete(existing)
            db.session.commit()
        try:
            RoutingEngine().apply_assignment_sets(db, RoutingGroup)
        except RoutingEngineError as exc:
            return jsonify({
                "ok": False,
                "error": f"Assignment saved, but nftables update failed: {exc}",
            }), 500

        return jsonify({
            "ok": True,
            "routing_group_id": None,
        })

    try:
        group_id = int(group_id)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "Invalid routing group."}), 400

    group = db.session.get(RoutingGroup, group_id)
    if group is None:
        return jsonify({"ok": False, "error": "Routing group not found."}), 404

    try:
        ipv4 = str(ipaddress.IPv4Address(client.ipv4_address))
    except ipaddress.AddressValueError:
        return jsonify({
            "ok": False,
            "error": "WG-Easy client does not currently have a valid IPv4 address.",
        }), 400

    if existing is None:
        existing = ClientAssignment(
            external_id=str(client.external_id),
            client_name=client.name,
            ipv4_address=ipv4,
            routing_group_id=group.id,
        )
        db.session.add(existing)
    else:
        existing.client_name = client.name
        existing.ipv4_address = ipv4
        existing.routing_group_id = group.id

    db.session.commit()

    try:
        RoutingEngine().apply_assignment_sets(db, RoutingGroup)
    except RoutingEngineError as exc:
        return jsonify({
            "ok": False,
            "error": f"Assignment saved, but nftables update failed: {exc}",
        }), 500

    return jsonify({
        "ok": True,
        "routing_group_id": group.id,
        "routing_group_name": group.name,
    })
