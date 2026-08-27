from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, render_template, request
from flask_login import login_required

from . import db
from .models import AppSetting, ClientAssignment, ClientRouteOverride, RouteOverrideEvent, RoutingGroup
from .services.routing import RoutingEngine, RoutingEngineError
from .services.routing_overrides import active_override_map, expiry_for
from .services.settings import SettingsService
from .services.wg_easy import WGEasyError, WGEasyService


bp = Blueprint("clients", __name__, url_prefix="/clients")

def _on_demand_manager():
    from flask import current_app
    return current_app.extensions.get("on_demand_vpn")



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


def _client_payload(client, assignment, override=None):
    effective_group_id = (
        override.routing_group_id
        if override is not None
        else (assignment.routing_group_id if assignment else None)
    )
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
        "effective_routing_group_id": effective_group_id,
        "override": (
            {
                "routing_group_id": override.routing_group_id,
                "routing_group_name": override.routing_group.name if override.routing_group else None,
                "expires_at": override.expires_at.isoformat() if override.expires_at else None,
                "created_at": override.created_at.isoformat() if override.created_at else None,
            }
            if override is not None
            else None
        ),
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
    overrides = active_override_map(db)
    override_events = db.session.execute(
        db.select(RouteOverrideEvent)
        .order_by(RouteOverrideEvent.created_at.desc(), RouteOverrideEvent.id.desc())
        .limit(12)
    ).scalars().all()

    return render_template(
        "clients.html",
        clients=clients,
        groups=groups,
        assignments=assignments,
        overrides=overrides,
        override_events=override_events,
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
    overrides = active_override_map(db)

    return jsonify({
        "ok": True,
        "clients": [
            _client_payload(
                client,
                assignments.get(str(client.external_id)),
                overrides.get(str(client.external_id)),
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
            manager = _on_demand_manager()
            if manager is not None:
                manager.reconcile_once()
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

    if group.vpn_profile is not None and not group.vpn_profile.enabled:
        return jsonify({
            "ok": False,
            "error": (
                f"Cannot assign this client to '{group.name}' because VPN profile "
                f"'{group.vpn_profile.name}' does not allow automatic connection. "
                "Enable Allow automatic connection first."
            ),
        }), 409

    try:
        ipv4 = str(ipaddress.IPv4Address(client.ipv4_address))
    except ipaddress.AddressValueError:
        return jsonify({
            "ok": False,
            "error": "WG-Easy client does not currently have a valid IPv4 address.",
        }), 400

    if (
        group.vpn_profile is not None
        and group.vpn_profile.enabled
        and group.vpn_profile.connection_policy == "on_demand"
    ):
        manager = _on_demand_manager()
        if manager is not None:
            ready, error = manager.ensure_profile_ready(group.vpn_profile)
            if not ready:
                return jsonify({
                    "ok": False,
                    "error": (
                        "Assignment was not changed because the target VPN "
                        f"could not become ready: {error}"
                    ),
                }), 503

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
        manager = _on_demand_manager()
        if manager is not None:
            manager.reconcile_once()
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

def _refresh_effective_routing():
    RoutingEngine().apply_assignment_sets(db, RoutingGroup)
    manager = _on_demand_manager()
    if manager is not None:
        manager.reconcile_once()


@bp.post("/<external_id>/override")
@login_required
def set_temporary_override(external_id):
    body = request.get_json(silent=True) or {}

    try:
        group_id = int(body.get("routing_group_id"))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "Select a temporary routing group."}), 400

    duration = str(body.get("duration") or "").strip()
    try:
        expires_at = expiry_for(duration)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    group = db.session.get(RoutingGroup, group_id)
    if group is None:
        return jsonify({"ok": False, "error": "Routing group not found."}), 404

    try:
        discovered = _wg_easy_service().get_clients()
    except WGEasyError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502

    client = next(
        (item for item in discovered if str(item.external_id) == str(external_id)),
        None,
    )
    if client is None:
        return jsonify({"ok": False, "error": "WG-Easy client no longer exists."}), 404

    try:
        ipv4 = str(ipaddress.IPv4Address(client.ipv4_address))
    except ipaddress.AddressValueError:
        return jsonify({
            "ok": False,
            "error": "WG-Easy client does not currently have a valid IPv4 address.",
        }), 400

    if group.vpn_profile is not None:
        profile = group.vpn_profile
        if not profile.enabled:
            return jsonify({
                "ok": False,
                "error": (
                    f"VPN profile '{profile.name}' does not allow automatic connection."
                ),
            }), 409

        manager = _on_demand_manager()
        if manager is not None:
            ready, error = manager.ensure_profile_ready(profile)
            if not ready:
                return jsonify({
                    "ok": False,
                    "error": (
                        "Temporary override was not applied because the target VPN "
                        f"could not become ready: {error}"
                    ),
                }), 503

    override = db.session.execute(
        db.select(ClientRouteOverride).where(
            ClientRouteOverride.external_id == str(external_id)
        )
    ).scalar_one_or_none()

    replacing_existing = override is not None

    if override is None:
        override = ClientRouteOverride(
            external_id=str(client.external_id),
            client_name=client.name,
            ipv4_address=ipv4,
            routing_group_id=group.id,
            expires_at=expires_at,
        )
        db.session.add(override)
    else:
        override.client_name = client.name
        override.ipv4_address = ipv4
        override.routing_group_id = group.id
        override.expires_at = expires_at

    db.session.add(RouteOverrideEvent(
        external_id=str(client.external_id),
        client_name=client.name,
        event_type="replaced" if replacing_existing else "started",
        routing_group_id=group.id,
        routing_group_name=group.name,
        detail=(
            (
                "Temporary routing override replaced"
                if replacing_existing
                else "Temporary routing override started"
            )
            + (
                f"; expires {expires_at.isoformat()} UTC"
                if expires_at is not None
                else "; active until cancelled"
            )
            + "."
        ),
    ))
    db.session.commit()

    try:
        _refresh_effective_routing()
    except RoutingEngineError as exc:
        db.session.rollback()
        return jsonify({
            "ok": False,
            "error": f"Override saved, but routing update failed: {exc}",
        }), 500

    return jsonify({
        "ok": True,
        "routing_group_id": group.id,
        "routing_group_name": group.name,
        "expires_at": expires_at.isoformat() if expires_at else None,
    })


@bp.post("/<external_id>/override/cancel")
@login_required
def cancel_temporary_override(external_id):
    override = db.session.execute(
        db.select(ClientRouteOverride).where(
            ClientRouteOverride.external_id == str(external_id)
        )
    ).scalar_one_or_none()

    if override is None:
        return jsonify({"ok": True, "removed": False})

    group = db.session.get(RoutingGroup, int(override.routing_group_id))
    db.session.add(RouteOverrideEvent(
        external_id=str(override.external_id),
        client_name=override.client_name,
        event_type="cancelled",
        routing_group_id=int(override.routing_group_id),
        routing_group_name=group.name if group else None,
        detail="Temporary routing override cancelled; persistent assignment resumed.",
    ))
    db.session.delete(override)
    db.session.commit()

    try:
        _refresh_effective_routing()
    except RoutingEngineError as exc:
        return jsonify({
            "ok": False,
            "error": f"Override removed, but routing update failed: {exc}",
        }), 500

    return jsonify({"ok": True, "removed": True})

