import os
import shutil
import subprocess
from pathlib import Path

from flask import Blueprint, jsonify, render_template
from flask_login import login_required

from . import db
from .models import ClientAssignment, RoutingGroup, VPNProfile
from .services.routing import RoutingEngine
from .services.vpn_runtime import VPNRuntimeService
from .services.wg_easy import WGEasyError, WGEasyService

bp = Blueprint("main", __name__)


def application_version():
    """
    Return the version baked into the container image.

    APP_VERSION remains an optional override for local development, but normal
    GHCR deployments no longer need to set it in Portainer.
    """
    override = os.getenv("APP_VERSION", "").strip()
    if override:
        return override

    for path in (Path("/app/VERSION"), Path(__file__).resolve().parents[1] / "VERSION"):
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return value

    return "unknown"


def command_exists(name):
    return shutil.which(name) is not None


def wg0_present():
    try:
        result = subprocess.run(
            ["ip", "link", "show", "wg0"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _count_model(model):
    return db.session.execute(
        db.select(db.func.count()).select_from(model)
    ).scalar_one()


def _wg_easy_service():
    verify_tls = os.getenv("WG_EASY_VERIFY_TLS", "true").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }

    return WGEasyService(
        base_url=os.getenv("WG_EASY_URL", "http://127.0.0.1:51821"),
        username=os.getenv("WG_EASY_USERNAME", ""),
        password=os.getenv("WG_EASY_PASSWORD", ""),
        verify_tls=verify_tls,
    )


def _format_uptime(seconds):
    if seconds is None:
        return "—"

    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"

    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"

    hours = minutes // 60
    if hours < 24:
        return f"{hours}h {minutes % 60}m"

    days = hours // 24
    return f"{days}d {hours % 24}h"


def _wg_easy_snapshot():
    try:
        clients = _wg_easy_service().get_clients()
    except WGEasyError as exc:
        return {
            "available": False,
            "error": str(exc),
            "total": None,
            "online": None,
            "recent": None,
            "offline": None,
            "never": None,
        }

    states = {
        "online": 0,
        "recent": 0,
        "offline": 0,
        "never": 0,
    }

    for client in clients:
        state = client.connection_state
        states[state] = states.get(state, 0) + 1

    return {
        "available": True,
        "error": None,
        "total": len(clients),
        **states,
    }


def _vpn_snapshot(profiles):
    runtime = VPNRuntimeService()
    rows = []

    for profile in profiles:
        if profile.vpn_type == "openvpn":
            status = runtime.status(profile, include_probe=True)
            gateway = None
            if status.state == "connected":
                gateway = runtime._route_gateway_from_logs(
                    runtime._log_tail(profile, 80)
                )

            rows.append({
                "id": profile.id,
                "name": profile.name,
                "provider": profile.provider or "—",
                "type": profile.type_label,
                "enabled": bool(profile.enabled),
                "state": status.state,
                "interface": status.interface_name,
                "tunnel_ipv4": status.tunnel_ipv4,
                "gateway": gateway,
                "exit_ip": status.exit_ip,
                "uptime": _format_uptime(status.uptime_seconds),
                "last_error": status.last_error,
            })
        else:
            rows.append({
                "id": profile.id,
                "name": profile.name,
                "provider": profile.provider or "—",
                "type": profile.type_label,
                "enabled": bool(profile.enabled),
                "state": "stored",
                "interface": None,
                "tunnel_ipv4": None,
                "gateway": None,
                "exit_ip": None,
                "uptime": "—",
                "last_error": None,
            })

    return rows


def _routing_snapshot(groups, assignments):
    engine = RoutingEngine()
    counts = {}

    for assignment in assignments:
        counts[assignment.routing_group_id] = (
            counts.get(assignment.routing_group_id, 0) + 1
        )

    rows = []
    for group in groups:
        runtime = engine.inspect_group(group)

        rows.append({
            "id": group.id,
            "name": group.name,
            "configured_exit": group.target_label,
            "effective_exit": runtime.effective_exit,
            "state": runtime.state,
            "detail": runtime.detail,
            "fallback": (
                "WAN fallback"
                if group.fallback_mode == "wan"
                else "Block / kill-switch"
            ),
            "assigned_clients": counts.get(group.id, 0),
            "fwmark": group.mark_hex,
            "table_id": group.table_id,
        })

    return rows


def operational_status():
    profiles = db.session.execute(
        db.select(VPNProfile).order_by(VPNProfile.id.asc())
    ).scalars().all()

    groups = db.session.execute(
        db.select(RoutingGroup).order_by(RoutingGroup.id.asc())
    ).scalars().all()

    assignments = db.session.execute(
        db.select(ClientAssignment).order_by(ClientAssignment.id.asc())
    ).scalars().all()

    wg_easy = _wg_easy_snapshot()
    vpn_rows = _vpn_snapshot(profiles)
    routing_rows = _routing_snapshot(groups, assignments)

    return {
        "vpn_profiles": len(profiles),
        "vpn_enabled": sum(1 for row in vpn_rows if row["enabled"]),
        "vpn_connected": sum(
            1 for row in vpn_rows if row["state"] == "connected"
        ),
        "vpn_connecting": sum(
            1 for row in vpn_rows if row["state"] == "connecting"
        ),
        "vpn_problem": sum(
            1 for row in vpn_rows
            if row["state"] in ("failed", "disconnected", "stale")
            and row["enabled"]
        ),
        "routing_groups": len(groups),
        "client_assignments": len(assignments),
        "wg_easy": wg_easy,
        "vpn_rows": vpn_rows,
        "routing_rows": routing_rows,
    }


def system_status():
    return {
        "version": application_version(),
        "wg_easy_url": os.getenv("WG_EASY_URL", "http://127.0.0.1:51821"),
        "wg0_present": wg0_present(),
        "routing_reconcile_interval": os.getenv(
            "ROUTING_RECONCILE_INTERVAL",
            "3",
        ),
        "retry_base_seconds": os.getenv("VPN_RETRY_BASE_SECONDS", "5"),
        "retry_max_seconds": os.getenv("VPN_RETRY_MAX_SECONDS", "300"),
        "tools": {
            "openvpn": command_exists("openvpn"),
            "wg": command_exists("wg"),
            "nft": command_exists("nft"),
            "ip": command_exists("ip"),
        },
        "operational": operational_status(),
    }


@bp.get("/")
@login_required
def dashboard():
    return render_template("dashboard.html", status=system_status())


@bp.get("/health")
def health():
    status = system_status()
    healthy = all(status["tools"].values())
    return jsonify(
        {"status": "ok" if healthy else "degraded", **status}
    ), 200 if healthy else 503
