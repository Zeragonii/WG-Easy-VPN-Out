import os
import shutil
import subprocess

from flask import Blueprint, jsonify, render_template
from flask_login import login_required

from . import db
from .models import ClientAssignment, RoutingGroup, VPNProfile
from .services.vpn_runtime import VPNRuntimeService
from .services.wg_easy import WGEasyError, WGEasyService

bp = Blueprint("main", __name__)


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


def _wg_easy_client_count():
    try:
        return len(_wg_easy_service().get_clients()), None
    except WGEasyError as exc:
        return None, str(exc)


def operational_status():
    profiles = db.session.execute(
        db.select(VPNProfile).order_by(VPNProfile.id.asc())
    ).scalars().all()

    wg_easy_total_clients, wg_easy_error = _wg_easy_client_count()

    runtime = VPNRuntimeService()
    connected = 0
    connecting = 0
    enabled = 0

    for profile in profiles:
        if profile.enabled:
            enabled += 1

        if profile.vpn_type != "openvpn":
            continue

        status = runtime.status(profile, include_probe=False)
        if status.state == "connected":
            connected += 1
        elif status.state == "connecting":
            connecting += 1

    return {
        "vpn_profiles": len(profiles),
        "vpn_enabled": enabled,
        "vpn_connected": connected,
        "vpn_connecting": connecting,
        "routing_groups": _count_model(RoutingGroup),
        "client_assignments": _count_model(ClientAssignment),
        "wg_easy_total_clients": wg_easy_total_clients,
        "wg_easy_error": wg_easy_error,
    }


def system_status():
    return {
        "version": os.getenv("APP_VERSION", "0.6.2"),
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
