import os

from flask import Blueprint, jsonify, render_template
from flask_login import login_required

from .services.wg_easy import WGEasyError, WGEasyService

bp = Blueprint("clients", __name__, url_prefix="/clients")


def _wg_easy_service() -> WGEasyService:
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


@bp.get("/")
@login_required
def index():
    try:
        clients = _wg_easy_service().get_clients()
        error = None
    except WGEasyError as exc:
        clients = []
        error = str(exc)

    return render_template(
        "clients.html",
        clients=clients,
        error=error,
    )


@bp.get("/api")
@login_required
def api():
    try:
        clients = _wg_easy_service().get_clients()
    except WGEasyError as exc:
        return jsonify({
            "ok": False,
            "error": str(exc),
            "clients": [],
        }), 502

    return jsonify({
        "ok": True,
        "clients": [
            {
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
            }
            for client in clients
        ],
    })
