from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template
from flask_login import login_required


bp = Blueprint("traffic", __name__, url_prefix="/traffic")


def _snapshot():
    service = current_app.extensions.get("traffic_visibility")
    if service is None:
        return {
            "available": False,
            "error": "Traffic visibility service is unavailable.",
            "sampled_at": None,
            "clients": [],
            "groups": [],
            "vpn_profiles": [],
            "totals": {
                "clients": 0,
                "active_clients": 0,
                "rx_total_display": "—",
                "tx_total_display": "—",
                "rx_rate_display": "—",
                "tx_rate_display": "—",
            },
        }
    return service.snapshot()


@bp.get("/")
@login_required
def index():
    return render_template("traffic.html", traffic=_snapshot())


@bp.get("/api")
@login_required
def api():
    return jsonify({"ok": True, "traffic": _snapshot()})
