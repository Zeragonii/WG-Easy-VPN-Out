from __future__ import annotations

from datetime import datetime, timezone
import io

from flask import Blueprint, current_app, jsonify, render_template, send_file
from flask_login import login_required

from . import db
from .main import application_version
from .models import ClientAssignment, RoutingGroup, VPNProfile
from .services.diagnostics import build_diagnostics, render_text


bp = Blueprint("diagnostics", __name__, url_prefix="/diagnostics")


def _snapshot():
    return build_diagnostics(
        db,
        VPNProfile,
        RoutingGroup,
        ClientAssignment,
        application_version(),
        app=current_app,
    )


@bp.get("/")
@login_required
def index():
    return render_template("diagnostics/index.html", diagnostics=_snapshot())


@bp.get("/json")
@login_required
def json_export():
    return jsonify(_snapshot())


@bp.get("/download")
@login_required
def download():
    text = render_text(_snapshot()).encode("utf-8")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return send_file(
        io.BytesIO(text),
        mimetype="text/plain; charset=utf-8",
        as_attachment=True,
        download_name=f"vpn-router-diagnostics-{stamp}.txt",
    )
