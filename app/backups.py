from __future__ import annotations

import os

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import login_required

from . import db
from .main import application_version
from .models import ClientAssignment, RoutingGroup, VPNProfile
from .services.backups import BackupError, export_backup, inspect_backup, restore_backup
from .services.routing import RoutingEngine, RoutingEngineError


bp = Blueprint("backups", __name__, url_prefix="/backups")


@bp.get("/")
@login_required
def index():
    return render_template(
        "backups/index.html",
        current_version=application_version(),
    )


@bp.get("/secret")
@login_required
def secret():
    return jsonify({
        "ok": True,
        "secret_key": os.getenv("SECRET_KEY", ""),
    })


@bp.post("/export")
@login_required
def export():
    include_secret = request.form.get("include_secret") == "1"
    acknowledge = request.form.get("acknowledge_secret") == "1"

    if include_secret and not acknowledge:
        flash(
            "Confirm the SECRET_KEY warning before including it in a backup.",
            "error",
        )
        return redirect(url_for("backups.index"))

    try:
        buffer, filename, _ = export_backup(
            db,
            VPNProfile,
            RoutingGroup,
            ClientAssignment,
            application_version(),
            include_secret=include_secret,
        )
    except BackupError as exc:
        flash(str(exc), "error")
        return redirect(url_for("backups.index"))

    return send_file(
        buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name=filename,
    )


@bp.post("/inspect")
@login_required
def inspect():
    upload = request.files.get("backup")
    if not upload or not upload.filename:
        return jsonify({"ok": False, "error": "Select a backup ZIP first."}), 400

    raw = upload.read()
    try:
        manifest, data, included_secret, _ = inspect_backup(raw)
    except BackupError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    current_secret = os.getenv("SECRET_KEY", "")
    return jsonify({
        "ok": True,
        "manifest": manifest,
        "counts": {
            "vpn_profiles": len(data["vpn_profiles"]),
            "routing_groups": len(data["routing_groups"]),
            "client_assignments": len(data["client_assignments"]),
        },
        "secret": {
            "included": included_secret is not None,
            "matches_current": (
                included_secret == current_secret
                if included_secret is not None
                else None
            ),
        },
    })


@bp.post("/restore")
@login_required
def restore():
    upload = request.files.get("backup")
    confirm = request.form.get("confirm_replace") == "1"

    if not confirm:
        flash("Confirm that restore will replace current configuration.", "error")
        return redirect(url_for("backups.index"))

    if not upload or not upload.filename:
        flash("Select a backup ZIP first.", "error")
        return redirect(url_for("backups.index"))

    raw = upload.read()
    try:
        result = restore_backup(
            raw,
            db,
            VPNProfile,
            RoutingGroup,
            ClientAssignment,
        )
    except BackupError as exc:
        flash(str(exc), "error")
        return redirect(url_for("backups.index"))
    except Exception as exc:
        current_app.logger.exception("Backup restore failed.")
        flash(f"Restore failed safely: {exc}", "error")
        return redirect(url_for("backups.index"))

    try:
        RoutingEngine().rebuild(db, RoutingGroup)
    except RoutingEngineError as exc:
        flash(
            f"Configuration restored, but routing rebuild failed: {exc}",
            "error",
        )

    resilience = current_app.extensions.get("vpn_resilience")
    if resilience:
        for profile in db.session.execute(db.select(VPNProfile)).scalars():
            resilience.reset(profile.id, success=False)

    msg = (
        f"Restore complete: {result['profiles']} VPN profile(s), "
        f"{result['groups']} routing group(s), "
        f"{result['assignments']} client assignment(s)."
    )

    if result["included_secret"] and not result["secret_matches"]:
        flash(
            "IMPORTANT: this backup contains a different SECRET_KEY. "
            "Configuration was restored, but encrypted VPN passwords cannot be "
            "used until you set Portainer's SECRET_KEY to the key contained in "
            "the backup and redeploy the container.",
            "error",
        )
    elif not result["included_secret"]:
        flash(
            "Backup did not contain SECRET_KEY. Encrypted VPN credentials will "
            "work only if this instance is using the same SECRET_KEY as the "
            "source instance.",
            "success",
        )

    flash(msg, "success")
    return redirect(url_for("backups.index"))
