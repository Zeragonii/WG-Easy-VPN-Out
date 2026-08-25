from __future__ import annotations

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import login_required

from . import db
from .models import AppSetting, User
from .services.settings import DEFINITIONS, SettingsError, SettingsService
from .services.wg_easy import WGEasyError, WGEasyService


bp = Blueprint("settings", __name__, url_prefix="/settings")


def _service():
    return SettingsService(db, AppSetting)


def _reload_runtime_settings():
    for name in ("routing_reconciler", "vpn_resilience", "observability"):
        service = current_app.extensions.get(name)
        if service and hasattr(service, "reload_settings"):
            service.reload_settings()


@bp.route("/", methods=["GET", "POST"])
@login_required
def index():
    settings = _service()
    if request.method == "POST":
        values = {}
        for key, definition in DEFINITIONS.items():
            if definition.value_type == "bool":
                values[key] = "true" if request.form.get(key) == "1" else "false"
            elif definition.secret:
                entered = request.form.get(key, "")
                if entered:
                    values[key] = entered
            else:
                values[key] = request.form.get(key, "")

        try:
            settings.set_many(values)
        except SettingsError as exc:
            db.session.rollback()
            flash(str(exc), "error")
        else:
            _reload_runtime_settings()
            flash("Settings saved. Runtime services reloaded where applicable.", "success")
            return redirect(url_for("settings.index"))

    display = {}
    for section, definitions in settings.sections().items():
        display[section] = []
        for definition in definitions:
            value = "" if definition.secret else settings.raw(definition.key)
            display[section].append({
                "definition": definition,
                "value": value,
                "source": settings.source(definition.key),
                "configured_secret": bool(settings.raw(definition.key)) if definition.secret else False,
            })
    user = db.session.execute(db.select(User).order_by(User.id.asc())).scalars().first()
    return render_template("settings/index.html", sections=display, user=user)


@bp.post("/test-wg-easy")
@login_required
def test_wg_easy():
    settings = _service()
    try:
        clients = WGEasyService(
            base_url=str(settings.get("wg_easy_url")),
            username=str(settings.get("wg_easy_username")),
            password=str(settings.get("wg_easy_password")),
            verify_tls=bool(settings.get("wg_easy_verify_tls")),
        ).get_clients()
    except WGEasyError as exc:
        flash(f"WG-Easy connection failed: {exc}", "error")
    else:
        flash(f"WG-Easy connection successful. API returned {len(clients)} client(s).", "success")
    return redirect(url_for("settings.index"))


@bp.post("/account")
@login_required
def account():
    user = db.session.execute(db.select(User).order_by(User.id.asc())).scalars().first()
    if user is None:
        flash("Administrator account is missing.", "error")
        return redirect(url_for("settings.index"))

    username = request.form.get("username", "").strip()
    password = request.form.get("new_password", "")
    confirm = request.form.get("new_password_confirm", "")
    if not username:
        flash("Username cannot be empty.", "error")
        return redirect(url_for("settings.index"))
    if password and len(password) < 10:
        flash("New password must be at least 10 characters.", "error")
        return redirect(url_for("settings.index"))
    if password != confirm:
        flash("New passwords do not match.", "error")
        return redirect(url_for("settings.index"))

    user.username = username
    if password:
        user.set_password(password)
    db.session.commit()
    flash("Administrator account updated.", "success")
    return redirect(url_for("settings.index"))
