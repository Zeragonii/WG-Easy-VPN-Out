from __future__ import annotations

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from . import db
from .models import AppSetting, User
from .services.settings import SettingsError, SettingsService
from .services.setup import remove_setup_token, validate_setup_token
from .services.wg_easy import WGEasyError, WGEasyService


bp = Blueprint("setup", __name__, url_prefix="/setup")


def _settings():
    return SettingsService(db, AppSetting)


@bp.route("/", methods=["GET", "POST"])
def index():
    settings = _settings()
    if settings.setup_complete():
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        token = request.form.get("setup_token", "")
        if not validate_setup_token(token):
            flash("Invalid setup token. Check the container logs.", "error")
            return render_template("setup/index.html")

        username = request.form.get("admin_username", "").strip()
        password = request.form.get("admin_password", "")
        confirm = request.form.get("admin_password_confirm", "")
        if not username:
            flash("Administrator username is required.", "error")
            return render_template("setup/index.html")
        if len(password) < 10:
            flash("Administrator password must be at least 10 characters.", "error")
            return render_template("setup/index.html")
        if password != confirm:
            flash("Administrator passwords do not match.", "error")
            return render_template("setup/index.html")

        values = {
            "wg_easy_url": request.form.get("wg_easy_url", "").strip(),
            "wg_easy_username": request.form.get("wg_easy_username", "").strip(),
            "wg_easy_password": request.form.get("wg_easy_password", ""),
            "wg_easy_verify_tls": "true" if request.form.get("wg_easy_verify_tls") == "1" else "false",
        }

        try:
            # Validate WG-Easy before committing setup.
            probe = WGEasyService(
                base_url=values["wg_easy_url"],
                username=values["wg_easy_username"],
                password=values["wg_easy_password"],
                verify_tls=values["wg_easy_verify_tls"] == "true",
            )
            clients = probe.get_clients()
            settings.set_many(values)
        except (WGEasyError, SettingsError) as exc:
            db.session.rollback()
            flash(f"WG-Easy connection test failed: {exc}", "error")
            return render_template("setup/index.html")

        user = db.session.execute(db.select(User).order_by(User.id.asc())).scalars().first()
        if user is None:
            user = User(username=username)
            db.session.add(user)
        else:
            user.username = username
        user.set_password(password)
        db.session.commit()

        settings.mark_setup_complete()
        remove_setup_token()
        flash(f"Setup complete. WG-Easy returned {len(clients)} client(s). Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("setup/index.html")
