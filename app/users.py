from __future__ import annotations

from functools import wraps

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy.exc import IntegrityError

from . import db
from .models import AppSetting, User, UserClientAccess
from .services.settings import SettingsService
from .services.wg_easy import WGEasyError, WGEasyService


bp = Blueprint("users", __name__, url_prefix="/users")


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            return redirect(url_for("clients.index"))
        return view(*args, **kwargs)
    return wrapped


def _wg_easy_service():
    settings = SettingsService(db, AppSetting)
    return WGEasyService(
        base_url=str(settings.get("wg_easy_url")),
        username=str(settings.get("wg_easy_username")),
        password=str(settings.get("wg_easy_password")),
        verify_tls=bool(settings.get("wg_easy_verify_tls")),
    )


def _clients():
    try:
        return _wg_easy_service().get_clients(), None
    except WGEasyError as exc:
        return [], str(exc)


@bp.get("/")
@admin_required
def index():
    users = db.session.execute(
        db.select(User).order_by(User.username.asc())
    ).scalars().all()
    rows = db.session.execute(
        db.select(UserClientAccess).order_by(UserClientAccess.client_name.asc())
    ).scalars().all()
    ownership = {str(row.external_id): row for row in rows}
    clients, error = _clients()
    return render_template(
        "users/index.html",
        users=users,
        clients=clients,
        ownership=ownership,
        error=error,
    )


@bp.post("/new")
@admin_required
def create():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    is_admin = request.form.get("is_admin") == "1"

    if not username or len(username) > 64:
        flash("Username is required and must be at most 64 characters.", "error")
        return redirect(url_for("users.index"))
    if len(password) < 10:
        flash("Password must be at least 10 characters.", "error")
        return redirect(url_for("users.index"))

    user = User(username=username, is_admin=is_admin)
    user.set_password(password)
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("That username already exists.", "error")
        return redirect(url_for("users.index"))

    flash(f"User '{username}' created.", "success")
    return redirect(url_for("users.index"))


@bp.post("/<int:user_id>/update")
@admin_required
def update(user_id):
    user = db.get_or_404(User, user_id)
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    is_admin = request.form.get("is_admin") == "1"

    if not username or len(username) > 64:
        flash("Username is required and must be at most 64 characters.", "error")
        return redirect(url_for("users.index"))
    if user.id == current_user.id and not is_admin:
        flash("You cannot remove your own administrator role.", "error")
        return redirect(url_for("users.index"))
    if password and len(password) < 10:
        flash("New passwords must be at least 10 characters.", "error")
        return redirect(url_for("users.index"))

    user.username = username
    user.is_admin = is_admin
    if password:
        user.set_password(password)

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("That username already exists.", "error")
        return redirect(url_for("users.index"))

    flash(f"User '{username}' updated.", "success")
    return redirect(url_for("users.index"))


@bp.post("/<int:user_id>/delete")
@admin_required
def delete(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("users.index"))

    db.session.query(UserClientAccess).filter_by(user_id=user.id).delete()
    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f"User '{username}' deleted.", "success")
    return redirect(url_for("users.index"))


@bp.post("/ownership")
@admin_required
def ownership():
    external_id = request.form.get("external_id", "").strip()
    client_name = request.form.get("client_name", "").strip()
    raw_user_id = request.form.get("user_id", "").strip()

    if not external_id:
        flash("WG-Easy client ID is required.", "error")
        return redirect(url_for("users.index"))

    row = db.session.execute(
        db.select(UserClientAccess).where(
            UserClientAccess.external_id == external_id
        )
    ).scalar_one_or_none()

    if not raw_user_id:
        if row is not None:
            db.session.delete(row)
            db.session.commit()
        flash(f"Client '{client_name or external_id}' is now unassigned.", "success")
        return redirect(url_for("users.index"))

    try:
        user_id = int(raw_user_id)
    except ValueError:
        flash("Invalid user selection.", "error")
        return redirect(url_for("users.index"))

    user = db.session.get(User, user_id)
    if user is None:
        flash("Selected user no longer exists.", "error")
        return redirect(url_for("users.index"))
    if user.is_admin:
        flash("Client ownership is only needed for self-service users.", "error")
        return redirect(url_for("users.index"))

    if row is None:
        row = UserClientAccess(
            user_id=user.id,
            external_id=external_id,
            client_name=client_name or external_id,
        )
        db.session.add(row)
    else:
        row.user_id = user.id
        row.client_name = client_name or row.client_name

    db.session.commit()
    flash(f"Client '{row.client_name}' assigned to '{user.username}'.", "success")
    return redirect(url_for("users.index"))
