from __future__ import annotations
import os
from pathlib import Path
from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy.exc import IntegrityError
from . import db
from .models import VPNProfile
from .services.vpn_profiles import VPNProfileValidationError, safe_filename, validate_config
from .services.vpn_runtime import VPNRuntimeError, VPNRuntimeService
from .services.secrets import encrypt_secret
from .services.routing import RoutingEngine, RoutingEngineError

bp = Blueprint("vpn_profiles", __name__, url_prefix="/vpn-profiles")

def _data_root():
    return Path(os.getenv("VPN_ROUTER_DATA_DIR", "/data"))

def _profile_dir(vpn_type):
    path = _data_root() / ("openvpn" if vpn_type == "openvpn" else "wireguard")
    path.mkdir(parents=True, exist_ok=True)
    return path

def _read_config(profile):
    return (_profile_dir(profile.vpn_type) / profile.config_filename).read_text(encoding="utf-8", errors="replace")

@bp.get("/")
@login_required
def index():
    profiles = db.session.execute(db.select(VPNProfile).order_by(VPNProfile.name.asc())).scalars().all()
    svc = VPNRuntimeService()
    runtime = {p.id: svc.status(p, include_probe=False) for p in profiles}
    return render_template("vpn_profiles/index.html", profiles=profiles, runtime=runtime)

@bp.route("/new", methods=["GET", "POST"])
@login_required
def new():
    supplied = {
        "name": request.form.get("name", ""),
        "provider": request.form.get("provider", ""),
        "username": request.form.get("username", ""),
    }
    if request.method == "POST":
        upload = request.files.get("config")
        if not supplied["name"].strip():
            flash("Friendly name is required.", "error")
            return render_template("vpn_profiles/form.html", profile=None, supplied=supplied)
        if not upload or not upload.filename:
            flash("Select a VPN configuration file.", "error")
            return render_template("vpn_profiles/form.html", profile=None, supplied=supplied)
        raw = upload.read()
        if len(raw) > 1024 * 1024:
            flash("Configuration files are limited to 1 MiB.", "error")
            return render_template("vpn_profiles/form.html", profile=None, supplied=supplied)
        content = raw.decode("utf-8", errors="replace")
        try:
            filename = safe_filename(upload.filename)
            vpn_type, _ = validate_config(filename, content)
            stored_name = f"{safe_filename(supplied['name'].strip())}-{filename}"
        except VPNProfileValidationError as exc:
            flash(str(exc), "error")
            return render_template("vpn_profiles/form.html", profile=None, supplied=supplied)

        path = _profile_dir(vpn_type) / stored_name
        if path.exists():
            flash("A configuration with this stored filename already exists.", "error")
            return render_template("vpn_profiles/form.html", profile=None, supplied=supplied)

        profile = VPNProfile(
            name=supplied["name"].strip(),
            provider=supplied["provider"].strip() or None,
            vpn_type=vpn_type,
            config_filename=stored_name,
            username=supplied["username"].strip() or None,
            password=encrypt_secret(request.form.get("password", "") or None),
            enabled=False,
        )
        try:
            path.write_text(content, encoding="utf-8")
            db.session.add(profile)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            path.unlink(missing_ok=True)
            flash("A VPN profile with that friendly name already exists.", "error")
            return render_template("vpn_profiles/form.html", profile=None, supplied=supplied)

        flash(f"VPN profile '{profile.name}' created.", "success")
        return redirect(url_for("vpn_profiles.detail", profile_id=profile.id))

    return render_template("vpn_profiles/form.html", profile=None, supplied=supplied)

@bp.get("/<int:profile_id>")
@login_required
def detail(profile_id):
    profile = db.get_or_404(VPNProfile, profile_id)
    try:
        _, validation = validate_config(profile.config_filename, _read_config(profile), profile.vpn_type)
        config_error = None
    except (OSError, VPNProfileValidationError) as exc:
        validation, config_error = None, str(exc)

    runtime = VPNRuntimeService().status(profile, include_probe=False)
    return render_template(
        "vpn_profiles/detail.html",
        profile=profile,
        validation=validation,
        config_error=config_error,
        runtime=runtime,
    )

@bp.post("/<int:profile_id>/connect")
@login_required
def connect(profile_id):
    profile = db.get_or_404(VPNProfile, profile_id)
    try:
        VPNRuntimeService().start(profile)
    except VPNRuntimeError as exc:
        flash(str(exc), "error")
    else:
        profile.enabled = True
        db.session.commit()
        try:
            from .models import RoutingGroup
            RoutingEngine().rebuild(db, RoutingGroup)
        except RoutingEngineError as routing_exc:
            flash(f"VPN connected, but routing rebuild failed: {routing_exc}", "error")
        flash(f"Connecting '{profile.name}'… Auto-connect enabled.", "success")
    return redirect(url_for("vpn_profiles.detail", profile_id=profile.id))

@bp.post("/<int:profile_id>/disconnect")
@login_required
def disconnect(profile_id):
    profile = db.get_or_404(VPNProfile, profile_id)
    VPNRuntimeService().stop(profile)
    profile.enabled = False
    db.session.commit()
    try:
        from .models import RoutingGroup
        RoutingEngine().rebuild(db, RoutingGroup)
    except RoutingEngineError as routing_exc:
        flash(f"VPN disconnected, but routing rebuild failed: {routing_exc}", "error")
    flash(f"Disconnected '{profile.name}'. Auto-connect disabled.", "success")
    return redirect(url_for("vpn_profiles.detail", profile_id=profile.id))

@bp.get("/<int:profile_id>/runtime")
@login_required
def runtime(profile_id):
    profile = db.get_or_404(VPNProfile, profile_id)
    status = VPNRuntimeService().status(profile, include_probe=True)
    return jsonify({"ok": True, **status.to_dict()})


@bp.post("/<int:profile_id>/autoconnect")
@login_required
def autoconnect(profile_id):
    profile = db.get_or_404(VPNProfile, profile_id)
    enabled = request.form.get("enabled") == "1"
    profile.enabled = enabled
    db.session.commit()
    flash(
        f"Auto-connect {'enabled' if enabled else 'disabled'} for '{profile.name}'.",
        "success",
    )
    return redirect(url_for("vpn_profiles.detail", profile_id=profile.id))


@bp.route("/<int:profile_id>/edit", methods=["GET", "POST"])
@login_required
def edit(profile_id):
    profile = db.get_or_404(VPNProfile, profile_id)
    if request.method == "POST":
        profile.name = request.form.get("name", "").strip()
        profile.provider = request.form.get("provider", "").strip() or None
        profile.username = request.form.get("username", "").strip() or None
        password = request.form.get("password", "")
        if password:
            profile.password = encrypt_secret(password)
        if not profile.name:
            flash("Friendly name is required.", "error")
            return render_template("vpn_profiles/form.html", profile=profile, supplied=None)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("A VPN profile with that friendly name already exists.", "error")
            return render_template("vpn_profiles/form.html", profile=profile, supplied=None)
        flash("VPN profile updated.", "success")
        return redirect(url_for("vpn_profiles.detail", profile_id=profile.id))
    return render_template("vpn_profiles/form.html", profile=profile, supplied=None)

@bp.post("/<int:profile_id>/delete")
@login_required
def delete(profile_id):
    profile = db.get_or_404(VPNProfile, profile_id)

    from .models import RoutingGroup
    in_use = db.session.execute(
        db.select(RoutingGroup).where(RoutingGroup.vpn_profile_id == profile.id)
    ).scalar_one_or_none()
    if in_use is not None:
        flash(
            f"Cannot delete '{profile.name}' while routing group "
            f"'{in_use.name}' uses it.",
            "error",
        )
        return redirect(url_for("vpn_profiles.detail", profile_id=profile.id))

    VPNRuntimeService().stop(profile)
    path = _profile_dir(profile.vpn_type) / profile.config_filename
    name = profile.name
    db.session.delete(profile)
    db.session.commit()
    try:
        path.unlink(missing_ok=True)
    except OSError:
        flash("Profile deleted, but the config file could not be removed.", "error")
    else:
        flash(f"VPN profile '{name}' deleted.", "success")
    return redirect(url_for("vpn_profiles.index"))
