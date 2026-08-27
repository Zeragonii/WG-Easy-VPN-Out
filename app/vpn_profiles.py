from __future__ import annotations
import os
from pathlib import Path
from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy.exc import IntegrityError
from . import db
from .models import VPNProfile
from .services.vpn_profiles import VPNProfileValidationError, safe_filename, validate_config
from .services.vpn_runtime import VPNRuntimeError, VPNRuntimeService
from .services.secrets import encrypt_secret
from .services.routing import RoutingEngine, RoutingEngineError
from .services.profile_intelligence import inspect_profile, display_provider, endpoint_label

bp = Blueprint("vpn_profiles", __name__, url_prefix="/vpn-profiles")


def _resilience_manager():
    from flask import current_app
    return current_app.extensions.get("vpn_resilience")


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

    from flask import current_app
    manager = current_app.extensions.get("on_demand_vpn")
    consumer_counts = manager.consumer_counts() if manager else {}

    runtime_display = {}
    intelligence = {}

    for profile in profiles:
        rt = runtime[profile.id]
        display_state = rt.state

        # List semantics:
        # idle on-demand profiles are Offline, not Failed. A real failure is
        # retained whenever the profile is actually required.
        if (
            profile.enabled
            and profile.connection_policy == "on_demand"
            and manager is not None
        ):
            demand = manager.public_state(profile.id)
            if demand.get("standby") and rt.state in ("disconnected", "failed"):
                display_state = "offline"

        runtime_display[profile.id] = display_state

        try:
            meta = inspect_profile(profile, _read_config(profile))
        except OSError:
            meta = inspect_profile(profile, "")
        intelligence[profile.id] = {
            "raw": meta,
            "provider": display_provider(profile, meta),
            "endpoint": endpoint_label(meta),
        }

    return render_template(
        "vpn_profiles/index.html",
        profiles=profiles,
        runtime=runtime,
        runtime_display=runtime_display,
        consumer_counts=consumer_counts,
        intelligence=intelligence,
    )

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
            connection_policy="always",
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
    from flask import current_app
    manager = current_app.extensions.get("on_demand_vpn")
    on_demand = manager.public_state(profile.id) if manager else None
    consumer_count = manager.consumer_counts().get(profile.id, 0) if manager else 0
    runtime_display_state = runtime.state
    if (
        profile.enabled
        and profile.connection_policy == "on_demand"
        and on_demand
        and on_demand.get("standby")
        and runtime.state in ("disconnected", "failed")
    ):
        runtime_display_state = "standby"

    try:
        intelligence_raw = inspect_profile(profile, _read_config(profile))
    except OSError:
        intelligence_raw = inspect_profile(profile, "")
    intelligence = {
        "raw": intelligence_raw,
        "provider": display_provider(profile, intelligence_raw),
        "endpoint": endpoint_label(intelligence_raw),
    }
    return render_template(
        "vpn_profiles/detail.html",
        profile=profile,
        validation=validation,
        config_error=config_error,
        runtime=runtime,
        runtime_display_state=runtime_display_state,
        on_demand=on_demand,
        consumer_count=consumer_count,
        intelligence=intelligence,
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

        resilience = _resilience_manager()
        if resilience:
            resilience.reset(profile.id, success=False)
        try:
            from .models import RoutingGroup
            RoutingEngine().rebuild(db, RoutingGroup)
        except RoutingEngineError as routing_exc:
            flash(f"VPN connected, but routing rebuild failed: {routing_exc}", "error")
        flash(f"Connecting '{profile.name}'… Automatic connection allowed.", "success")
    return redirect(url_for("vpn_profiles.detail", profile_id=profile.id))

@bp.post("/<int:profile_id>/disconnect")
@login_required
def disconnect(profile_id):
    profile = db.get_or_404(VPNProfile, profile_id)

    manager = current_app.extensions.get("on_demand_vpn")
    demand = manager.public_state(profile.id) if manager else None
    was_required = bool(
        profile.enabled
        and profile.connection_policy == "on_demand"
        and demand
        and demand.get("required")
    )

    VPNRuntimeService().stop(profile)
    profile.enabled = False
    db.session.commit()

    resilience = _resilience_manager()
    if resilience:
        resilience.reset(profile.id, success=False)
    try:
        from .models import RoutingGroup
        RoutingEngine().rebuild(db, RoutingGroup)
    except RoutingEngineError as routing_exc:
        flash(f"VPN disconnected, but routing rebuild failed: {routing_exc}", "error")

    if was_required:
        flash(
            "This On-demand VPN is still required by one or more client assignments. "
            "Disconnecting also disabled automatic connection, so those routing groups "
            "will remain blocked until automatic connection is allowed again.",
            "warning",
        )

    flash(
        f"Disconnected '{profile.name}'. Automatic connection disabled.",
        "success",
    )
    return redirect(url_for("vpn_profiles.detail", profile_id=profile.id))

@bp.get("/<int:profile_id>/runtime")
@login_required
def runtime(profile_id):
    profile = db.get_or_404(VPNProfile, profile_id)
    status = VPNRuntimeService().status(profile, include_probe=True)

    resilience = _resilience_manager()
    retry = resilience.public_state(profile.id) if resilience else {
        "failures": 0,
        "retry_in_seconds": None,
        "last_error": None,
        "gave_up": False,
        "last_success_at": None,
    }

    from flask import current_app
    manager = current_app.extensions.get("on_demand_vpn")
    on_demand = manager.public_state(profile.id) if manager else None

    payload = status.to_dict()
    if (
        profile.enabled
        and profile.connection_policy == "on_demand"
        and on_demand
        and on_demand.get("standby")
        and payload.get("state") in ("disconnected", "failed")
    ):
        payload["state"] = "standby"
        # Historical OpenVPN log errors are not current failures when the
        # profile was intentionally stopped because it has no consumers.
        payload["last_error"] = None

    return jsonify({
        "ok": True,
        **payload,
        "retry": retry,
        "on_demand": on_demand,
    })


@bp.post("/<int:profile_id>/autoconnect")
@login_required
def autoconnect(profile_id):
    profile = db.get_or_404(VPNProfile, profile_id)
    enabled = request.form.get("enabled") == "1"
    profile.enabled = enabled
    db.session.commit()

    resilience = _resilience_manager()
    if resilience:
        resilience.reset(profile.id, success=False)

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
        policy = request.form.get("connection_policy", "always").strip().lower()
        profile.connection_policy = (
            policy if policy in ("always", "on_demand") else "always"
        )
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
    ).scalars().first()
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
