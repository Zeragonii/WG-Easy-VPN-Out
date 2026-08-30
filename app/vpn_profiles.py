from __future__ import annotations
import os
from pathlib import Path
from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy.exc import IntegrityError
from . import db
from .models import VPNProfile, RoutingGroup
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


def _provider_options():
    """Return distinct configured provider names for reusable form choices."""
    values = db.session.execute(
        db.select(VPNProfile.provider)
        .where(VPNProfile.provider.is_not(None))
        .distinct()
        .order_by(VPNProfile.provider.asc())
    ).scalars().all()
    return [value.strip() for value in values if value and value.strip()]


def _provider_from_form():
    """Resolve provider dropdown selection, including the Add New sentinel."""
    selected = request.form.get("provider_choice", "").strip()
    if selected == "__new__":
        return request.form.get("provider_new", "").strip()
    return selected



def _display_health_state(profile, runtime, observability):
    """
    Presentation-only VPN health.

    Core runtime semantics intentionally remain transport-focused: for
    WireGuard a recent handshake means the tunnel transport is established.
    The UI additionally requires a successful cached exit-IP probe before it
    presents that transport as fully Connected.
    """
    state = runtime.state
    if state != "connected":
        return state, None

    if observability is None:
        return "verifying", None

    egress = observability.exit_ip_state(profile.id)
    if not egress:
        return "verifying", None

    if egress.get("checking"):
        return "verifying", egress.get("exit_ip")

    # A cached disconnected observation predating the current runtime should
    # not be treated as a failed current tunnel. Wait for a fresh probe.
    if not egress.get("connected"):
        return "verifying", None

    if egress.get("probe_ok") is True and egress.get("exit_ip"):
        return "connected", egress.get("exit_ip")

    if egress.get("probe_ok") is False:
        return "degraded", None

    return "verifying", egress.get("exit_ip")

@bp.get("/")
@login_required
def index():
    profiles = db.session.execute(db.select(VPNProfile).order_by(VPNProfile.name.asc())).scalars().all()
    svc = VPNRuntimeService()
    runtime = {p.id: svc.status(p, include_probe=False) for p in profiles}

    from flask import current_app
    manager = current_app.extensions.get("on_demand_vpn")
    observability = current_app.extensions.get("observability")
    consumer_counts = manager.consumer_counts() if manager else {}
    on_demand_states = (
        {profile.id: manager.public_state(profile.id) for profile in profiles}
        if manager
        else {}
    )

    runtime_display = {}
    intelligence = {}

    for profile in profiles:
        rt = runtime[profile.id]
        display_state, _ = _display_health_state(
            profile,
            rt,
            observability,
        )

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
        from .services.geoip import effective_location
        intelligence[profile.id] = {
            "raw": meta,
            "provider": display_provider(profile, meta),
            "endpoint": endpoint_label(meta),
            "location": effective_location(
                profile,
                meta.region_hint,
            ),
        }

    return render_template(
        "vpn_profiles/index.html",
        profiles=profiles,
        runtime=runtime,
        runtime_display=runtime_display,
        consumer_counts=consumer_counts,
        on_demand_states=on_demand_states,
        intelligence=intelligence,
    )

@bp.get("/runtime-summary")
@login_required
def runtime_summary():
    """
    Lightweight bulk status used by the VPN Clients page.

    Avoids one request per profile so the list remains practical with tens or
    hundreds of configured VPN exits.
    """
    profiles = db.session.execute(
        db.select(VPNProfile).order_by(VPNProfile.id.asc())
    ).scalars().all()

    svc = VPNRuntimeService()
    manager = current_app.extensions.get("on_demand_vpn")
    observability = current_app.extensions.get("observability")
    consumer_counts = manager.consumer_counts() if manager else {}

    rows = []
    for profile in profiles:
        runtime = svc.status(profile, include_probe=False)
        demand = manager.public_state(profile.id) if manager else None

        display_state, verified_exit_ip = _display_health_state(
            profile,
            runtime,
            observability,
        )
        if (
            profile.enabled
            and profile.connection_policy == "on_demand"
            and demand
            and demand.get("standby")
            and runtime.state in ("disconnected", "failed")
        ):
            display_state = "offline"

        rows.append({
            "id": profile.id,
            "state": display_state,
            "verified_exit_ip": verified_exit_ip,
            "connection_policy": profile.connection_policy,
            "enabled": bool(profile.enabled),
            "consumer_count": consumer_counts.get(profile.id, 0),
            "idle_remaining_seconds": (
                demand.get("idle_remaining_seconds")
                if demand
                else None
            ),
            "required": demand.get("required") if demand else None,
        })

    return jsonify({
        "ok": True,
        "profiles": rows,
    })


@bp.route("/new", methods=["GET", "POST"])
@login_required
def new():
    providers = _provider_options()
    supplied = {
        "name": request.form.get("name", ""),
        "provider": _provider_from_form() if request.method == "POST" else "",
        "provider_choice": request.form.get("provider_choice", ""),
        "provider_new": request.form.get("provider_new", ""),
        "connection_policy": request.form.get("connection_policy", "on_demand"),
        "manual_country": request.form.get("manual_country", ""),
        "manual_region": request.form.get("manual_region", ""),
        "manual_city": request.form.get("manual_city", ""),
        "create_routing_group": (
            request.form.get("create_routing_group", "1")
            if request.method == "POST"
            else "1"
        ),
        "username": request.form.get("username", ""),
    }

    def render_new():
        return render_template(
            "vpn_profiles/form.html",
            profile=None,
            supplied=supplied,
            providers=providers,
        )

    if request.method == "POST":
        policy = supplied["connection_policy"].strip().lower()
        if policy not in ("always", "on_demand"):
            policy = "on_demand"
        supplied["connection_policy"] = policy

        if (
            supplied["provider_choice"] == "__new__"
            and not supplied["provider"].strip()
        ):
            flash("Enter a name for the new VPN provider.", "error")
            return render_new()

        upload = request.files.get("config")
        if not supplied["name"].strip():
            flash("Friendly name is required.", "error")
            return render_new()
        if not upload or not upload.filename:
            flash("Select a VPN configuration file.", "error")
            return render_new()

        raw = upload.read()
        if len(raw) > 1024 * 1024:
            flash("Configuration files are limited to 1 MiB.", "error")
            return render_new()

        content = raw.decode("utf-8", errors="replace")
        try:
            filename = safe_filename(upload.filename)
            vpn_type, _ = validate_config(filename, content)
            stored_name = f"{safe_filename(supplied['name'].strip())}-{filename}"
        except VPNProfileValidationError as exc:
            flash(str(exc), "error")
            return render_new()

        path = _profile_dir(vpn_type) / stored_name
        if path.exists():
            flash("A configuration with this stored filename already exists.", "error")
            return render_new()

        profile = VPNProfile(
            name=supplied["name"].strip(),
            provider=supplied["provider"].strip() or None,
            vpn_type=vpn_type,
            config_filename=stored_name,
            username=supplied["username"].strip() or None,
            password=encrypt_secret(request.form.get("password", "") or None),
            enabled=False,
            connection_policy=policy,
            manual_country=supplied["manual_country"].strip() or None,
            manual_region=supplied["manual_region"].strip() or None,
            manual_city=supplied["manual_city"].strip() or None,
        )

        try:
            path.write_text(content, encoding="utf-8")
            db.session.add(profile)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            path.unlink(missing_ok=True)
            flash("A VPN profile with that friendly name already exists.", "error")
            return render_new()

        geoip = current_app.extensions.get("geoip")
        if geoip and geoip.available():
            try:
                from .services.geoip import apply_detected_location
                meta = inspect_profile(profile, content)
                if meta.endpoint_is_ip and meta.endpoint_host:
                    if apply_detected_location(
                        db,
                        profile,
                        geoip,
                        meta.endpoint_host,
                        "endpoint_geoip",
                    ):
                        db.session.commit()
            except Exception as exc:
                db.session.rollback()
                current_app.logger.warning(
                    "Initial GeoIP enrichment failed for profile %s: %s",
                    profile.id,
                    exc,
                )

        routing_group_created = False
        if supplied["create_routing_group"] == "1":
            existing_group = db.session.execute(
                db.select(RoutingGroup).where(RoutingGroup.name == profile.name)
            ).scalar_one_or_none()

            if existing_group is None:
                group = RoutingGroup(
                    name=profile.name,
                    vpn_profile_id=profile.id,
                    fallback_mode="block",
                    dns_mode="inherit",
                    dns_target=None,
                )
                db.session.add(group)
                try:
                    db.session.commit()
                except IntegrityError:
                    db.session.rollback()
                    flash(
                        "VPN profile was created, but its automatic routing "
                        "group could not be created because that group name "
                        "already exists.",
                        "warning",
                    )
                else:
                    routing_group_created = True
                    try:
                        RoutingEngine().rebuild(db, RoutingGroup)
                    except RoutingEngineError as exc:
                        flash(
                            "Routing group was created, but routing rebuild "
                            f"failed: {exc}",
                            "warning",
                        )
            else:
                flash(
                    "VPN profile was created, but the automatic routing group "
                    f"was skipped because '{profile.name}' already exists.",
                    "warning",
                )

        if routing_group_created:
            flash(
                f"VPN profile '{profile.name}' and matching routing group created.",
                "success",
            )
        else:
            flash(f"VPN profile '{profile.name}' created.", "success")

        return redirect(url_for("vpn_profiles.detail", profile_id=profile.id))

    return render_new()


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
    observability = current_app.extensions.get("observability")
    on_demand = manager.public_state(profile.id) if manager else None
    consumer_count = manager.consumer_counts().get(profile.id, 0) if manager else 0
    runtime_display_state, verified_exit_ip = _display_health_state(
        profile,
        runtime,
        observability,
    )
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
    from .services.geoip import effective_location
    intelligence = {
        "raw": intelligence_raw,
        "provider": display_provider(profile, intelligence_raw),
        "endpoint": endpoint_label(intelligence_raw),
        "location": effective_location(
            profile,
            intelligence_raw.region_hint,
        ),
        "geoip_status": (
            current_app.extensions.get("geoip").status()
            if current_app.extensions.get("geoip")
            else {"available": False, "path": None, "error": None}
        ),
    }
    return render_template(
        "vpn_profiles/detail.html",
        profile=profile,
        validation=validation,
        config_error=config_error,
        runtime=runtime,
        runtime_display_state=runtime_display_state,
        verified_exit_ip=verified_exit_ip,
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
    status = VPNRuntimeService().status(profile, include_probe=False)

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
    observability = current_app.extensions.get("observability")
    on_demand = manager.public_state(profile.id) if manager else None

    payload = status.to_dict()
    display_state, verified_exit_ip = _display_health_state(
        profile,
        status,
        observability,
    )
    payload["state"] = display_state
    payload["exit_ip"] = verified_exit_ip
    if (
        profile.enabled
        and profile.connection_policy == "on_demand"
        and on_demand
        and on_demand.get("standby")
        and payload.get("state") in ("disconnected", "failed")
    ):
        payload["state"] = "standby"
        # Historical runtime log errors are not current failures when the
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
    providers = _provider_options()

    if request.method == "POST":
        selected_provider = _provider_from_form()
        supplied = {
            "name": request.form.get("name", ""),
            "provider": selected_provider,
            "provider_choice": request.form.get("provider_choice", ""),
            "provider_new": request.form.get("provider_new", ""),
            "connection_policy": request.form.get(
                "connection_policy",
                profile.connection_policy,
            ),
            "manual_country": request.form.get("manual_country", ""),
            "manual_region": request.form.get("manual_region", ""),
            "manual_city": request.form.get("manual_city", ""),
            "username": request.form.get("username", ""),
        }

        if (
            supplied["provider_choice"] == "__new__"
            and not selected_provider
        ):
            flash("Enter a name for the new VPN provider.", "error")
            return render_template(
                "vpn_profiles/form.html",
                profile=profile,
                supplied=supplied,
                providers=providers,
            )

        profile.name = supplied["name"].strip()
        profile.provider = selected_provider or None
        profile.username = supplied["username"].strip() or None
        profile.manual_country = supplied["manual_country"].strip() or None
        profile.manual_region = supplied["manual_region"].strip() or None
        profile.manual_city = supplied["manual_city"].strip() or None

        policy = supplied["connection_policy"].strip().lower()
        profile.connection_policy = (
            policy if policy in ("always", "on_demand") else "always"
        )

        password = request.form.get("password", "")
        if password:
            profile.password = encrypt_secret(password)

        if not profile.name:
            flash("Friendly name is required.", "error")
            return render_template(
                "vpn_profiles/form.html",
                profile=profile,
                supplied=supplied,
                providers=providers,
            )

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("A VPN profile with that friendly name already exists.", "error")
            return render_template(
                "vpn_profiles/form.html",
                profile=profile,
                supplied=supplied,
                providers=providers,
            )

        flash("VPN profile updated.", "success")
        return redirect(url_for("vpn_profiles.detail", profile_id=profile.id))

    return render_template(
        "vpn_profiles/form.html",
        profile=profile,
        supplied=None,
        providers=providers,
    )


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
