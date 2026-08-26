from __future__ import annotations

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy.exc import IntegrityError

from . import db
from .models import RoutingEvent, RoutingGroup, VPNProfile
from .services.routing import RoutingEngine, RoutingEngineError


bp = Blueprint("routing_groups", __name__, url_prefix="/routing-groups")


def _profiles():
    return db.session.execute(
        db.select(VPNProfile).order_by(VPNProfile.name.asc())
    ).scalars().all()


def _rebuild_with_flash(success_message=None):
    try:
        RoutingEngine().rebuild(db, RoutingGroup)
    except RoutingEngineError as exc:
        flash(f"Routing rebuild failed: {exc}", "error")
        return False
    if success_message:
        flash(success_message, "success")
    return True


@bp.get("/")
@login_required
def index():
    groups = db.session.execute(
        db.select(RoutingGroup).order_by(RoutingGroup.name.asc())
    ).scalars().all()
    engine = RoutingEngine()
    runtime = {group.id: engine.inspect_group(group) for group in groups}
    observability = current_app.extensions.get("observability")

    events = {}
    for group in groups:
        events[group.id] = db.session.execute(
            db.select(RoutingEvent)
            .where(RoutingEvent.routing_group_id == group.id)
            .order_by(RoutingEvent.created_at.desc(), RoutingEvent.id.desc())
            .limit(5)
        ).scalars().all()

    dns = {
        group.id: (
            observability.dns_state(group.vpn_profile_id)
            if observability and group.vpn_profile_id
            else None
        )
        for group in groups
    }

    return render_template(
        "routing_groups/index.html",
        groups=groups,
        runtime=runtime,
        events=events,
        dns=dns,
    )


@bp.route("/new", methods=["GET", "POST"])
@login_required
def new():
    profiles = _profiles()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        target = request.form.get("target", "wan")
        fallback = request.form.get("fallback_mode", "block")

        if not name:
            flash("Routing group name is required.", "error")
            return render_template(
                "routing_groups/form.html",
                group=None,
                profiles=profiles,
            )

        vpn_profile_id = None
        if target != "wan":
            try:
                vpn_profile_id = int(target)
            except ValueError:
                flash("Invalid VPN target.", "error")
                return render_template(
                    "routing_groups/form.html",
                    group=None,
                    profiles=profiles,
                )

            if db.session.get(VPNProfile, vpn_profile_id) is None:
                flash("Selected VPN profile no longer exists.", "error")
                return render_template(
                    "routing_groups/form.html",
                    group=None,
                    profiles=profiles,
                )

        if fallback not in ("block", "wan"):
            fallback = "block"

        group = RoutingGroup(
            name=name,
            vpn_profile_id=vpn_profile_id,
            fallback_mode=fallback,
        )
        db.session.add(group)

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("A routing group with that name already exists.", "error")
            return render_template(
                "routing_groups/form.html",
                group=None,
                profiles=profiles,
            )

        fwmark, table_id, _ = RoutingEngine.allocation(group.id)
        group.fwmark = fwmark
        group.table_id = table_id
        db.session.commit()

        _rebuild_with_flash(f"Routing group '{group.name}' created.")
        return redirect(url_for("routing_groups.index"))

    return render_template(
        "routing_groups/form.html",
        group=None,
        profiles=profiles,
    )


@bp.route("/<int:group_id>/edit", methods=["GET", "POST"])
@login_required
def edit(group_id):
    group = db.get_or_404(RoutingGroup, group_id)
    profiles = _profiles()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        target = request.form.get("target", "wan")
        fallback = request.form.get("fallback_mode", "block")

        if not name:
            flash("Routing group name is required.", "error")
            return render_template(
                "routing_groups/form.html",
                group=group,
                profiles=profiles,
            )

        group.name = name
        group.fallback_mode = fallback if fallback in ("block", "wan") else "block"

        if target == "wan":
            group.vpn_profile_id = None
        else:
            try:
                profile_id = int(target)
            except ValueError:
                flash("Invalid VPN target.", "error")
                return render_template(
                    "routing_groups/form.html",
                    group=group,
                    profiles=profiles,
                )
            if db.session.get(VPNProfile, profile_id) is None:
                flash("Selected VPN profile no longer exists.", "error")
                return render_template(
                    "routing_groups/form.html",
                    group=group,
                    profiles=profiles,
                )
            group.vpn_profile_id = profile_id

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("A routing group with that name already exists.", "error")
            return render_template(
                "routing_groups/form.html",
                group=group,
                profiles=profiles,
            )

        _rebuild_with_flash(f"Routing group '{group.name}' updated.")
        return redirect(url_for("routing_groups.index"))

    return render_template(
        "routing_groups/form.html",
        group=group,
        profiles=profiles,
    )


@bp.post("/<int:group_id>/delete")
@login_required
def delete(group_id):
    group = db.get_or_404(RoutingGroup, group_id)

    from .models import ClientAssignment
    assignment = db.session.execute(
        db.select(ClientAssignment).where(
            ClientAssignment.routing_group_id == group.id
        )
    ).scalar_one_or_none()

    if assignment is not None:
        flash(
            f"Cannot delete '{group.name}' while WG-Easy clients are assigned to it.",
            "error",
        )
        return redirect(url_for("routing_groups.index"))

    name = group.name
    group_id = group.id

    # Remove the group's allocated ip rule/table explicitly. The following
    # rebuild also performs stale-state reconciliation as a second line of
    # defence.
    RoutingEngine().remove_group_state(group_id)

    db.session.query(RoutingEvent).filter_by(routing_group_id=group.id).delete()
    db.session.delete(group)
    db.session.commit()
    _rebuild_with_flash(f"Routing group '{name}' deleted.")
    return redirect(url_for("routing_groups.index"))


@bp.post("/rebuild")
@login_required
def rebuild():
    _rebuild_with_flash("Routing engine rebuilt.")
    return redirect(url_for("routing_groups.index"))


@bp.post("/<int:group_id>/probe-dns")
@login_required
def probe_dns(group_id):
    group = db.get_or_404(RoutingGroup, group_id)
    if not group.vpn_profile_id:
        flash("DNS leak probing applies only to VPN-backed routing groups.", "error")
        return redirect(url_for("routing_groups.index"))

    observability = current_app.extensions.get("observability")
    if observability is None:
        flash("Observability service is unavailable.", "error")
        return redirect(url_for("routing_groups.index"))

    try:
        result = observability.refresh_dns_profile(group.vpn_profile_id)
    except Exception as exc:
        flash(f"DNS probe failed: {exc}", "error")
    else:
        label = (result or {}).get("state", "unknown").replace("_", " ")
        flash(f"DNS probe completed: {label}.", "success")

    return redirect(url_for("routing_groups.index"))
