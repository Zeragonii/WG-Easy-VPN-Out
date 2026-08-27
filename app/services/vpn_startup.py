from __future__ import annotations

from .vpn_runtime import VPNRuntimeError, VPNRuntimeService


def restore_enabled_profiles(app, db, VPNProfile) -> None:
    """Reconnect enabled supported VPN profiles once at app startup."""
    with app.app_context():
        profiles = db.session.execute(
            db.select(VPNProfile)
            .where(
                VPNProfile.enabled.is_(True),
                VPNProfile.connection_policy == "always",
            )
            .order_by(VPNProfile.id.asc())
        ).scalars().all()

        runtime = VPNRuntimeService()

        for profile in profiles:
            if profile.vpn_type not in ("openvpn", "wireguard"):
                app.logger.warning(
                    "Skipping auto-connect for profile %s (%s): runtime unsupported",
                    profile.id,
                    profile.name,
                )
                continue

            status = runtime.status(profile, include_probe=False)
            if status.state in ("connected", "connecting"):
                continue

            try:
                runtime.start(profile)
            except VPNRuntimeError as exc:
                app.logger.error(
                    "Auto-connect failed for profile %s (%s): %s",
                    profile.id,
                    profile.name,
                    exc,
                )
            else:
                app.logger.info(
                    "Auto-connect started for profile %s (%s)",
                    profile.id,
                    profile.name,
                )
