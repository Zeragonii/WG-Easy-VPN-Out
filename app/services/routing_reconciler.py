from __future__ import annotations

import os
import threading

from .routing import RoutingEngine, RoutingEngineError


class RoutingReconciler:
    """Rebuild routing when VPN-backed group tunnel state materially changes."""

    def __init__(self, app, db, RoutingGroup, interval_seconds=None):
        self.app = app
        self.db = db
        self.RoutingGroup = RoutingGroup
        self.interval_seconds = float(
            interval_seconds
            or os.getenv("ROUTING_RECONCILE_INTERVAL", "3")
        )
        self._stop = threading.Event()
        self._thread = None
        self._last_signature = None

    def _snapshot(self):
        engine = RoutingEngine()
        groups = self.db.session.execute(
            self.db.select(self.RoutingGroup)
            .where(self.RoutingGroup.vpn_profile_id.is_not(None))
            .order_by(self.RoutingGroup.id.asc())
        ).scalars().all()

        snapshot = []
        for group in groups:
            profile = group.vpn_profile
            status = engine.vpn_runtime.status(profile, include_probe=False)

            gateway = None
            if status.state == "connected":
                gateway = engine.vpn_runtime.route_gateway(profile)

            snapshot.append((
                group.id,
                profile.id,
                status.state,
                status.interface_name,
                status.tunnel_ipv4,
                gateway,
                group.fallback_mode,
            ))
        return tuple(snapshot)

    def _loop(self):
        while not self._stop.wait(self.interval_seconds):
            try:
                with self.app.app_context():
                    current = self._snapshot()

                    if current != self._last_signature:
                        try:
                            RoutingEngine().rebuild(
                                self.db,
                                self.RoutingGroup,
                            )
                        except RoutingEngineError as exc:
                            self.app.logger.error(
                                "Routing reconciler rebuild failed: %s",
                                exc,
                            )
                        else:
                            self.app.logger.info(
                                "Routing reconciler applied VPN state change."
                            )
                            self._last_signature = current

                    self.db.session.remove()
            except Exception:
                self.app.logger.exception(
                    "Unhandled error in routing reconciler."
                )

    def start(self):
        if self._thread and self._thread.is_alive():
            return

        with self.app.app_context():
            self._last_signature = self._snapshot()
            self.db.session.remove()

        self._thread = threading.Thread(
            target=self._loop,
            name="vpn-router-routing-reconciler",
            daemon=True,
        )
        self._thread.start()

        self.app.logger.info(
            "Routing reconciler started (interval %.1fs).",
            self.interval_seconds,
        )

    def stop(self):
        self._stop.set()
