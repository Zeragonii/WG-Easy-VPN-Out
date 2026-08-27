from __future__ import annotations

from datetime import datetime, timedelta, timezone
import threading

from ..models import ClientRouteOverride, RouteOverrideEvent, RoutingGroup
from .routing import RoutingEngine, RoutingEngineError


DURATIONS = {
    "15m": timedelta(minutes=15),
    "30m": timedelta(minutes=30),
    "1h": timedelta(hours=1),
    "4h": timedelta(hours=4),
}


def _utcnow_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def expiry_for(duration_key):
    if duration_key == "until_cancelled":
        return None
    delta = DURATIONS.get(duration_key)
    if delta is None:
        raise ValueError("Unsupported override duration.")
    return _utcnow_naive() + delta


def active_override_map(db):
    now = _utcnow_naive()
    rows = db.session.execute(
        db.select(ClientRouteOverride).where(
            db.or_(
                ClientRouteOverride.expires_at.is_(None),
                ClientRouteOverride.expires_at > now,
            )
        )
    ).scalars().all()
    return {str(row.external_id): row for row in rows}


def _event(db, override, event_type, detail):
    group = db.session.get(RoutingGroup, int(override.routing_group_id))
    db.session.add(RouteOverrideEvent(
        external_id=str(override.external_id),
        client_name=override.client_name,
        event_type=event_type,
        routing_group_id=int(override.routing_group_id),
        routing_group_name=group.name if group else None,
        detail=detail,
    ))


class TemporaryOverrideManager:
    def __init__(self, app, db, interval_seconds=2.0):
        self.app = app
        self.db = db
        self.interval_seconds = float(interval_seconds)
        self._stop = threading.Event()
        self._thread = None

    def _reconcile_routing(self):
        RoutingEngine().apply_assignment_sets(self.db, RoutingGroup)
        manager = self.app.extensions.get("on_demand_vpn")
        if manager is not None:
            manager.reconcile_once()

    def expire_once(self):
        now = _utcnow_naive()
        rows = self.db.session.execute(
            self.db.select(ClientRouteOverride).where(
                ClientRouteOverride.expires_at.is_not(None),
                ClientRouteOverride.expires_at <= now,
            )
        ).scalars().all()

        if not rows:
            return 0

        for override in rows:
            _event(
                self.db,
                override,
                "expired",
                "Temporary routing override expired and the persistent assignment resumed.",
            )
            self.db.session.delete(override)

        self.db.session.commit()

        try:
            self._reconcile_routing()
        except RoutingEngineError as exc:
            self.app.logger.error(
                "Routing refresh after override expiry failed: %s",
                exc,
            )

        return len(rows)

    def _loop(self):
        while not self._stop.wait(self.interval_seconds):
            try:
                with self.app.app_context():
                    self.expire_once()
                    self.db.session.remove()
            except Exception:
                self.app.logger.exception(
                    "Unhandled temporary-routing-override expiry error."
                )

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="vpn-router-temporary-overrides",
            daemon=True,
        )
        self._thread.start()
        self.app.logger.info(
            "Temporary routing override manager started (check %.1fs).",
            self.interval_seconds,
        )

    def status(self):
        with self.app.app_context():
            count = self.db.session.execute(
                self.db.select(self.db.func.count(ClientRouteOverride.id))
            ).scalar_one()
            self.db.session.remove()
        return {
            "name": "temporary_routing_overrides",
            "running": bool(self._thread and self._thread.is_alive()),
            "interval_seconds": self.interval_seconds,
            "active_overrides": int(count or 0),
        }

    def stop(self, timeout=3.0):
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, float(timeout)))
        return not bool(thread and thread.is_alive())
