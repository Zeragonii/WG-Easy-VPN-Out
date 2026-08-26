
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

from .routing import RoutingEngine, RoutingEngineError
from .vpn_runtime import VPNRuntimeError, VPNRuntimeService


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


class OnDemandVPNManager:
    """Assignment-driven lifecycle manager for outbound VPN profiles."""

    def __init__(
        self,
        app,
        db,
        VPNProfile,
        RoutingGroup,
        ClientAssignment,
        interval_seconds=2.0,
        idle_grace_seconds=60.0,
    ):
        self.app = app
        self.db = db
        self.VPNProfile = VPNProfile
        self.RoutingGroup = RoutingGroup
        self.ClientAssignment = ClientAssignment
        self.runtime = VPNRuntimeService()
        self.interval_seconds = float(interval_seconds)
        self.idle_grace_seconds = float(idle_grace_seconds)
        self._idle_since = {}
        self._last_error = {}
        self._last_action = {}
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.RLock()

    def _required_ids(self):
        rows = self.db.session.execute(
            self.db.select(self.RoutingGroup.vpn_profile_id)
            .join(
                self.ClientAssignment,
                self.ClientAssignment.routing_group_id == self.RoutingGroup.id,
            )
            .where(self.RoutingGroup.vpn_profile_id.is_not(None))
            .distinct()
        ).scalars().all()
        return {int(value) for value in rows if value is not None}

    def required_profile_ids(self):
        with self.app.app_context():
            values = self._required_ids()
            self.db.session.remove()
            return values

    def consumer_counts(self):
        with self.app.app_context():
            rows = self.db.session.execute(
                self.db.select(
                    self.RoutingGroup.vpn_profile_id,
                    self.db.func.count(self.ClientAssignment.id),
                )
                .outerjoin(
                    self.ClientAssignment,
                    self.ClientAssignment.routing_group_id == self.RoutingGroup.id,
                )
                .where(self.RoutingGroup.vpn_profile_id.is_not(None))
                .group_by(self.RoutingGroup.vpn_profile_id)
            ).all()
            result = {
                int(profile_id): int(count or 0)
                for profile_id, count in rows
                if profile_id is not None
            }
            self.db.session.remove()
            return result

    def public_state(self, profile_id):
        profile_id = int(profile_id)
        with self._lock:
            started = self._idle_since.get(profile_id)
            remaining = None
            if started is not None:
                remaining = max(
                    0,
                    int(self.idle_grace_seconds - (time.monotonic() - started)),
                )
            return {
                "idle_remaining_seconds": remaining,
                "last_error": self._last_error.get(profile_id),
                "last_action": self._last_action.get(profile_id),
            }

    def _record(self, profile_id, action):
        with self._lock:
            self._last_action[int(profile_id)] = {
                "action": action,
                "at": _iso_now(),
            }
            self._last_error.pop(int(profile_id), None)

    def _error(self, profile_id, exc):
        with self._lock:
            self._last_error[int(profile_id)] = str(exc)[-500:]

    def ensure_profile_ready(self, profile, wait_seconds=48.0):
        """
        Start an on-demand profile if needed and wait for a confirmed tunnel.

        Used during assignment changes so a client is not moved onto a routing
        group until its new outbound tunnel is actually available.
        """
        if not profile.enabled:
            return False, "VPN profile is disabled."

        status = self.runtime.status(profile, include_probe=False)
        if status.state == "connected":
            self._idle_since.pop(profile.id, None)
            return True, None

        if status.state not in ("connecting",):
            try:
                self.runtime.start(profile)
                self._record(profile.id, "start")
            except VPNRuntimeError as exc:
                self._error(profile.id, exc)
                return False, str(exc)

        deadline = time.monotonic() + max(1.0, float(wait_seconds))
        while time.monotonic() < deadline:
            status = self.runtime.status(profile, include_probe=False)
            if status.state == "connected":
                self._idle_since.pop(profile.id, None)
                return True, None
            if status.state in ("failed", "disconnected"):
                message = status.last_error or "VPN did not establish a tunnel."
                self._error(profile.id, message)
                return False, message
            time.sleep(0.5)

        message = "Timed out waiting for the VPN tunnel to connect."
        self._error(profile.id, message)
        return False, message

    def reconcile_once(self):
        required = self._required_ids()
        changed = False
        now = time.monotonic()

        profiles = self.db.session.execute(
            self.db.select(self.VPNProfile).order_by(self.VPNProfile.id.asc())
        ).scalars().all()

        for profile in profiles:
            if (
                not profile.enabled
                or profile.connection_policy != "on_demand"
                or profile.vpn_type != "openvpn"
            ):
                self._idle_since.pop(profile.id, None)
                continue

            if profile.id in required:
                self._idle_since.pop(profile.id, None)
                status = self.runtime.status(profile, include_probe=False)
                if status.state not in ("connected", "connecting"):
                    try:
                        self.runtime.start(profile)
                        self._record(profile.id, "start")
                        changed = True
                    except VPNRuntimeError as exc:
                        self._error(profile.id, exc)
                continue

            status = self.runtime.status(profile, include_probe=False)
            if status.state in ("disconnected", "failed"):
                self._idle_since.pop(profile.id, None)
                continue

            started = self._idle_since.setdefault(profile.id, now)
            if now - started >= self.idle_grace_seconds:
                self.runtime.stop(profile)
                self._record(profile.id, "stop")
                self._idle_since.pop(profile.id, None)
                changed = True

        if changed:
            try:
                RoutingEngine().rebuild(self.db, self.RoutingGroup)
            except RoutingEngineError as exc:
                self.app.logger.error("On-demand routing rebuild failed: %s", exc)

        return {"required_profile_ids": sorted(required), "changed": changed}

    def _loop(self):
        while not self._stop.wait(self.interval_seconds):
            try:
                with self.app.app_context():
                    self.reconcile_once()
                    self.db.session.remove()
            except Exception:
                self.app.logger.exception("Unhandled error in on-demand VPN manager.")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="vpn-router-on-demand",
            daemon=True,
        )
        self._thread.start()
        self.app.logger.info(
            "On-demand VPN manager started (check %.1fs, idle grace %.1fs).",
            self.interval_seconds,
            self.idle_grace_seconds,
        )

    def status(self):
        return {
            "name": "on_demand_vpn",
            "running": bool(self._thread and self._thread.is_alive()),
            "interval_seconds": self.interval_seconds,
            "idle_grace_seconds": self.idle_grace_seconds,
            "tracked_idle_profiles": len(self._idle_since),
        }

    def stop(self, timeout=3.0):
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, float(timeout)))
        return not bool(thread and thread.is_alive())
