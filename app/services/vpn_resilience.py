from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
import time

from .vpn_runtime import VPNRuntimeError, VPNRuntimeService


@dataclass(slots=True)
class RetryState:
    profile_id: int
    failures: int = 0
    next_retry_at: float | None = None
    last_error: str | None = None
    gave_up: bool = False
    last_success_at: float | None = None

    def to_dict(self):
        return {
            "profile_id": self.profile_id,
            "failures": self.failures,
            "next_retry_at": self.next_retry_at,
            "last_error": self.last_error,
            "gave_up": self.gave_up,
            "last_success_at": self.last_success_at,
        }


class VPNResilienceManager:
    def __init__(self, app, db, VPNProfile):
        self.app = app
        self.db = db
        self.VPNProfile = VPNProfile
        self.runtime = VPNRuntimeService()

        self.interval = float(os.getenv("VPN_RETRY_CHECK_INTERVAL", "2"))
        self.base_delay = float(os.getenv("VPN_RETRY_BASE_SECONDS", "5"))
        self.max_delay = float(os.getenv("VPN_RETRY_MAX_SECONDS", "300"))
        self.max_failures = int(os.getenv("VPN_RETRY_MAX_FAILURES", "0"))
        self.connect_timeout = float(
            os.getenv("VPN_CONNECT_TIMEOUT_SECONDS", "45")
        )

        self.state_dir = Path(os.getenv("VPN_ROUTER_DATA_DIR", "/data")) / "runtime"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.state_dir / "retry-state.json"

        self._stop = threading.Event()
        self._thread = None
        self._states: dict[int, RetryState] = {}
        self._load_state()

    def _load_state(self):
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            payload = {}

        for key, value in payload.items():
            try:
                profile_id = int(key)
                self._states[profile_id] = RetryState(
                    profile_id=profile_id,
                    failures=int(value.get("failures", 0)),
                    next_retry_at=value.get("next_retry_at"),
                    last_error=value.get("last_error"),
                    gave_up=bool(value.get("gave_up", False)),
                    last_success_at=value.get("last_success_at"),
                )
            except (TypeError, ValueError):
                continue

    def _save_state(self):
        self.state_path.write_text(
            json.dumps(
                {str(k): v.to_dict() for k, v in self._states.items()},
                indent=2,
            ),
            encoding="utf-8",
        )

    def _state_for(self, profile_id):
        state = self._states.get(profile_id)
        if state is None:
            state = RetryState(profile_id=profile_id)
            self._states[profile_id] = state
        return state

    def _delay_for_failure(self, failures):
        return min(
            self.max_delay,
            self.base_delay * (2 ** max(0, failures - 1)),
        )

    def reset(self, profile_id, success=False):
        state = self._state_for(profile_id)
        state.failures = 0
        state.next_retry_at = None
        state.last_error = None
        state.gave_up = False
        if success:
            state.last_success_at = time.time()
        self._save_state()

    def record_failure(self, profile_id, error):
        state = self._state_for(profile_id)
        state.failures += 1
        state.last_error = str(error)[-500:]

        if self.max_failures > 0 and state.failures >= self.max_failures:
            state.gave_up = True
            state.next_retry_at = None
        else:
            state.gave_up = False
            state.next_retry_at = time.time() + self._delay_for_failure(
                state.failures
            )

        self._save_state()

    def prune(self, valid_profile_ids):
        valid = {int(profile_id) for profile_id in valid_profile_ids}
        stale = [
            profile_id
            for profile_id in self._states
            if profile_id not in valid
        ]
        for profile_id in stale:
            self._states.pop(profile_id, None)
        if stale:
            self._save_state()
        return stale

    def public_state(self, profile_id):
        state = self._state_for(profile_id)
        retry_in = None
        if state.next_retry_at is not None:
            retry_in = max(0, int(state.next_retry_at - time.time()))

        return {
            "failures": state.failures,
            "retry_in_seconds": retry_in,
            "last_error": state.last_error,
            "gave_up": state.gave_up,
            "last_success_at": (
                datetime.fromtimestamp(
                    state.last_success_at,
                    tz=timezone.utc,
                ).isoformat()
                if state.last_success_at
                else None
            ),
        }

    def _attempt_start(self, profile):
        try:
            self.runtime.start(profile)
        except VPNRuntimeError as exc:
            self.record_failure(profile.id, exc)
            self.app.logger.warning(
                "Retry start failed for profile %s (%s): %s",
                profile.id,
                profile.name,
                exc,
            )
            return False

        # Starting an OpenVPN process is not the same as establishing a
        # working tunnel. Preserve the existing failure count until a later
        # resilience tick observes status == "connected". This also keeps
        # last_success_at meaningful and allows repeated connecting timeouts
        # to accumulate exponential backoff correctly.
        state = self._state_for(profile.id)
        state.next_retry_at = None
        state.gave_up = False
        self._save_state()

        self.app.logger.info(
            "Retry process started for profile %s (%s); "
            "awaiting confirmed tunnel connection.",
            profile.id,
            profile.name,
        )
        return True

    def _tick_profile(self, profile):
        state = self._state_for(profile.id)

        if not profile.enabled:
            if state.failures or state.next_retry_at or state.last_error or state.gave_up:
                self.reset(profile.id)
            return

        if profile.vpn_type != "openvpn":
            return

        status = self.runtime.status(profile, include_probe=False)

        if status.state == "connected":
            if state.failures or state.next_retry_at or state.last_error or state.gave_up:
                self.reset(profile.id, success=True)
            return

        if status.state == "connecting":
            # A live OpenVPN PID is not enough to call an attempt healthy.
            # If it never acquires a tunnel address, recycle it and enter the
            # normal exponential retry path.
            if (
                self.connect_timeout > 0
                and status.uptime_seconds is not None
                and status.uptime_seconds >= self.connect_timeout
            ):
                error = (
                    f"OpenVPN remained in connecting state for "
                    f"{status.uptime_seconds}s "
                    f"(timeout {int(self.connect_timeout)}s)."
                )
                try:
                    self.runtime.stop(profile)
                except Exception as exc:
                    error += f" Stop also reported: {exc}"

                self.record_failure(profile.id, error)
                self.app.logger.warning(
                    "Connecting timeout for profile %s (%s): %s",
                    profile.id,
                    profile.name,
                    error,
                )
            return

        if state.gave_up:
            return

        now = time.time()
        if state.next_retry_at is None:
            state.next_retry_at = now
            self._save_state()

        if now >= state.next_retry_at:
            self._attempt_start(profile)

    def _loop(self):
        while not self._stop.wait(self.interval):
            try:
                with self.app.app_context():
                    profiles = self.db.session.execute(
                        self.db.select(self.VPNProfile)
                        .order_by(self.VPNProfile.id.asc())
                    ).scalars().all()

                    active_ids = {profile.id for profile in profiles}
                    for profile in profiles:
                        self._tick_profile(profile)

                    stale = [
                        profile_id
                        for profile_id in self._states
                        if profile_id not in active_ids
                    ]
                    for profile_id in stale:
                        self._states.pop(profile_id, None)
                    if stale:
                        self._save_state()

                    self.db.session.remove()
            except Exception:
                self.app.logger.exception(
                    "Unhandled error in VPN resilience manager."
                )

    def start(self):
        if self._thread and self._thread.is_alive():
            return

        self._stop.clear()

        self._thread = threading.Thread(
            target=self._loop,
            name="vpn-router-vpn-resilience",
            daemon=True,
        )
        self._thread.start()

        self.app.logger.info(
            "VPN resilience manager started "
            "(check %.1fs, base %.1fs, max %.1fs, connect timeout %.1fs).",
            self.interval,
            self.base_delay,
            self.max_delay,
            self.connect_timeout,
        )

    def status(self):
        return {
            "name": "vpn_resilience",
            "running": bool(self._thread and self._thread.is_alive()),
            "interval_seconds": self.interval,
            "base_delay_seconds": self.base_delay,
            "max_delay_seconds": self.max_delay,
            "max_failures": self.max_failures,
            "connect_timeout_seconds": self.connect_timeout,
            "tracked_profiles": len(self._states),
        }

    def stop(self, timeout=3.0):
        self._stop.set()
        thread = self._thread
        if (
            thread
            and thread.is_alive()
            and thread is not threading.current_thread()
        ):
            thread.join(timeout=max(0.0, float(timeout)))
        return not bool(thread and thread.is_alive())
