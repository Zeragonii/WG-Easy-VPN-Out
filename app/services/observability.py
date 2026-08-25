from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import threading
import time

import requests

from .vpn_runtime import VPNRuntimeService


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


def _installed_version():
    override = os.getenv("APP_VERSION", "").strip()
    if override:
        return override

    for path in (
        Path("/app/VERSION"),
        Path(__file__).resolve().parents[2] / "VERSION",
    ):
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return value

    return "unknown"


def _version_key(value):
    """
    Compare ordinary semantic-ish versions such as 0.7.3 or v1.2.0.

    Non-numeric suffixes are ignored for update-awareness purposes.
    """
    if not value:
        return None

    match = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", str(value).strip())
    if not match:
        return None

    return tuple(int(part) for part in match.groups())


class ObservabilityService:
    """
    Background-only external observability.

    No exit-IP or GitHub request is made as part of a dashboard page request.
    """

    def __init__(self, app, db, VPNProfile):
        self.app = app
        self.db = db
        self.VPNProfile = VPNProfile
        self.runtime = VPNRuntimeService()

        self.loop_interval = float(
            os.getenv("OBSERVABILITY_LOOP_INTERVAL", "2")
        )
        self.exit_ip_interval = float(
            os.getenv("EXIT_IP_PROBE_INTERVAL", "60")
        )
        self.update_cache_seconds = float(
            os.getenv("UPDATE_CHECK_CACHE_SECONDS", "900")
        )
        self.update_url = os.getenv(
            "UPDATE_VERSION_URL",
            "https://raw.githubusercontent.com/"
            "Zeragonii/WG-Easy-VPN-Out/main/VERSION",
        ).strip()
        self.repository_url = os.getenv(
            "UPDATE_REPOSITORY_URL",
            "https://github.com/Zeragonii/WG-Easy-VPN-Out",
        ).strip()

        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

        self._exit_ips = {}
        self._update = {
            "installed": _installed_version(),
            "latest": None,
            "available": False,
            "checked_at": None,
            "error": None,
            "repository_url": self.repository_url,
        }

        self._update_checked_monotonic = None

        self._next_exit_refresh = 0.0

    def exit_ip_state(self, profile_id):
        with self._lock:
            value = self._exit_ips.get(int(profile_id))
            return dict(value) if value else None

    def update_state(self, refresh_if_stale=False):
        if refresh_if_stale:
            self.refresh_update_if_stale()

        with self._lock:
            return dict(self._update)

    def snapshot(self):
        with self._lock:
            return {
                "exit_ips": {
                    str(key): dict(value)
                    for key, value in self._exit_ips.items()
                },
                "update": dict(self._update),
            }

    def _set_exit_state(self, profile_id, **values):
        with self._lock:
            current = dict(self._exit_ips.get(profile_id, {}))
            current.update(values)
            self._exit_ips[profile_id] = current

    def _refresh_exit_ips(self):
        with self.app.app_context():
            profiles = self.db.session.execute(
                self.db.select(self.VPNProfile)
                .where(self.VPNProfile.vpn_type == "openvpn")
                .order_by(self.VPNProfile.id.asc())
            ).scalars().all()

            active_ids = {profile.id for profile in profiles}

            for profile in profiles:
                status = self.runtime.status(
                    profile,
                    include_probe=False,
                )

                if status.state != "connected" or not status.tunnel_ipv4:
                    self._set_exit_state(
                        profile.id,
                        connected=False,
                        checking=False,
                        last_checked=_iso_now(),
                    )
                    continue

                # Publish "checking" without erasing the last successful IP.
                self._set_exit_state(
                    profile.id,
                    connected=True,
                    checking=True,
                )

                try:
                    exit_ip = self.runtime._exit_ip(
                        profile,
                        status.interface_name,
                        status.tunnel_ipv4,
                    )
                except Exception as exc:
                    self.app.logger.warning(
                        "Exit-IP probe crashed for profile %s (%s): %s",
                        profile.id,
                        profile.name,
                        exc,
                    )
                    exit_ip = None

                if exit_ip:
                    self._set_exit_state(
                        profile.id,
                        exit_ip=exit_ip,
                        connected=True,
                        checking=False,
                        probe_ok=True,
                        last_checked=_iso_now(),
                        error=None,
                    )
                else:
                    self._set_exit_state(
                        profile.id,
                        connected=True,
                        checking=False,
                        probe_ok=False,
                        last_checked=_iso_now(),
                        error="Probe unavailable",
                    )

            with self._lock:
                stale = [
                    profile_id
                    for profile_id in self._exit_ips
                    if profile_id not in active_ids
                ]
                for profile_id in stale:
                    self._exit_ips.pop(profile_id, None)

            self.db.session.remove()

    def refresh_update_if_stale(self):
        now = time.monotonic()

        with self._lock:
            checked = self._update_checked_monotonic

        if (
            checked is not None
            and self.update_cache_seconds > 0
            and (now - checked) < self.update_cache_seconds
        ):
            return

        self._refresh_update()

    def _refresh_update(self):
        installed = _installed_version()
        latest = None
        error = None

        try:
            response = requests.get(
                self.update_url,
                timeout=5,
                headers={
                    "Accept": "text/plain",
                    "User-Agent": f"WG-Easy-VPN-Out/{installed}",
                },
            )
            response.raise_for_status()
            latest = response.text.strip().splitlines()[0].strip()
            if len(latest) > 64:
                raise ValueError("VERSION response is unexpectedly long")
        except (requests.RequestException, ValueError, IndexError) as exc:
            error = str(exc)[-300:]

        installed_key = _version_key(installed)
        latest_key = _version_key(latest)

        available = bool(
            installed_key
            and latest_key
            and latest_key > installed_key
        )

        with self._lock:
            self._update = {
                "installed": installed,
                "latest": latest,
                "available": available,
                "checked_at": _iso_now(),
                "error": error,
                "repository_url": self.repository_url,
            }
            self._update_checked_monotonic = time.monotonic()

    def _loop(self):
        # The initial refreshes happen immediately after startup, but entirely
        # off the request path.
        while not self._stop.wait(self.loop_interval):
            now = time.monotonic()

            if now >= self._next_exit_refresh:
                self._next_exit_refresh = now + self.exit_ip_interval
                try:
                    self._refresh_exit_ips()
                except Exception:
                    self.app.logger.exception(
                        "Unhandled exit-IP observability refresh error."
                    )


    def start(self):
        if self._thread and self._thread.is_alive():
            return

        self._thread = threading.Thread(
            target=self._loop,
            name="vpn-router-observability",
            daemon=True,
        )
        self._thread.start()

        self.app.logger.info(
            "Observability service started "
            "(exit IP %.0fs, update cache %.0fs).",
            self.exit_ip_interval,
            self.update_cache_seconds,
        )

    def stop(self):
        self._stop.set()
