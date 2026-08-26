from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import threading
import time

import requests

from .vpn_runtime import VPNRuntimeService
from .dns_observability import run_dns_leak_probe, run_explicit_resolver_probe


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


def _version_tokens(value):
    """
    Parse flexible human-friendly version strings.

    Supported examples:
      0.7.5
      0.7.5.1
      0.7.5a
      0.7.5.3a
      v1.2.0-beta

    Numeric runs compare numerically, alphabetic runs compare
    case-insensitively, and an additional suffix/component sorts after an
    otherwise identical shorter version. This intentionally treats 0.7.5a as
    newer than 0.7.5, matching the project's micro-patch convention.
    """
    if not value:
        return None

    text = str(value).strip()
    if text[:1].lower() == "v":
        text = text[1:]

    if not text or not re.fullmatch(r"[0-9A-Za-z._+\-]+", text):
        return None

    raw_tokens = re.findall(r"\d+|[A-Za-z]+", text)
    if not raw_tokens:
        return None

    tokens = []
    for token in raw_tokens:
        if token.isdigit():
            tokens.append(("n", int(token)))
        else:
            tokens.append(("a", token.lower()))

    return tuple(tokens)


def _compare_versions(left, right):
    """
    Return -1, 0, or 1 using the project's flexible version convention.
    """
    left_tokens = _version_tokens(left)
    right_tokens = _version_tokens(right)

    if left_tokens is None or right_tokens is None:
        return None

    for left_token, right_token in zip(left_tokens, right_tokens):
        if left_token == right_token:
            continue

        left_type, left_value = left_token
        right_type, right_value = right_token

        if left_type == right_type:
            return 1 if left_value > right_value else -1

        # Numeric components sort after alphabetic components at the same
        # position, e.g. 1.0.1 > 1.0a.
        return 1 if left_type == "n" else -1

    if len(left_tokens) == len(right_tokens):
        return 0

    # A longer otherwise-identical version is considered newer:
    # 0.7.5a > 0.7.5 and 0.7.5.1 > 0.7.5.
    return 1 if len(left_tokens) > len(right_tokens) else -1


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

        self.loop_interval = 2.0
        self.reload_settings()

        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

        self._exit_ips = {}
        self._dns_states = {}
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
        self._next_dns_refresh = 0.0

    def reload_settings(self):
        from ..models import AppSetting
        from .settings import SettingsService
        with self.app.app_context():
            settings = SettingsService(self.db, AppSetting)
            self.exit_ip_interval = float(settings.get("exit_ip_probe_interval"))
            self.dns_probe_interval = float(settings.get("dns_leak_probe_interval"))
            self.update_cache_seconds = float(settings.get("update_check_cache_seconds"))
            self.update_url = str(settings.get("update_version_url")).strip()
            self.repository_url = str(settings.get("update_repository_url")).strip()
            if hasattr(self, "_update") and isinstance(self._update, dict):
                self._update["repository_url"] = self.repository_url

    def dns_state(self, profile_id):
        with self._lock:
            value = self._dns_states.get(int(profile_id))
            return dict(value) if value else None

    def _set_dns_state(self, profile_id, **values):
        with self._lock:
            current = dict(self._dns_states.get(int(profile_id), {}))
            current.update(values)
            self._dns_states[int(profile_id)] = current

    def _probe_dns_for_profile(self, profile):
        status = self.runtime.status(profile, include_probe=False)
        if status.state != "connected" or not status.tunnel_ipv4:
            self._set_dns_state(
                profile.id,
                state="unavailable",
                detail="VPN is not currently connected.",
                checked_at=_iso_now(),
                resolvers=[],
                checking=False,
            )
            return

        self._set_dns_state(profile.id, checking=True)
        try:
            result = run_dns_leak_probe(
                self.runtime,
                profile,
                status.interface_name,
                status.tunnel_ipv4,
            )
        except Exception as exc:
            self._set_dns_state(
                profile.id,
                state="unavailable",
                detail=str(exc)[-400:],
                checked_at=_iso_now(),
                resolvers=[],
                checking=False,
            )
        else:
            result["checking"] = False
            self._set_dns_state(profile.id, **result)

    def refresh_dns_group(self, group):
        with self.app.app_context():
            profile = group.vpn_profile
            if profile is None:
                raise ValueError("Routing group is not VPN-backed.")

            status = self.runtime.status(profile, include_probe=False)
            if status.state != "connected" or not status.tunnel_ipv4:
                result = {
                    "state": "unavailable",
                    "detail": "VPN is not currently connected.",
                    "checked_at": _iso_now(),
                    "resolvers": [],
                    "checking": False,
                }
                self._set_dns_state(profile.id, **result)
                return result

            target = group.effective_dns_target
            if target:
                try:
                    result = run_explicit_resolver_probe(
                        self.runtime,
                        profile,
                        status.interface_name,
                        status.tunnel_ipv4,
                        target,
                        group.table_id,
                        group.mark_hex,
                    )
                except Exception as exc:
                    result = {
                        "state": "unavailable",
                        "detail": str(exc)[-400:],
                        "checked_at": _iso_now(),
                        "resolvers": [],
                        "configured_resolver": target,
                        "checking": False,
                    }
                else:
                    result["checking"] = False
                self._set_dns_state(profile.id, **result)
                return result

            return self.refresh_dns_profile(profile.id)

    def refresh_dns_profile(self, profile_id):
        with self.app.app_context():
            profile = self.db.session.get(self.VPNProfile, int(profile_id))
            if profile is None:
                raise ValueError("VPN profile not found.")
            self._probe_dns_for_profile(profile)
            result = self.dns_state(profile.id)
            self.db.session.remove()
            return result

    def _refresh_dns(self):
        with self.app.app_context():
            profiles = self.db.session.execute(
                self.db.select(self.VPNProfile)
                .where(
                    self.VPNProfile.vpn_type == "openvpn",
                    self.VPNProfile.enabled.is_(True),
                )
                .order_by(self.VPNProfile.id.asc())
            ).scalars().all()

            active_ids = {profile.id for profile in profiles}
            for profile in profiles:
                self._probe_dns_for_profile(profile)

            with self._lock:
                stale = [
                    profile_id
                    for profile_id in self._dns_states
                    if profile_id not in active_ids
                ]
                for profile_id in stale:
                    self._dns_states.pop(profile_id, None)

            self.db.session.remove()

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
                "dns": {
                    str(key): dict(value)
                    for key, value in self._dns_states.items()
                },
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
                    exit_ip = self.runtime.exit_ip(
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

        comparison = _compare_versions(latest, installed)
        available = comparison == 1

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

            if (
                self.dns_probe_interval > 0
                and now >= self._next_dns_refresh
            ):
                self._next_dns_refresh = now + self.dns_probe_interval
                try:
                    self._refresh_dns()
                except Exception:
                    self.app.logger.exception(
                        "Unhandled DNS observability refresh error."
                    )


    def start(self):
        if self._thread and self._thread.is_alive():
            return

        self._stop.clear()

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

    def invalidate_profiles(self, valid_profile_ids=None):
        """
        Drop cached exit-IP rows, optionally retaining only current profile IDs.
        """
        with self._lock:
            if valid_profile_ids is None:
                self._exit_ips.clear()
                return

            valid = {int(profile_id) for profile_id in valid_profile_ids}
            stale = [
                profile_id
                for profile_id in self._exit_ips
                if profile_id not in valid
            ]
            for profile_id in stale:
                self._exit_ips.pop(profile_id, None)

    def status(self):
        with self._lock:
            cached_exit_ips = len(self._exit_ips)
            update_checked_at = self._update.get("checked_at")

        return {
            "name": "observability",
            "running": bool(self._thread and self._thread.is_alive()),
            "loop_interval_seconds": self.loop_interval,
            "exit_ip_interval_seconds": self.exit_ip_interval,
            "update_cache_seconds": self.update_cache_seconds,
            "dns_probe_interval_seconds": self.dns_probe_interval,
            "cached_dns_states": len(self._dns_states),
            "cached_exit_ips": cached_exit_ips,
            "update_checked_at": update_checked_at,
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
