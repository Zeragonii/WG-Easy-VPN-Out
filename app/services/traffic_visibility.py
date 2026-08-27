from __future__ import annotations

from datetime import datetime, timezone
import threading
import time

from ..models import AppSetting, RoutingGroup, VPNProfile
from .effective_assignments import effective_assignments
from .routing import RoutingEngine
from .settings import SettingsService
from .wg_easy import WGEasyError, WGEasyService


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


def _rate(current, previous, elapsed):
    if current is None or previous is None or elapsed <= 0:
        return 0.0
    delta = int(current) - int(previous)
    if delta < 0:
        # Peer counters can reset after WG-Easy/WireGuard restart.
        return 0.0
    return float(delta) / float(elapsed)


def _format_bytes(value):
    if value is None:
        return "—"
    size = float(value)
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{int(value)} B"


def _format_rate(value):
    return f"{_format_bytes(max(0.0, float(value or 0.0)))}/s"


class TrafficVisibilityService:
    """
    In-memory traffic visibility derived from WG-Easy peer counters.

    WG-Easy exposes cumulative WireGuard RX/TX counters per peer. Successive
    samples let us derive short-term byte rates without adding packet counters
    or hooks to the routing dataplane itself.

    Route aggregation is based on the client's *current effective assignment*.
    Cumulative route totals therefore describe the WG counters belonging to the
    clients currently on that route; they are not historical per-route billing.
    """

    def __init__(self, app, db):
        self.app = app
        self.db = db
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = None
        self._previous = {}
        self._snapshot = {
            "available": False,
            "error": "Waiting for first traffic sample.",
            "sampled_at": None,
            "sample_interval_seconds": 5.0,
            "clients": [],
            "groups": [],
            "vpn_profiles": [],
            "totals": {
                "clients": 0,
                "active_clients": 0,
                "rx_total": 0,
                "tx_total": 0,
                "rx_rate": 0.0,
                "tx_rate": 0.0,
            },
        }

    def _interval(self):
        try:
            value = float(
                SettingsService(self.db, AppSetting).get(
                    "traffic_sample_interval"
                )
            )
        except Exception:
            value = 5.0
        return max(2.0, value)

    def _wg_easy(self):
        settings = SettingsService(self.db, AppSetting)
        return WGEasyService(
            base_url=str(settings.get("wg_easy_url")),
            username=str(settings.get("wg_easy_username")),
            password=str(settings.get("wg_easy_password")),
            verify_tls=bool(settings.get("wg_easy_verify_tls")),
        )

    def sample_once(self):
        started = time.monotonic()
        interval = self._interval()

        try:
            clients = self._wg_easy().get_clients()
        except WGEasyError as exc:
            with self._lock:
                current = dict(self._snapshot)
                current.update({
                    "available": False,
                    "error": str(exc),
                    "sampled_at": _iso_now(),
                    "sample_interval_seconds": interval,
                })
                self._snapshot = current
            return self.snapshot()

        effective = {
            str(row.external_id): row
            for row in effective_assignments(self.db)
        }

        groups = self.db.session.execute(
            self.db.select(RoutingGroup).order_by(RoutingGroup.id.asc())
        ).scalars().all()
        group_map = {int(group.id): group for group in groups}

        profiles = self.db.session.execute(
            self.db.select(VPNProfile).order_by(VPNProfile.id.asc())
        ).scalars().all()
        profile_map = {int(profile.id): profile for profile in profiles}

        engine = RoutingEngine()
        group_runtime = {}
        for group in groups:
            try:
                runtime = engine.inspect_group(group)
                group_runtime[int(group.id)] = {
                    "state": runtime.state,
                    "effective_exit": runtime.effective_exit,
                    "detail": runtime.detail,
                }
            except Exception as exc:
                group_runtime[int(group.id)] = {
                    "state": "unknown",
                    "effective_exit": "Unknown",
                    "detail": str(exc)[-240:],
                }

        now_mono = time.monotonic()
        rows = []
        live_ids = set()

        for client in clients:
            external_id = str(client.external_id)
            live_ids.add(external_id)

            previous = self._previous.get(external_id)
            elapsed = (
                now_mono - previous["at"]
                if previous is not None
                else 0.0
            )

            rx_rate = _rate(
                client.transfer_rx,
                previous.get("rx") if previous else None,
                elapsed,
            )
            tx_rate = _rate(
                client.transfer_tx,
                previous.get("tx") if previous else None,
                elapsed,
            )

            self._previous[external_id] = {
                "rx": client.transfer_rx,
                "tx": client.transfer_tx,
                "at": now_mono,
            }

            assignment = effective.get(external_id)
            if assignment is None:
                group = None
                route_group_id = None
                route_name = "Normal routing"
                route_source = "normal"
                configured_exit = "Default WAN"
                effective_exit = "Default WAN"
                route_state = "ready"
                profile_id = None
                profile_name = None
            else:
                route_group_id = int(assignment.routing_group_id)
                group = group_map.get(route_group_id)
                route_name = group.name if group else f"Group {route_group_id}"
                route_source = "override" if assignment.overridden else "permanent"
                configured_exit = (
                    group.target_label if group else "Unknown"
                )
                runtime = group_runtime.get(route_group_id, {})
                effective_exit = runtime.get("effective_exit", configured_exit)
                route_state = runtime.get("state", "unknown")
                profile_id = (
                    int(group.vpn_profile_id)
                    if group and group.vpn_profile_id is not None
                    else None
                )
                profile_name = (
                    profile_map[profile_id].name
                    if profile_id in profile_map
                    else None
                )

            rows.append({
                "id": external_id,
                "name": client.name,
                "ipv4_address": client.ipv4_address,
                "connection_state": client.connection_state,
                "latest_handshake_at": client.latest_handshake_at,
                "routing_group_id": route_group_id,
                "routing_group_name": route_name,
                "route_source": route_source,
                "configured_exit": configured_exit,
                "effective_exit": effective_exit,
                "route_state": route_state,
                "vpn_profile_id": profile_id,
                "vpn_profile_name": profile_name,
                "rx_total": int(client.transfer_rx or 0),
                "tx_total": int(client.transfer_tx or 0),
                "rx_total_display": _format_bytes(client.transfer_rx),
                "tx_total_display": _format_bytes(client.transfer_tx),
                "rx_rate": rx_rate,
                "tx_rate": tx_rate,
                "rx_rate_display": _format_rate(rx_rate),
                "tx_rate_display": _format_rate(tx_rate),
                "active_traffic": (rx_rate + tx_rate) > 0.0,
            })

        # Drop stale rate baselines for clients no longer returned by WG-Easy.
        for external_id in list(self._previous):
            if external_id not in live_ids:
                self._previous.pop(external_id, None)

        # Aggregate by current effective routing group, including normal routing.
        group_buckets = {}
        for row in rows:
            key = row["routing_group_id"]
            bucket = group_buckets.setdefault(key, {
                "id": key,
                "name": row["routing_group_name"],
                "configured_exit": row["configured_exit"],
                "effective_exit": row["effective_exit"],
                "state": row["route_state"],
                "clients": 0,
                "active_clients": 0,
                "rx_total": 0,
                "tx_total": 0,
                "rx_rate": 0.0,
                "tx_rate": 0.0,
            })
            bucket["clients"] += 1
            bucket["active_clients"] += 1 if row["active_traffic"] else 0
            bucket["rx_total"] += row["rx_total"]
            bucket["tx_total"] += row["tx_total"]
            bucket["rx_rate"] += row["rx_rate"]
            bucket["tx_rate"] += row["tx_rate"]

        group_rows = []
        for bucket in group_buckets.values():
            bucket["rx_total_display"] = _format_bytes(bucket["rx_total"])
            bucket["tx_total_display"] = _format_bytes(bucket["tx_total"])
            bucket["rx_rate_display"] = _format_rate(bucket["rx_rate"])
            bucket["tx_rate_display"] = _format_rate(bucket["tx_rate"])
            group_rows.append(bucket)
        group_rows.sort(key=lambda row: (row["id"] is not None, row["name"].casefold()))

        # "Who is using this VPN right now?" Only count clients whose effective
        # routing group is presently exiting through that VPN (not WAN fallback).
        vpn_rows = []
        for profile in profiles:
            matching = [
                row for row in rows
                if row["vpn_profile_id"] == profile.id
                and row["effective_exit"] == profile.name
                and row["route_state"] == "ready"
            ]
            vpn_rows.append({
                "id": profile.id,
                "name": profile.name,
                "consumers": len(matching),
                "active_consumers": sum(
                    1 for row in matching if row["active_traffic"]
                ),
                "client_names": [row["name"] for row in matching],
                "rx_rate": sum(row["rx_rate"] for row in matching),
                "tx_rate": sum(row["tx_rate"] for row in matching),
                "rx_rate_display": _format_rate(
                    sum(row["rx_rate"] for row in matching)
                ),
                "tx_rate_display": _format_rate(
                    sum(row["tx_rate"] for row in matching)
                ),
            })

        totals = {
            "clients": len(rows),
            "active_clients": sum(1 for row in rows if row["active_traffic"]),
            "rx_total": sum(row["rx_total"] for row in rows),
            "tx_total": sum(row["tx_total"] for row in rows),
            "rx_rate": sum(row["rx_rate"] for row in rows),
            "tx_rate": sum(row["tx_rate"] for row in rows),
        }
        totals["rx_total_display"] = _format_bytes(totals["rx_total"])
        totals["tx_total_display"] = _format_bytes(totals["tx_total"])
        totals["rx_rate_display"] = _format_rate(totals["rx_rate"])
        totals["tx_rate_display"] = _format_rate(totals["tx_rate"])

        snapshot = {
            "available": True,
            "error": None,
            "sampled_at": _iso_now(),
            "sample_interval_seconds": interval,
            "sample_duration_seconds": max(0.0, time.monotonic() - started),
            "clients": rows,
            "groups": group_rows,
            "vpn_profiles": vpn_rows,
            "totals": totals,
            "notes": {
                "source": "WG-Easy WireGuard peer counters",
                "rates": "Derived from successive cumulative counter samples",
                "route_totals": (
                    "Cumulative counters for clients currently assigned to each "
                    "effective route; not historical per-route accounting"
                ),
            },
        }

        with self._lock:
            self._snapshot = snapshot

        return self.snapshot()

    def snapshot(self):
        with self._lock:
            result = dict(self._snapshot)
            result["totals"] = dict(self._snapshot.get("totals", {}))
            result["clients"] = [
                dict(row) for row in self._snapshot.get("clients", [])
            ]
            result["groups"] = [
                dict(row) for row in self._snapshot.get("groups", [])
            ]
            result["vpn_profiles"] = [
                dict(row) for row in self._snapshot.get("vpn_profiles", [])
            ]
            result["notes"] = dict(self._snapshot.get("notes", {}))
            return result

    def _loop(self):
        # First sample immediately so the UI is populated shortly after startup.
        while not self._stop.is_set():
            try:
                with self.app.app_context():
                    self.sample_once()
                    self.db.session.remove()
            except Exception:
                self.app.logger.exception(
                    "Unhandled traffic visibility sampling error."
                )

            interval = self._interval()
            if self._stop.wait(interval):
                break

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="vpn-router-traffic-visibility",
            daemon=True,
        )
        self._thread.start()
        self.app.logger.info("Traffic visibility service started.")

    def status(self):
        snapshot = self.snapshot()
        return {
            "name": "traffic_visibility",
            "running": bool(self._thread and self._thread.is_alive()),
            "available": snapshot.get("available"),
            "sampled_at": snapshot.get("sampled_at"),
            "sample_interval_seconds": snapshot.get("sample_interval_seconds"),
            "clients": snapshot.get("totals", {}).get("clients", 0),
            "active_clients": snapshot.get("totals", {}).get("active_clients", 0),
            "error": snapshot.get("error"),
        }

    def stop(self, timeout=3.0):
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, float(timeout)))
        return not bool(thread and thread.is_alive())
