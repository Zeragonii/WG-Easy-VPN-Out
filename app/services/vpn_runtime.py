from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import time


class VPNRuntimeError(RuntimeError):
    pass


@dataclass(slots=True)
class RuntimeStatus:
    state: str
    interface_name: str
    pid: int | None = None
    tunnel_ipv4: str | None = None
    uptime_seconds: int | None = None
    exit_ip: str | None = None
    last_error: str | None = None
    log_tail: list[str] | None = None

    def to_dict(self):
        return asdict(self)


class VPNRuntimeService:
    def __init__(self, data_root: str = "/data"):
        self.data_root = Path(data_root)
        self.runtime_dir = self.data_root / "runtime"
        self.runtime_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def interface_name(profile) -> str:
        return f"tun-vpn{profile.id}" if profile.vpn_type == "openvpn" else f"wg-vpn{profile.id}"

    def _pid_path(self, profile): return self.runtime_dir / f"profile-{profile.id}.pid"
    def _meta_path(self, profile): return self.runtime_dir / f"profile-{profile.id}.json"
    def _log_path(self, profile): return self.runtime_dir / f"profile-{profile.id}.log"
    def _auth_path(self, profile): return self.runtime_dir / f"profile-{profile.id}.auth"

    def _config_path(self, profile):
        folder = "openvpn" if profile.vpn_type == "openvpn" else "wireguard"
        return self.data_root / folder / profile.config_filename

    @staticmethod
    def _run(args, timeout=5.0):
        return subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)

    @staticmethod
    def _pid_alive(pid):
        if not pid:
            return False
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False

    def _read_pid(self, profile):
        try:
            return int(self._pid_path(profile).read_text().strip())
        except (OSError, ValueError):
            return None

    def _read_meta(self, profile):
        try:
            return json.loads(self._meta_path(profile).read_text())
        except (OSError, ValueError, json.JSONDecodeError):
            return {}

    def _write_meta(self, profile, data):
        self._meta_path(profile).write_text(json.dumps(data, indent=2))

    def _interface_exists(self, name):
        return self._run(["ip", "link", "show", "dev", name], 2).returncode == 0

    def _interface_ipv4(self, name):
        result = self._run(["ip", "-j", "-4", "addr", "show", "dev", name], 2)
        if result.returncode != 0:
            return None
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
        for iface in payload:
            for addr in iface.get("addr_info", []):
                if addr.get("family") == "inet" and addr.get("local"):
                    return addr["local"]
        return None

    def _log_tail(self, profile, lines=20):
        try:
            return self._log_path(profile).read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]
        except OSError:
            return []

    @staticmethod
    def _detect_last_error(lines):
        tokens = ("AUTH_FAILED", "ERROR", "Options error", "TLS Error", "Connection refused", "Cannot resolve", "fatal error")
        for line in reversed(lines):
            if any(token.lower() in line.lower() for token in tokens):
                return line[-500:]
        return None

    def _probe_ids(self, profile):
        value = 20000 + int(profile.id)
        return value, value

    def _ensure_probe_route(self, profile, iface, tunnel_ip):
        table, priority = self._probe_ids(profile)
        self._run(["ip", "route", "replace", "default", "dev", iface, "table", str(table)])
        rules = self._run(["ip", "-4", "rule", "show"], 2).stdout
        if f"from {tunnel_ip} lookup {table}" not in rules:
            self._run(["ip", "-4", "rule", "add", "priority", str(priority), "from", f"{tunnel_ip}/32", "lookup", str(table)])

    def _remove_probe_route(self, profile):
        table, priority = self._probe_ids(profile)
        self._run(["ip", "-4", "rule", "del", "priority", str(priority)])
        self._run(["ip", "route", "flush", "table", str(table)])

    def _exit_ip(self, profile, iface, tunnel_ip):
        self._ensure_probe_route(profile, iface, tunnel_ip)
        result = self._run([
            "curl", "--silent", "--show-error", "--fail",
            "--max-time", "5",
            "--interface", tunnel_ip,
            "https://api.ipify.org",
        ], 7)
        value = result.stdout.strip()
        return value if result.returncode == 0 and value and len(value) < 65 else None

    def start(self, profile):
        if profile.vpn_type != "openvpn":
            raise VPNRuntimeError("WireGuard runtime activation is not implemented in v0.3.1 yet.")

        if self._pid_alive(self._read_pid(profile)):
            raise VPNRuntimeError("This VPN profile is already running.")

        config_path = self._config_path(profile)
        if not config_path.exists():
            raise VPNRuntimeError(f"VPN config file is missing: {config_path}")

        iface = self.interface_name(profile)
        log_path = self._log_path(profile)
        auth_path = self._auth_path(profile)

        self._remove_probe_route(profile)
        self._pid_path(profile).unlink(missing_ok=True)

        args = [
            "openvpn",
            "--config", str(config_path),
            "--dev", iface,
            "--route-noexec",
            "--pull-filter", "ignore", "redirect-gateway",
            "--verb", "3",
        ]

        if profile.username or profile.password:
            auth_path.write_text(f"{profile.username or ''}\n{profile.password or ''}\n", encoding="utf-8")
            os.chmod(auth_path, 0o600)
            args.extend(["--auth-user-pass", str(auth_path)])

        log_handle = open(log_path, "a", encoding="utf-8", buffering=1)
        log_handle.write(f"\n=== VPN Router start {datetime.now(timezone.utc).isoformat()} ===\n")
        log_handle.flush()

        try:
            process = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            raise VPNRuntimeError(f"Could not start OpenVPN: {exc}") from exc
        finally:
            log_handle.close()

        self._pid_path(profile).write_text(str(process.pid))
        self._write_meta(profile, {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "interface_name": iface,
        })

        time.sleep(0.4)
        if process.poll() is not None:
            self._pid_path(profile).unlink(missing_ok=True)
            logs = self._log_tail(profile)
            raise VPNRuntimeError(self._detect_last_error(logs) or "OpenVPN exited during startup.")

    def stop(self, profile):
        pid = self._read_pid(profile)
        iface = self.interface_name(profile)

        self._remove_probe_route(profile)

        if pid and self._pid_alive(pid):
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and self._pid_alive(pid):
                time.sleep(0.2)
            if self._pid_alive(pid):
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

        if self._interface_exists(iface):
            self._run(["ip", "link", "delete", iface])

        self._pid_path(profile).unlink(missing_ok=True)
        self._meta_path(profile).unlink(missing_ok=True)
        self._auth_path(profile).unlink(missing_ok=True)

    def status(self, profile, include_probe=True):
        iface = self.interface_name(profile)
        pid = self._read_pid(profile)
        alive = self._pid_alive(pid)
        exists = self._interface_exists(iface)
        tunnel_ip = self._interface_ipv4(iface) if exists else None
        logs = self._log_tail(profile)
        last_error = self._detect_last_error(logs)

        if alive and tunnel_ip:
            state = "connected"
        elif alive:
            state = "connecting"
        elif exists:
            state = "stale"
        elif last_error:
            state = "failed"
        else:
            state = "disconnected"

        uptime = None
        meta = self._read_meta(profile)
        if alive and meta.get("started_at"):
            try:
                dt = datetime.fromisoformat(meta["started_at"].replace("Z", "+00:00"))
                uptime = max(0, int((datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds()))
            except (TypeError, ValueError):
                pass

        exit_ip = None
        if include_probe and state == "connected" and tunnel_ip:
            exit_ip = self._exit_ip(profile, iface, tunnel_ip)

        return RuntimeStatus(
            state=state,
            interface_name=iface,
            pid=pid if alive else None,
            tunnel_ipv4=tunnel_ip,
            uptime_seconds=uptime,
            exit_ip=exit_ip,
            last_error=last_error,
            log_tail=logs,
        )
