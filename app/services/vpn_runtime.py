from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import re
import subprocess
import tempfile
import time

from .secrets import decrypt_secret


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

    def log_tail(self, profile, lines=20):
        """Return the most recent runtime log lines for diagnostics/consumers."""
        return self._log_tail(profile, lines)

    def route_gateway(self, profile):
        """Return the runtime gateway when the VPN transport requires one."""
        if profile.vpn_type == "wireguard":
            return None
        return self._route_gateway_from_logs(self._log_tail(profile, 80))

    @staticmethod
    def _detect_last_error(lines, connected=False):
        fatal_tokens = (
            "AUTH_FAILED",
            "Options error",
            "TLS Error",
            "Connection refused",
            "Cannot resolve",
            "fatal error",
        )
        nonfatal_tokens = (
            "Network is unreachable",
            "sitnl_send",
        )
        for line in reversed(lines):
            lowered = line.lower()
            if any(token.lower() in lowered for token in fatal_tokens):
                return line[-500:]
            if not connected and any(token.lower() in lowered for token in nonfatal_tokens):
                return line[-500:]
        return None

    @staticmethod
    def _route_gateway_from_logs(lines):
        pattern = re.compile(r"(?:^|,)route-gateway\s+([^,\s]+)", re.IGNORECASE)
        for line in reversed(lines):
            if "PUSH_REPLY" not in line:
                continue
            match = pattern.search(line)
            if match:
                return match.group(1)
        return None


    @staticmethod
    def _wg_interface_values(content):
        """
        Extract wg-quick-only [Interface] values that `wg setconf` does not
        understand. Runtime networking is created explicitly so provider
        AllowedIPs can never replace the host/container default route.
        """
        section = None
        addresses = []
        dns = []
        mtu = None

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip().lower()
                continue

            if section != "interface" or "=" not in line:
                continue

            key, value = [part.strip() for part in line.split("=", 1)]
            lowered = key.lower()

            if lowered == "address":
                addresses.extend(
                    item.strip()
                    for item in value.split(",")
                    if item.strip()
                )
            elif lowered == "dns":
                dns.extend(
                    item.strip()
                    for item in value.split(",")
                    if item.strip()
                )
            elif lowered == "mtu":
                try:
                    mtu = int(value)
                except ValueError:
                    pass

        return {
            "addresses": addresses,
            "dns": dns,
            "mtu": mtu,
        }

    def _wg_latest_handshake(self, iface):
        result = self._run(
            ["wg", "show", iface, "latest-handshakes"],
            timeout=2,
        )
        if result.returncode != 0:
            return 0

        latest = 0
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                latest = max(latest, int(parts[1]))
            except ValueError:
                continue
        return latest

    def _wg_handshake_recent(self, iface, max_age=180):
        latest = self._wg_latest_handshake(iface)
        if latest <= 0:
            return False
        return (time.time() - latest) <= max_age

    def _wg_log(self, profile, message):
        path = self._log_path(profile)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(
                f"{datetime.now(timezone.utc).isoformat()} "
                f"{message}\n"
            )

    def _wg_start(self, profile):
        if self._interface_exists(self.interface_name(profile)):
            raise VPNRuntimeError("This WireGuard VPN profile is already running.")

        config_path = self._config_path(profile)
        if not config_path.exists():
            raise VPNRuntimeError(f"VPN config file is missing: {config_path}")

        content = config_path.read_text(
            encoding="utf-8",
            errors="replace",
        )
        values = self._wg_interface_values(content)
        ipv4_addresses = [
            address
            for address in values["addresses"]
            if ":" not in address
        ]

        if not ipv4_addresses:
            raise VPNRuntimeError(
                "WireGuard config has no IPv4 Address in [Interface]."
            )

        iface = self.interface_name(profile)
        self._remove_probe_route(profile)
        self._pid_path(profile).unlink(missing_ok=True)
        self._meta_path(profile).unlink(missing_ok=True)

        self._wg_log(
            profile,
            "=== WireGuard VPN Router start ===",
        )

        created = False
        stripped_path = None

        try:
            result = self._run(
                ["ip", "link", "add", iface, "type", "wireguard"],
                timeout=4,
            )
            if result.returncode != 0:
                raise VPNRuntimeError(
                    "Could not create WireGuard interface: "
                    + (result.stderr or result.stdout).strip()
                )
            created = True

            # `wg-quick strip` insists the input filename itself is a valid
            # WireGuard interface name followed by .conf. Uploaded provider
            # configs often have human-friendly names (spaces, country names,
            # punctuation), so never pass the persisted upload path directly.
            #
            # Copy the config to a sanitized runtime-only filename matching the
            # actual interface name, run wg-quick strip against that, then feed
            # the stripped output to wg setconf.
            sanitized_config_path = self.runtime_dir / f"{iface}.conf"
            sanitized_config_path.write_text(
                content,
                encoding="utf-8",
            )
            os.chmod(sanitized_config_path, 0o600)

            try:
                stripped = self._run(
                    ["wg-quick", "strip", str(sanitized_config_path)],
                    timeout=4,
                )
            finally:
                sanitized_config_path.unlink(missing_ok=True)

            if stripped.returncode != 0 or not stripped.stdout.strip():
                raise VPNRuntimeError(
                    "Could not parse WireGuard configuration with wg-quick: "
                    + (stripped.stderr or stripped.stdout).strip()
                )

            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                dir=self.runtime_dir,
                prefix=f"wg-{profile.id}-",
                suffix=".conf",
            ) as handle:
                handle.write(stripped.stdout)
                stripped_path = handle.name
            os.chmod(stripped_path, 0o600)

            result = self._run(
                ["wg", "setconf", iface, stripped_path],
                timeout=4,
            )
            if result.returncode != 0:
                raise VPNRuntimeError(
                    "Could not apply WireGuard configuration: "
                    + (result.stderr or result.stdout).strip()
                )

            for address in ipv4_addresses:
                result = self._run(
                    ["ip", "-4", "address", "add", address, "dev", iface],
                    timeout=3,
                )
                if result.returncode != 0:
                    raise VPNRuntimeError(
                        f"Could not assign WireGuard address {address}: "
                        + (result.stderr or result.stdout).strip()
                    )

            mtu = values["mtu"] or 1420
            result = self._run(
                ["ip", "link", "set", "dev", iface, "mtu", str(mtu), "up"],
                timeout=3,
            )
            if result.returncode != 0:
                raise VPNRuntimeError(
                    "Could not bring WireGuard interface up: "
                    + (result.stderr or result.stdout).strip()
                )

            tunnel_ip = self._interface_ipv4(iface)
            if not tunnel_ip:
                raise VPNRuntimeError(
                    "WireGuard interface came up without an IPv4 tunnel address."
                )

            self._write_meta(profile, {
                "started_at": datetime.now(timezone.utc).isoformat(),
                "interface_name": iface,
                "runtime": "wireguard",
                "dns": values["dns"],
                "mtu": mtu,
            })

            # Install only the isolated probe table/rule. This does NOT modify
            # the host's main/default route. A short probe generates real WG
            # traffic so status/connect-before-switch can wait for a handshake.
            self._ensure_probe_route(profile, iface, tunnel_ip)
            self._run(
                [
                    "ping",
                    "-c", "1",
                    "-W", "2",
                    "-I", tunnel_ip,
                    "1.1.1.1",
                ],
                timeout=3,
            )

            self._wg_log(
                profile,
                f"Interface {iface} created; waiting for WireGuard handshake.",
            )

        except Exception:
            self._remove_probe_route(profile)
            if created and self._interface_exists(iface):
                self._run(["ip", "link", "delete", iface], timeout=3)
            self._meta_path(profile).unlink(missing_ok=True)
            raise
        finally:
            if stripped_path:
                try:
                    Path(stripped_path).unlink(missing_ok=True)
                except OSError:
                    pass

    def _wg_stop(self, profile):
        iface = self.interface_name(profile)
        self._remove_probe_route(profile)

        if self._interface_exists(iface):
            result = self._run(
                ["ip", "link", "delete", iface],
                timeout=4,
            )
            if result.returncode != 0:
                raise VPNRuntimeError(
                    f"Could not delete WireGuard interface {iface}: "
                    + (result.stderr or result.stdout).strip()
                )

        if self._interface_exists(iface):
            raise VPNRuntimeError(
                f"WireGuard interface {iface} still exists after stop request."
            )

        self._pid_path(profile).unlink(missing_ok=True)
        self._meta_path(profile).unlink(missing_ok=True)

        try:
            self._wg_log(profile, f"WireGuard interface {iface} stopped.")
        except OSError:
            pass

    def _probe_ids(self, profile):
        value = 20000 + int(profile.id)
        return value, value

    def _ensure_probe_route(self, profile, iface, tunnel_ip):
        table, priority = self._probe_ids(profile)

        route_result = self._run(["ip", "-j", "-4", "route", "show", "dev", iface], 2)
        if route_result.returncode == 0:
            try:
                routes = json.loads(route_result.stdout)
            except json.JSONDecodeError:
                routes = []

            for route in routes:
                dst = route.get("dst")
                prefsrc = route.get("prefsrc")
                if dst and dst != "default":
                    args = ["ip", "route", "replace", dst, "dev", iface]
                    if prefsrc:
                        args.extend(["src", prefsrc])
                    args.extend(["table", str(table)])
                    self._run(args)
                    break

        gateway = self._route_gateway_from_logs(self._log_tail(profile, 80))
        if gateway:
            self._run([
                "ip", "route", "replace",
                "default", "via", gateway,
                "dev", iface,
                "table", str(table),
            ])
        else:
            self._run([
                "ip", "route", "replace",
                "default", "dev", iface,
                "table", str(table),
            ])

        rules = self._run(["ip", "-4", "rule", "show"], 2).stdout
        if f"from {tunnel_ip} lookup {table}" not in rules:
            self._run([
                "ip", "-4", "rule", "add",
                "priority", str(priority),
                "from", f"{tunnel_ip}/32",
                "lookup", str(table),
            ])

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


    def ensure_probe_route(self, profile, iface, tunnel_ip):
        """Public wrapper used by observability probes pinned to a VPN tunnel."""
        self._ensure_probe_route(profile, iface, tunnel_ip)

    def exit_ip(self, profile, iface=None, tunnel_ip=None):
        """
        Probe the public IPv4 exit for a connected profile.

        iface/tunnel_ip may be supplied by a caller that already has status,
        avoiding duplicate interface inspection.
        """
        if iface is None or tunnel_ip is None:
            status = self.status(profile, include_probe=False)
            if status.state != "connected" or not status.tunnel_ipv4:
                return None
            iface = status.interface_name
            tunnel_ip = status.tunnel_ipv4

        return self._exit_ip(profile, iface, tunnel_ip)

    def start(self, profile):
        if profile.vpn_type == "wireguard":
            return self._wg_start(profile)

        if profile.vpn_type != "openvpn":
            raise VPNRuntimeError(f"Unsupported VPN runtime type: {profile.vpn_type}")

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
            decrypted_password = decrypt_secret(profile.password) or ""
            auth_path.write_text(
                f"{profile.username or ''}\n{decrypted_password}\n",
                encoding="utf-8",
            )
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
            raise VPNRuntimeError(self._detect_last_error(logs, connected=False) or "OpenVPN exited during startup.")

    def stop(self, profile):
        if profile.vpn_type == "wireguard":
            return self._wg_stop(profile)

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

        if profile.vpn_type == "wireguard":
            alive = False
            if exists and tunnel_ip:
                state = (
                    "connected"
                    if self._wg_handshake_recent(iface)
                    else "connecting"
                )
            elif exists:
                state = "stale"
            else:
                state = "disconnected"
            last_error = None
        else:
            if alive and tunnel_ip:
                state = "connected"
            elif alive:
                state = "connecting"
            elif exists:
                state = "stale"
            else:
                state = "disconnected"

            last_error = self._detect_last_error(
                logs,
                connected=(state == "connected"),
            )

        if state == "disconnected" and last_error:
            if bool(getattr(profile, "enabled", False)):
                state = "failed"
            else:
                # A manually disabled/disconnected profile may have historical
                # OpenVPN errors in its log. They are not a current failure.
                last_error = None

        uptime = None
        meta = self._read_meta(profile)
        runtime_active = alive or (profile.vpn_type == "wireguard" and exists)
        if runtime_active and meta.get("started_at"):
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
