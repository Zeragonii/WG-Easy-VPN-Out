from __future__ import annotations

from dataclasses import dataclass
import json
import ipaddress
import subprocess
import threading
import time

from .vpn_runtime import VPNRuntimeService


class RoutingEngineError(RuntimeError):
    pass


@dataclass(slots=True)
class GroupRuntime:
    state: str
    effective_exit: str
    detail: str


class RoutingEngine:
    NFT_FAMILY = "inet"
    NFT_TABLE = "vpn_router"

    # Auto-detected public IPv4 is process-cached so the 3-second routing
    # reconciler never turns into a 3-second external HTTP poller.
    _WAN_IP_CACHE_TTL = 600.0
    _wan_ip_cache = None
    _wan_ip_cache_at = 0.0
    _wan_ip_cache_error = None
    _wan_ip_lock = threading.Lock()

    def __init__(self):
        self.vpn_runtime = VPNRuntimeService()

    @staticmethod
    def _run(args, input_text=None, timeout=8):
        return subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    def _must(self, args, input_text=None):
        result = self._run(args, input_text=input_text)
        if result.returncode != 0:
            raise RoutingEngineError(
                f"{' '.join(args)} failed: "
                f"{(result.stderr or result.stdout).strip()}"
            )
        return result

    @staticmethod
    def allocation(group_id: int) -> tuple[int, int, int]:
        fwmark = 0x100 + int(group_id)
        table_id = 10000 + int(group_id)
        priority = 10000 + int(group_id)
        return fwmark, table_id, priority

    def ensure_allocations(self, db, groups) -> None:
        changed = False
        for group in groups:
            fwmark, table_id, _ = self.allocation(group.id)
            if group.fwmark != fwmark:
                group.fwmark = fwmark
                changed = True
            if group.table_id != table_id:
                group.table_id = table_id
                changed = True
        if changed:
            db.session.commit()

    def _main_default(self):
        result = self._must(["ip", "-j", "-4", "route", "show", "default"])
        routes = json.loads(result.stdout or "[]")
        if not routes:
            raise RoutingEngineError("Host has no IPv4 default route.")
        route = routes[0]
        dev = route.get("dev")
        gateway = route.get("gateway")
        if not dev:
            raise RoutingEngineError("Could not determine host WAN interface.")
        return dev, gateway

    @classmethod
    def _detect_public_wan_ip(cls, force=False):
        now = time.monotonic()
        with cls._wan_ip_lock:
            if (
                not force
                and cls._wan_ip_cache
                and (now - cls._wan_ip_cache_at) < cls._WAN_IP_CACHE_TTL
            ):
                return cls._wan_ip_cache, "auto", None

            result = subprocess.run(
                [
                    "curl",
                    "--silent",
                    "--show-error",
                    "--fail",
                    "--max-time",
                    "5",
                    "-4",
                    "https://api.ipify.org",
                ],
                text=True,
                capture_output=True,
                timeout=7,
                check=False,
            )
            if result.returncode != 0:
                cls._wan_ip_cache_error = (
                    result.stderr or result.stdout or "public IPv4 lookup failed"
                ).strip()[-300:]
                return None, "auto", cls._wan_ip_cache_error

            candidate = (result.stdout or "").strip()
            try:
                parsed = str(ipaddress.IPv4Address(candidate))
            except ipaddress.AddressValueError:
                cls._wan_ip_cache_error = (
                    f"Public IPv4 lookup returned invalid value: {candidate!r}"
                )
                return None, "auto", cls._wan_ip_cache_error

            cls._wan_ip_cache = parsed
            cls._wan_ip_cache_at = now
            cls._wan_ip_cache_error = None
            return parsed, "auto", None

    def hairpin_state(self, db, refresh=False):
        from ..models import AppSetting
        from .settings import SettingsService

        settings = SettingsService(db, AppSetting)
        enabled = bool(settings.get("wan_hairpin_enabled"))
        manual = str(settings.get("wan_hairpin_public_ip") or "").strip()
        iface = None
        gateway = None

        try:
            iface, gateway = self._main_default()
        except RoutingEngineError as exc:
            return {
                "enabled": enabled,
                "public_ip": manual or None,
                "source": "manual" if manual else "auto",
                "interface": None,
                "gateway": None,
                "ready": False,
                "error": str(exc),
            }

        if not enabled:
            return {
                "enabled": False,
                "public_ip": manual or None,
                "source": "manual" if manual else "auto",
                "interface": iface,
                "gateway": gateway,
                "ready": False,
                "error": None,
            }

        if manual:
            return {
                "enabled": True,
                "public_ip": manual,
                "source": "manual",
                "interface": iface,
                "gateway": gateway,
                "ready": True,
                "error": None,
            }

        public_ip, source, error = self._detect_public_wan_ip(force=refresh)
        return {
            "enabled": True,
            "public_ip": public_ip,
            "source": source,
            "interface": iface,
            "gateway": gateway,
            "ready": bool(public_ip and iface),
            "error": error,
        }

    def _connected_routes(self, iface: str):
        result = self._must(["ip", "-j", "-4", "route", "show", "dev", iface])
        routes = json.loads(result.stdout or "[]")
        return [
            r for r in routes
            if r.get("dst") and r.get("dst") != "default"
        ]

    def _flush_group_rule(self, priority: int, table_id: int) -> None:
        # Delete by priority repeatedly in case a previous failed rebuild left
        # duplicates. ip returns non-zero once none remain, which is fine.
        for _ in range(4):
            result = self._run([
                "ip", "-4", "rule", "del",
                "priority", str(priority),
            ])
            if result.returncode != 0:
                break
        self._run(["ip", "route", "flush", "table", str(table_id)])

    @classmethod
    def _managed_rule_matches(cls, rule) -> bool:
        """
        Recognise only rules created by this application.

        A VPN Router group rule has:
          priority/table = 10000 + group_id
          fwmark         = 0x100 + group_id

        Requiring all three relationships avoids deleting unrelated host rules
        that merely happen to use a nearby priority.
        """
        try:
            priority = int(rule.get("priority"))
            table = int(rule.get("table"))
            fwmark_raw = rule.get("fwmark")
            fwmark = (
                int(fwmark_raw, 0)
                if isinstance(fwmark_raw, str)
                else int(fwmark_raw)
            )
        except (TypeError, ValueError):
            return False

        group_id = priority - 10000
        if group_id <= 0:
            return False

        expected_mark, expected_table, expected_priority = cls.allocation(group_id)
        return (
            priority == expected_priority
            and table == expected_table
            and fwmark == expected_mark
        )

    def cleanup_stale_policy_state(self, active_group_ids) -> list[int]:
        """
        Remove VPN Router policy rules/tables belonging to groups that no
        longer exist in the database. Returns the cleaned group IDs.
        """
        active = {int(group_id) for group_id in active_group_ids}
        result = self._run(["ip", "-j", "-4", "rule", "show"], timeout=4)

        if result.returncode != 0:
            return []

        try:
            rules = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return []

        cleaned = []
        for rule in rules:
            if not self._managed_rule_matches(rule):
                continue

            priority = int(rule["priority"])
            group_id = priority - 10000
            if group_id in active:
                continue

            _, table_id, _ = self.allocation(group_id)
            self._flush_group_rule(priority, table_id)
            cleaned.append(group_id)

        return sorted(set(cleaned))

    def remove_group_state(self, group_id: int) -> None:
        """Explicitly remove the policy rule/table allocated to one group."""
        _, table_id, priority = self.allocation(group_id)
        self._flush_group_rule(priority, table_id)

    def _mirror_connected(self, iface: str, table_id: int) -> None:
        for route in self._connected_routes(iface):
            dst = route["dst"]
            args = ["ip", "route", "replace", dst, "dev", iface]
            if route.get("prefsrc"):
                args.extend(["src", route["prefsrc"]])
            args.extend(["table", str(table_id)])
            self._must(args)

    def _build_wan_table(self, table_id: int) -> tuple[str, str | None]:
        iface, gateway = self._main_default()
        self._mirror_connected(iface, table_id)

        args = ["ip", "route", "replace", "default"]
        if gateway:
            args.extend(["via", gateway])
        args.extend(["dev", iface, "table", str(table_id)])
        self._must(args)
        return iface, gateway

    def _build_vpn_table(self, group) -> tuple[str, str | None, str]:
        profile = group.vpn_profile
        status = self.vpn_runtime.status(profile, include_probe=False)

        if status.state != "connected" or not status.tunnel_ipv4:
            if group.fallback_mode == "wan":
                iface, gateway = self._build_wan_table(group.table_id)
                return iface, gateway, "wan-fallback"

            self._must([
                "ip", "route", "replace",
                "blackhole", "default",
                "table", str(group.table_id),
            ])
            return "", None, "blocked"

        iface = status.interface_name
        self._mirror_connected(iface, group.table_id)

        gateway = self.vpn_runtime.route_gateway(profile)

        args = ["ip", "route", "replace", "default"]
        if gateway:
            args.extend(["via", gateway])
        args.extend(["dev", iface, "table", str(group.table_id)])
        self._must(args)

        return iface, gateway, "vpn"

    def _nft_script(self, groups, effective_ifaces, assignments_by_group, hairpin=None):
        lines = [
            f"delete table {self.NFT_FAMILY} {self.NFT_TABLE}",
            f"table {self.NFT_FAMILY} {self.NFT_TABLE} {{",
        ]

        for group in groups:
            addresses = assignments_by_group.get(group.id, [])
            if addresses:
                elements = ", ".join(addresses)
                lines.append(
                    f"  set group_{group.id}_v4 {{ "
                    f"type ipv4_addr; flags interval; elements = {{ {elements} }}; }}"
                )
            else:
                lines.append(
                    f"  set group_{group.id}_v4 {{ type ipv4_addr; flags interval; }}"
                )

        # Mark forced classic-DNS traffic before the RFC1918 bypass. This is
        # important for PIA DNS (10.0.0.242), which intentionally lives inside
        # 10/8 even though that range is otherwise treated as local/private.
        lines.extend([
            "  chain prerouting {",
            "    type filter hook prerouting priority mangle; policy accept;",
        ])

        for group in groups:
            target = group.effective_dns_target
            if group.vpn_profile_id and target:
                lines.append(
                    f"    ip saddr @group_{group.id}_v4 udp dport 53 "
                    f"meta mark set {group.mark_hex}"
                )
                lines.append(
                    f"    ip saddr @group_{group.id}_v4 tcp dport 53 "
                    f"meta mark set {group.mark_hex}"
                )

        lines.extend([
            "    ip daddr 127.0.0.0/8 return",
            "    ip daddr 10.0.0.0/8 return",
            "    ip daddr 172.16.0.0/12 return",
            "    ip daddr 192.168.0.0/16 return",
            "    ip daddr 169.254.0.0/16 return",
        ])

        for group in groups:
            lines.append(
                f"    ip saddr @group_{group.id}_v4 meta mark set {group.mark_hex}"
            )
        lines.append("  }")

        # Destination NAT transparently redirects classic UDP/TCP DNS from
        # assigned WG-Easy clients to the routing group's selected resolver.
        # The fwmark above ensures the rewritten destination follows the same
        # policy table / VPN path as the rest of the group traffic.
        lines.extend([
            "  chain dns_redirect {",
            "    type nat hook prerouting priority dstnat; policy accept;",
        ])
        for group in groups:
            target = group.effective_dns_target
            iface, mode = effective_ifaces.get(group.id, ("", ""))
            # Only install forced provider/custom DNS while the VPN is the
            # effective path. If the group is blocked, its policy table remains
            # blackholed. If it is in WAN fallback, leave DNS untouched rather
            # than silently pretending provider DNS is still active.
            if group.vpn_profile_id and target and mode == "vpn":
                lines.append(
                    f"    ip saddr @group_{group.id}_v4 udp dport 53 "
                    f"dnat to {target}"
                )
                lines.append(
                    f"    ip saddr @group_{group.id}_v4 tcp dport 53 "
                    f"dnat to {target}"
                )
        lines.append("  }")

        lines.extend([
            "  chain postrouting {",
            "    type nat hook postrouting priority srcnat; policy accept;",
        ])
        for group in groups:
            iface, mode = effective_ifaces.get(group.id, ("", ""))

            # Targeted hairpin compatibility for routed WG clients whose
            # effective egress is WAN. Only traffic to this site's own public
            # IPv4 is SNATed; ordinary WAN traffic retains the original
            # 192.168.3.x client source address.
            if (
                hairpin
                and hairpin.get("ready")
                and mode in ("wan", "wan-fallback")
                and iface
            ):
                safe_iface = iface.replace('"', "")
                public_ip = hairpin["public_ip"]
                lines.append(
                    f'    ip saddr @group_{group.id}_v4 '
                    f'ip daddr {public_ip} '
                    f'oifname "{safe_iface}" masquerade'
                )

            if group.vpn_profile_id and mode == "vpn" and iface:
                safe_iface = iface.replace('"', "")
                lines.append(
                    f'    meta mark {group.mark_hex} oifname "{safe_iface}" masquerade'
                )
        lines.append("  }")
        lines.append("}")
        return "\n".join(lines) + "\n"

    def rebuild(self, db, RoutingGroup) -> None:
        from .effective_assignments import effective_assignments

        groups = db.session.execute(
            db.select(RoutingGroup).order_by(RoutingGroup.id.asc())
        ).scalars().all()

        self.ensure_allocations(db, groups)

        assignments = effective_assignments(db)

        assignments_by_group = {}
        valid_group_ids = {group.id for group in groups}

        # Clean policy rules/tables left behind by deleted groups before
        # rebuilding the currently configured set.
        self.cleanup_stale_policy_state(valid_group_ids)

        for assignment in assignments:
            if assignment.routing_group_id not in valid_group_ids:
                continue
            try:
                address = str(ipaddress.IPv4Address(assignment.ipv4_address))
            except ipaddress.AddressValueError:
                continue
            assignments_by_group.setdefault(
                assignment.routing_group_id,
                [],
            ).append(address)

        # Clean our ip rules/tables first.
        for group in groups:
            _, table_id, priority = self.allocation(group.id)
            self._flush_group_rule(priority, table_id)

        effective_ifaces = {}

        # Build route tables and matching fwmark rules.
        for group in groups:
            fwmark, table_id, priority = self.allocation(group.id)

            if group.vpn_profile is None:
                iface, _ = self._build_wan_table(table_id)
                effective_ifaces[group.id] = (iface, "wan")
            else:
                iface, _, mode = self._build_vpn_table(group)
                effective_ifaces[group.id] = (iface, mode)

            self._must([
                "ip", "-4", "rule", "add",
                "priority", str(priority),
                "fwmark", hex(fwmark),
                "lookup", str(table_id),
            ])

        # nft "delete table" fails if the table does not exist. Remove it
        # separately, ignoring that error, then atomically load a fresh table.
        self._run(["nft", "delete", "table", self.NFT_FAMILY, self.NFT_TABLE])
        hairpin = self.hairpin_state(db)
        script = self._nft_script(
            groups,
            effective_ifaces,
            assignments_by_group,
            hairpin=hairpin,
        )
        # Strip the leading delete from the generated transaction because the
        # best-effort delete above has already run.
        script = "\n".join(script.splitlines()[1:]) + "\n"
        self._must(["nft", "-f", "-"], input_text=script)

    def apply_assignment_sets(self, db, RoutingGroup) -> None:
        """
        Refresh only nftables set membership without rebuilding route tables.
        Used for client dropdown changes and WG-Easy IP changes.
        """
        from .effective_assignments import effective_assignments

        groups = db.session.execute(
            db.select(RoutingGroup).order_by(RoutingGroup.id.asc())
        ).scalars().all()

        assignments = effective_assignments(db)

        by_group = {group.id: [] for group in groups}

        for assignment in assignments:
            if assignment.routing_group_id not in by_group:
                continue
            try:
                address = str(ipaddress.IPv4Address(assignment.ipv4_address))
            except ipaddress.AddressValueError:
                continue
            by_group[assignment.routing_group_id].append(address)

        for group in groups:
            set_name = f"group_{group.id}_v4"

            # The set should already exist after normal engine rebuild. If it
            # doesn't, fall back to a complete rebuild.
            result = self._run([
                "nft", "list", "set",
                self.NFT_FAMILY,
                self.NFT_TABLE,
                set_name,
            ])
            if result.returncode != 0:
                self.rebuild(db, RoutingGroup)
                return

            self._must([
                "nft", "flush", "set",
                self.NFT_FAMILY,
                self.NFT_TABLE,
                set_name,
            ])

            addresses = sorted(set(by_group[group.id]))
            if addresses:
                element_text = ", ".join(addresses)
                self._must([
                    "nft", "add", "element",
                    self.NFT_FAMILY,
                    self.NFT_TABLE,
                    set_name,
                    "{", element_text, "}",
                ])

    def inspect_group(self, group) -> GroupRuntime:
        if group.vpn_profile is None:
            return GroupRuntime(
                state="ready",
                effective_exit="Default WAN",
                detail="WAN routing table ready",
            )

        status = self.vpn_runtime.status(group.vpn_profile, include_probe=False)
        if status.state == "connected":
            return GroupRuntime(
                state="ready",
                effective_exit=group.vpn_profile.name,
                detail=f"VPN via {status.interface_name}",
            )

        if group.fallback_mode == "wan":
            return GroupRuntime(
                state="fallback",
                effective_exit="Default WAN",
                detail=f"{group.vpn_profile.name} unavailable; WAN fallback",
            )

        return GroupRuntime(
            state="blocked",
            effective_exit="Blocked",
            detail=f"{group.vpn_profile.name} unavailable; kill-switch active",
        )


def rebuild_routing(db, RoutingGroup) -> None:
    RoutingEngine().rebuild(db, RoutingGroup)
