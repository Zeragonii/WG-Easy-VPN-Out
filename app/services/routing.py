from __future__ import annotations

from dataclasses import dataclass
import json
import subprocess

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

        gateway = self.vpn_runtime._route_gateway_from_logs(
            self.vpn_runtime._log_tail(profile, 80)
        )

        args = ["ip", "route", "replace", "default"]
        if gateway:
            args.extend(["via", gateway])
        args.extend(["dev", iface, "table", str(group.table_id)])
        self._must(args)

        return iface, gateway, "vpn"

    def _nft_script(self, groups, effective_ifaces):
        lines = [
            f"delete table {self.NFT_FAMILY} {self.NFT_TABLE}",
            f"table {self.NFT_FAMILY} {self.NFT_TABLE} {{",
        ]

        for group in groups:
            lines.append(
                f"  set group_{group.id}_v4 {{ type ipv4_addr; flags interval; }}"
            )

        lines.extend([
            "  chain prerouting {",
            "    type filter hook prerouting priority mangle; policy accept;",
        ])
        for group in groups:
            lines.append(
                f"    ip saddr @group_{group.id}_v4 meta mark set {group.mark_hex}"
            )
        lines.append("  }")

        lines.extend([
            "  chain postrouting {",
            "    type nat hook postrouting priority srcnat; policy accept;",
        ])
        for group in groups:
            iface, mode = effective_ifaces.get(group.id, ("", ""))
            if group.vpn_profile_id and mode == "vpn" and iface:
                safe_iface = iface.replace('"', "")
                lines.append(
                    f'    meta mark {group.mark_hex} oifname "{safe_iface}" masquerade'
                )
        lines.append("  }")
        lines.append("}")
        return "\n".join(lines) + "\n"

    def rebuild(self, db, RoutingGroup) -> None:
        groups = db.session.execute(
            db.select(RoutingGroup).order_by(RoutingGroup.id.asc())
        ).scalars().all()

        self.ensure_allocations(db, groups)

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
        script = self._nft_script(groups, effective_ifaces)
        # Strip the leading delete from the generated transaction because the
        # best-effort delete above has already run.
        script = "\n".join(script.splitlines()[1:]) + "\n"
        self._must(["nft", "-f", "-"], input_text=script)

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
