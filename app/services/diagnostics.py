from __future__ import annotations

from datetime import datetime, timezone
import os
import platform
import subprocess

from .migrations import (
    CURRENT_SCHEMA_VERSION,
    current_schema_version,
    migration_history,
)
from .routing import RoutingEngine
from .settings import DEFINITIONS, SettingsService
from .vpn_runtime import VPNRuntimeService
from .profile_intelligence import inspect_profile, display_provider, endpoint_label


def _run(args, timeout=5):
    try:
        result = subprocess.run(
            args,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return (result.stdout or result.stderr or "").strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return f"<error: {exc}>"


def _profile_config_text(profile):
    root = os.getenv("VPN_ROUTER_DATA_DIR", "/data")
    folder = "openvpn" if profile.vpn_type == "openvpn" else "wireguard"
    path = os.path.join(root, folder, profile.config_filename)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""

def _safe_env():
    # Deployment-level environment only; application settings are reported
    # separately without exposing secret values.
    names = ("TZ", "VPN_ROUTER_PORT", "VPN_ROUTER_BIND", "VPN_ROUTER_DATA_DIR")
    return {name: os.getenv(name) for name in names if os.getenv(name) is not None}


def build_diagnostics(
    db,
    VPNProfile,
    RoutingGroup,
    ClientAssignment,
    version,
    app=None,
):
    runtime = VPNRuntimeService()
    engine = RoutingEngine()

    profiles = db.session.execute(
        db.select(VPNProfile).order_by(VPNProfile.id.asc())
    ).scalars().all()
    groups = db.session.execute(
        db.select(RoutingGroup).order_by(RoutingGroup.id.asc())
    ).scalars().all()
    assignments = db.session.execute(
        db.select(ClientAssignment).order_by(ClientAssignment.id.asc())
    ).scalars().all()

    vpn_rows = []
    for profile in profiles:
        status = runtime.status(profile, include_probe=False)
        resilience = (
            app.extensions.get("vpn_resilience")
            if app is not None
            else None
        )
        retry = (
            resilience.public_state(profile.id)
            if resilience
            else None
        )

        intelligence = inspect_profile(profile, _profile_config_text(profile))
        display_state = status.state
        if (
            app is not None
            and profile.enabled
            and profile.connection_policy == "on_demand"
        ):
            manager = app.extensions.get("on_demand_vpn")
            demand = manager.public_state(profile.id) if manager else None
            if (
                demand
                and demand.get("standby")
                and status.state in ("disconnected", "failed")
            ):
                display_state = "standby"

        vpn_rows.append({
            "id": profile.id,
            "name": profile.name,
            "provider": display_provider(profile, intelligence),
            "detected_provider": intelligence.provider_detected,
            "endpoint": endpoint_label(intelligence),
            "transport": intelligence.transport,
            "protocol": intelligence.protocol,
            "region_hint": intelligence.region_hint,
            "provider_key": intelligence.provider_key,
            "provider_confidence": intelligence.provider_confidence,
            "provider_reason": intelligence.provider_reason,
            "type": profile.vpn_type,
            "enabled": bool(profile.enabled),
            "connection_policy": profile.connection_policy,
            "state": display_state,
            "interface": status.interface_name,
            "tunnel_ipv4": status.tunnel_ipv4,
            "uptime_seconds": status.uptime_seconds,
            "gateway": (
                runtime.route_gateway(profile)
                if profile.vpn_type == "openvpn"
                else None
            ),
            "last_error": status.last_error,
            "retry": retry,
            "dns": (
                app.extensions.get("observability").dns_state(profile.id)
                if app is not None and app.extensions.get("observability")
                else None
            ),
        })

    group_rows = []
    for group in groups:
        state = engine.inspect_group(group)
        group_rows.append({
            "id": group.id,
            "name": group.name,
            "target": group.target_label,
            "fallback_mode": group.fallback_mode,
            "dns_mode": group.dns_mode,
            "dns_target": group.effective_dns_target,
            "fwmark": group.mark_hex,
            "table_id": group.table_id,
            "state": state.state,
            "effective_exit": state.effective_exit,
            "detail": state.detail,
            "assigned_clients": sum(
                1 for a in assignments if a.routing_group_id == group.id
            ),
        })

    route_tables = {}
    for group in groups:
        if group.table_id:
            route_tables[str(group.table_id)] = _run([
                "ip", "-4", "route", "show",
                "table", str(group.table_id),
            ])

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "application_version": version,
        "system": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "safe_environment": _safe_env(),
        },
        "application_settings": {
            key: {
                "source": SettingsService(db, __import__("app.models", fromlist=["AppSetting"]).AppSetting).source(key),
                "value": (
                    "<configured secret>"
                    if definition.secret and SettingsService(db, __import__("app.models", fromlist=["AppSetting"]).AppSetting).raw(key)
                    else (
                        None if definition.secret
                        else str(SettingsService(db, __import__("app.models", fromlist=["AppSetting"]).AppSetting).raw(key))
                    )
                ),
            }
            for key, definition in DEFINITIONS.items()
        },
        "counts": {
            "vpn_profiles": len(profiles),
            "routing_groups": len(groups),
            "client_assignments": len(assignments),
        },
        "schema": {
            "current": current_schema_version(db),
            "supported": CURRENT_SCHEMA_VERSION,
            "history": migration_history(db),
        },
        "services": (
            __import__(
                "app.services.lifecycle",
                fromlist=["background_service_status"],
            ).background_service_status(app)
            if app is not None
            else []
        ),
        "vpns": vpn_rows,
        "routing_groups": group_rows,
        "network": {
            "ip_rules": _run(["ip", "-4", "rule", "show"]),
            "managed_route_tables": route_tables,
            "nft_vpn_router": _run([
                "nft", "list", "table",
                RoutingEngine.NFT_FAMILY,
                RoutingEngine.NFT_TABLE,
            ]),
            "wg0": _run(["ip", "-details", "link", "show", "wg0"]),
            "main_default": _run(["ip", "-4", "route", "show", "default"]),
        },
    }


def render_text(data):
    lines = [
        "VPN Router diagnostics",
        "=" * 72,
        f"Generated: {data['generated_at']}",
        f"Version: {data['application_version']}",
        "",
        "Counts",
        "-" * 72,
        f"VPN profiles: {data['counts']['vpn_profiles']}",
        f"Routing groups: {data['counts']['routing_groups']}",
        f"Client assignments: {data['counts']['client_assignments']}",
        "",
        "Database schema",
        "-" * 72,
        f"Current: v{data['schema']['current']}",
        f"Supported: v{data['schema']['supported']}",
        *[
            f"Applied v{row['version']} ({row['name']}) at {row['applied_at']}"
            for row in data['schema']['history']
        ],
        "",
        "Safe environment (secrets intentionally excluded)",
        "-" * 72,
    ]

    for key, value in sorted(data["system"]["safe_environment"].items()):
        lines.append(f"{key}={value}")

    lines.extend(["", "Application settings", "-" * 72])
    for key, item in sorted(data.get("application_settings", {}).items()):
        lines.append(
            f"{key}={item.get('value')} (source={item.get('source')})"
        )

    lines.extend(["", "Background services", "-" * 72])
    for service in data.get("services", []):
        details = ", ".join(
            f"{key}={value}"
            for key, value in service.items()
            if key not in ("name",)
        )
        lines.append(f"{service.get('name', 'unknown')}: {details}")

    lines.extend(["", "VPN profiles", "-" * 72])
    for vpn in data["vpns"]:
        lines.append(
            f"[{vpn['id']}] {vpn['name']} | {vpn['state']} | "
            f"enabled={vpn['enabled']} | policy={vpn.get('connection_policy')} | "
            f"provider={vpn.get('provider')} | "
            f"endpoint={vpn.get('endpoint')} | protocol={vpn.get('protocol')} | "
            f"transport={vpn.get('transport')} | region={vpn.get('region_hint')} | "
            f"provider_key={vpn.get('provider_key')} | "
            f"confidence={vpn.get('provider_confidence')} | "
            f"iface={vpn['interface']} | ip={vpn['tunnel_ipv4']} | "
            f"gateway={vpn['gateway']} | uptime={vpn['uptime_seconds']}"
        )
        if vpn["last_error"]:
            lines.append(f"  last_error={vpn['last_error']}")
        if vpn.get("dns"):
            dns = vpn["dns"]
            lines.append(
                "  dns="
                f"state:{dns.get('state')} "
                f"checked_at:{dns.get('checked_at')} "
                f"exit_asn:{dns.get('exit_asn')}"
            )
            for resolver in dns.get("resolvers") or []:
                lines.append(
                    "    resolver="
                    f"{resolver.get('ip')} "
                    f"country:{resolver.get('country')} "
                    f"asn:{resolver.get('asn')}"
                )
        if vpn.get("retry"):
            retry = vpn["retry"]
            lines.append(
                "  retry="
                f"failures:{retry.get('failures')} "
                f"retry_in:{retry.get('retry_in_seconds')} "
                f"gave_up:{retry.get('gave_up')} "
                f"last_success:{retry.get('last_success_at')}"
            )
            if retry.get("last_error"):
                lines.append(f"  retry_error={retry['last_error']}")

    lines.extend(["", "Routing groups", "-" * 72])
    for group in data["routing_groups"]:
        lines.append(
            f"[{group['id']}] {group['name']} | target={group['target']} | "
            f"effective={group['effective_exit']} | state={group['state']} | "
            f"fallback={group['fallback_mode']} | "
            f"dns={group.get('dns_mode')}:{group.get('dns_target')} | "
            f"mark={group['fwmark']} | table={group['table_id']} | "
            f"clients={group['assigned_clients']}"
        )
        lines.append(f"  {group['detail']}")

    lines.extend([
        "",
        "IPv4 policy rules",
        "-" * 72,
        data["network"]["ip_rules"] or "<none>",
        "",
        "Managed routing tables",
        "-" * 72,
    ])
    for table, content in data["network"]["managed_route_tables"].items():
        lines.append(f"table {table}:")
        lines.append(content or "<empty>")

    lines.extend([
        "",
        "nftables inet vpn_router",
        "-" * 72,
        data["network"]["nft_vpn_router"] or "<not present>",
        "",
        "wg0",
        "-" * 72,
        data["network"]["wg0"] or "<not present>",
        "",
        "Main IPv4 default",
        "-" * 72,
        data["network"]["main_default"] or "<none>",
        "",
        "NOTE: SECRET_KEY, admin credentials, WG-Easy credentials, VPN usernames/",
        "passwords and VPN configuration file contents are intentionally omitted.",
    ])

    return "\n".join(lines) + "\n"
