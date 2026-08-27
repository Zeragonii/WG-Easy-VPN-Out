from __future__ import annotations

from dataclasses import dataclass, asdict
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from .migrations import CURRENT_SCHEMA_VERSION, current_schema_version
from .routing import RoutingEngine
from .vpn_runtime import VPNRuntimeService


@dataclass(slots=True)
class CheckResult:
    key: str
    label: str
    status: str   # pass | warn | fail
    detail: str

    def to_dict(self):
        return asdict(self)


def _command_exists(name):
    return shutil.which(name) is not None


def _run(args, timeout=4):
    try:
        return subprocess.run(
            args,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _writable_directory(path):
    path.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.NamedTemporaryFile(dir=path, delete=True):
            pass
    except OSError:
        return False
    return True


def _expected_policy_rule(group):
    return (
        f"{10000 + group.id}:",
        f"fwmark 0x{0x100 + group.id:x}",
        f"lookup {10000 + group.id}",
    )


def run_preflight(
    app,
    db,
    VPNProfile,
    RoutingGroup,
    ClientAssignment,
):
    checks = []
    data_root = Path(os.getenv("VPN_ROUTER_DATA_DIR", "/data"))
    runtime = VPNRuntimeService()
    engine = RoutingEngine()

    # Database schema
    try:
        current = current_schema_version(db)
    except Exception as exc:
        checks.append(CheckResult(
            "schema",
            "Database schema",
            "fail",
            f"Could not read schema version: {exc}",
        ))
    else:
        if current == CURRENT_SCHEMA_VERSION:
            checks.append(CheckResult(
                "schema",
                "Database schema",
                "pass",
                f"Schema v{current} matches supported v{CURRENT_SCHEMA_VERSION}.",
            ))
        else:
            checks.append(CheckResult(
                "schema",
                "Database schema",
                "fail",
                f"Schema v{current}; application supports v{CURRENT_SCHEMA_VERSION}.",
            ))

    # Persistent storage
    required_dirs = [
        data_root,
        data_root / "openvpn",
        data_root / "wireguard",
        data_root / "backups",
        data_root / "runtime",
    ]
    unwritable = []
    for path in required_dirs:
        if not _writable_directory(path):
            unwritable.append(str(path))
    checks.append(CheckResult(
        "storage",
        "Persistent storage",
        "pass" if not unwritable else "fail",
        (
            "Required /data directories are writable."
            if not unwritable
            else "Not writable: " + ", ".join(unwritable)
        ),
    ))

    # Essential tools
    tools = ("ip", "nft", "openvpn", "wg", "curl", "ping", "dig")
    missing = [tool for tool in tools if not _command_exists(tool)]
    checks.append(CheckResult(
        "tools",
        "Networking tools",
        "pass" if not missing else "fail",
        (
            "All required networking tools are installed."
            if not missing
            else "Missing: " + ", ".join(missing)
        ),
    ))

    # Background managers
    services = app.extensions.get("background_services", [])
    stopped = []
    for service in services:
        try:
            status = service.status()
        except Exception as exc:
            stopped.append(f"{service.__class__.__name__} ({exc})")
            continue
        if not status.get("running"):
            stopped.append(status.get("name", service.__class__.__name__))
    checks.append(CheckResult(
        "background_services",
        "Background services",
        "pass" if services and not stopped else "fail",
        (
            f"{len(services)} background services are running."
            if services and not stopped
            else (
                "No background services registered."
                if not services
                else "Stopped/unhealthy: " + ", ".join(stopped)
            )
        ),
    ))

    profiles = db.session.execute(
        db.select(VPNProfile).order_by(VPNProfile.id.asc())
    ).scalars().all()
    groups = db.session.execute(
        db.select(RoutingGroup).order_by(RoutingGroup.id.asc())
    ).scalars().all()
    assignments = db.session.execute(
        db.select(ClientAssignment).order_by(ClientAssignment.id.asc())
    ).scalars().all()

    # VPN config presence
    missing_configs = []
    for profile in profiles:
        folder = "openvpn" if profile.vpn_type == "openvpn" else "wireguard"
        path = data_root / folder / profile.config_filename
        if not path.is_file():
            missing_configs.append(profile.name)
    checks.append(CheckResult(
        "vpn_configs",
        "VPN configuration files",
        "pass" if not missing_configs else "fail",
        (
            f"All {len(profiles)} profile config files are present."
            if not missing_configs
            else "Missing config files for: " + ", ".join(missing_configs)
        ),
    ))

    # Deterministic allocations
    bad_allocations = []
    for group in groups:
        expected_mark, expected_table, _ = engine.allocation(group.id)
        if group.fwmark != expected_mark or group.table_id != expected_table:
            bad_allocations.append(group.name)
    checks.append(CheckResult(
        "allocations",
        "Routing allocations",
        "pass" if not bad_allocations else "fail",
        (
            f"All {len(groups)} routing-group allocations are deterministic."
            if not bad_allocations
            else "Allocation mismatch: " + ", ".join(bad_allocations)
        ),
    ))

    # Policy rules for configured groups
    rule_result = _run(["ip", "-4", "rule", "show"])
    if rule_result is None or rule_result.returncode != 0:
        checks.append(CheckResult(
            "policy_rules",
            "Policy rules",
            "fail",
            "Could not inspect IPv4 policy rules.",
        ))
    else:
        output = rule_result.stdout
        missing_rules = []
        for group in groups:
            parts = _expected_policy_rule(group)
            if not all(part in output for part in parts):
                missing_rules.append(group.name)
        checks.append(CheckResult(
            "policy_rules",
            "Policy rules",
            "pass" if not missing_rules else "fail",
            (
                f"Expected policy rules exist for all {len(groups)} routing groups."
                if not missing_rules
                else "Missing/inconsistent rules: " + ", ".join(missing_rules)
            ),
        ))

    # nft table
    nft = _run(["nft", "list", "table", "inet", "vpn_router"])
    nft_ok = bool(nft and nft.returncode == 0)
    checks.append(CheckResult(
        "nftables",
        "nftables policy table",
        "pass" if nft_ok else "fail",
        (
            "inet vpn_router is present."
            if nft_ok
            else "inet vpn_router could not be read."
        ),
    ))

    # Enabled VPN health
    enabled = [p for p in profiles if p.enabled and p.vpn_type in ("openvpn", "wireguard")]
    unhealthy = []
    for profile in enabled:
        status = runtime.status(profile, include_probe=False)
        if status.state != "connected":
            unhealthy.append(f"{profile.name} ({status.state})")
    checks.append(CheckResult(
        "enabled_vpns",
        "Enabled VPN profiles",
        "pass" if not unhealthy else "warn",
        (
            f"All {len(enabled)} enabled VPN profiles are connected."
            if not unhealthy
            else "Not currently connected: " + ", ".join(unhealthy)
        ),
    ))

    # Assignment integrity at runtime
    group_ids = {g.id for g in groups}
    orphaned = [
        a.client_name
        for a in assignments
        if a.routing_group_id not in group_ids
    ]
    checks.append(CheckResult(
        "assignments",
        "Client assignments",
        "pass" if not orphaned else "fail",
        (
            f"All {len(assignments)} client assignments reference valid groups."
            if not orphaned
            else "Orphaned assignments: " + ", ".join(orphaned)
        ),
    ))

    # Secret-key hygiene is advisory only.
    secret = os.getenv("SECRET_KEY", "")
    weak = (
        not secret
        or secret == "CHANGE-ME-TO-A-LONG-RANDOM-STRING"
        or len(secret) < 32
    )
    checks.append(CheckResult(
        "secret_key",
        "SECRET_KEY",
        "warn" if weak else "pass",
        (
            "SECRET_KEY is present and at least 32 characters."
            if not weak
            else "SECRET_KEY is missing, default-looking, or shorter than 32 characters."
        ),
    ))

    summary = {
        "pass": sum(1 for c in checks if c.status == "pass"),
        "warn": sum(1 for c in checks if c.status == "warn"),
        "fail": sum(1 for c in checks if c.status == "fail"),
    }
    ready = summary["fail"] == 0

    return {
        "ready": ready,
        "summary": summary,
        "checks": [check.to_dict() for check in checks],
    }
