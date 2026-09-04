from __future__ import annotations

import io
import ipaddress
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
import zipfile

from .migrations import CURRENT_SCHEMA_VERSION
from .vpn_runtime import VPNRuntimeService


BACKUP_FORMAT = 1
MAX_BACKUP_BYTES = 16 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 256
MAX_ENTITY_ROWS = 10000
SAFE_CONFIG_NAME = re.compile(r"^[A-Za-z0-9._-]{1,255}$")


class BackupError(RuntimeError):
    pass


def _now():
    return datetime.now(timezone.utc)


def _iso(value):
    return value.isoformat() if value else None


def _data_root():
    root = Path(os.getenv("VPN_ROUTER_DATA_DIR", "/data"))
    root.mkdir(parents=True, exist_ok=True)
    return root


def export_backup(db, VPNProfile, RoutingGroup, ClientAssignment, version, include_secret=False, AppSetting=None, ClientRouteOverride=None):
    profiles = db.session.execute(
        db.select(VPNProfile).order_by(VPNProfile.id.asc())
    ).scalars().all()
    groups = db.session.execute(
        db.select(RoutingGroup).order_by(RoutingGroup.id.asc())
    ).scalars().all()
    assignments = db.session.execute(
        db.select(ClientAssignment).order_by(ClientAssignment.id.asc())
    ).scalars().all()
    overrides = []
    if ClientRouteOverride is not None:
        overrides = db.session.execute(
            db.select(ClientRouteOverride).order_by(ClientRouteOverride.id.asc())
        ).scalars().all()

    app_settings = []
    if AppSetting is not None:
        rows = db.session.execute(db.select(AppSetting).order_by(AppSetting.key.asc())).scalars().all()
        app_settings = [
            {"key": row.key, "value": row.value, "is_secret": bool(row.is_secret)}
            for row in rows
        ]

    payload = {
        "app_settings": app_settings,
        "vpn_profiles": [{
            "id": p.id,
            "name": p.name,
            "provider": p.provider,
            "vpn_type": p.vpn_type,
            "config_filename": p.config_filename,
            "username": p.username,
            "password": p.password,
            "enabled": bool(p.enabled),
            "connection_policy": p.connection_policy,
            "detected_country_code": p.detected_country_code,
            "detected_country_name": p.detected_country_name,
            "detected_region": p.detected_region,
            "detected_city": p.detected_city,
            "detected_location_source": p.detected_location_source,
            "detected_location_ip": p.detected_location_ip,
            "manual_country": p.manual_country,
            "manual_region": p.manual_region,
            "manual_city": p.manual_city,
            "favorite": bool(p.favorite),
            "tags": p.tags,
            "created_at": _iso(p.created_at),
            "updated_at": _iso(p.updated_at),
        } for p in profiles],
        "routing_groups": [{
            "id": g.id,
            "name": g.name,
            "vpn_profile_id": g.vpn_profile_id,
            "fallback_mode": g.fallback_mode,
            "dns_mode": g.dns_mode,
            "dns_target": g.dns_target,
            "fwmark": g.fwmark,
            "table_id": g.table_id,
            "created_at": _iso(g.created_at),
            "updated_at": _iso(g.updated_at),
        } for g in groups],
        "client_assignments": [{
            "id": a.id,
            "external_id": a.external_id,
            "client_name": a.client_name,
            "ipv4_address": a.ipv4_address,
            "routing_group_id": a.routing_group_id,
            "created_at": _iso(a.created_at),
            "updated_at": _iso(a.updated_at),
        } for a in assignments],
        "client_route_overrides": [{
            "id": o.id,
            "external_id": o.external_id,
            "client_name": o.client_name,
            "ipv4_address": o.ipv4_address,
            "routing_group_id": o.routing_group_id,
            "expires_at": _iso(o.expires_at),
            "created_at": _iso(o.created_at),
        } for o in overrides],
    }

    manifest = {
        "format": BACKUP_FORMAT,
        "application": "WG-Easy-VPN-Out",
        "application_version": version,
        "schema_version": CURRENT_SCHEMA_VERSION,
        "created_at": _now().isoformat(),
        "secret_key_included": bool(include_secret),
        "contents": {
            "app_settings": len(app_settings),
            "vpn_profiles": len(profiles),
            "routing_groups": len(groups),
            "client_assignments": len(assignments),
            "client_route_overrides": len(overrides),
            "vpn_config_files": 0,
        },
    }

    buffer = io.BytesIO()
    root = _data_root()

    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for profile in profiles:
            folder = "openvpn" if profile.vpn_type == "openvpn" else "wireguard"
            source = root / folder / profile.config_filename
            if source.is_file():
                archive.write(
                    source,
                    f"configs/{folder}/{profile.config_filename}",
                )
                manifest["contents"]["vpn_config_files"] += 1

        if include_secret:
            secret = os.getenv("SECRET_KEY", "")
            if not secret:
                raise BackupError("SECRET_KEY is not available to include.")
            archive.writestr("secret-key.txt", secret)

        archive.writestr(
            "data.json",
            json.dumps(payload, indent=2, ensure_ascii=False),
        )
        archive.writestr(
            "manifest.json",
            json.dumps(manifest, indent=2),
        )

    buffer.seek(0)
    stamp = _now().strftime("%Y%m%d-%H%M%S")
    return buffer, f"vpn-router-backup-{stamp}.zip", manifest



def _require_int(value, label, minimum=1):
    if isinstance(value, bool):
        raise BackupError(f"{label} must be an integer.")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise BackupError(f"{label} must be an integer.") from exc
    if parsed < minimum:
        raise BackupError(f"{label} must be at least {minimum}.")
    return parsed


def _require_text(value, label, max_length, allow_empty=False):
    if value is None:
        if allow_empty:
            return None
        raise BackupError(f"{label} is required.")
    if not isinstance(value, str):
        raise BackupError(f"{label} must be text.")
    value = value.strip()
    if not value and not allow_empty:
        raise BackupError(f"{label} cannot be empty.")
    if len(value) > max_length:
        raise BackupError(f"{label} exceeds {max_length} characters.")
    return value or None


def _validate_backup_data(data, configs):
    data.setdefault("app_settings", [])
    data.setdefault("client_route_overrides", [])
    for key in ("app_settings", "vpn_profiles", "routing_groups", "client_assignments", "client_route_overrides"):
        rows = data.get(key)
        if not isinstance(rows, list):
            raise BackupError(f"Backup data is missing '{key}'.")
        if len(rows) > MAX_ENTITY_ROWS:
            raise BackupError(f"Backup contains too many {key} rows.")

    profiles = data["vpn_profiles"]
    groups = data["routing_groups"]
    assignments = data["client_assignments"]
    overrides = data["client_route_overrides"]

    profile_ids = set()
    profile_names = set()
    config_keys = set()

    for index, row in enumerate(profiles, 1):
        if not isinstance(row, dict):
            raise BackupError(f"VPN profile row {index} is invalid.")

        profile_id = _require_int(row.get("id"), f"VPN profile {index} ID")
        name = _require_text(row.get("name"), f"VPN profile {index} name", 120)
        vpn_type = row.get("vpn_type")
        if vpn_type not in ("openvpn", "wireguard"):
            raise BackupError(
                f"VPN profile '{name}' has unsupported type {vpn_type!r}."
            )

        filename = _require_text(
            row.get("config_filename"),
            f"VPN profile '{name}' config filename",
            255,
        )
        if (
            not SAFE_CONFIG_NAME.fullmatch(filename)
            or filename in (".", "..")
            or "/" in filename
            or "\\" in filename
        ):
            raise BackupError(
                f"VPN profile '{name}' has an unsafe config filename."
            )

        provider = row.get("provider")
        if provider is not None:
            _require_text(provider, f"VPN profile '{name}' provider", 120, True)
        username = row.get("username")
        if username is not None:
            _require_text(username, f"VPN profile '{name}' username", 255, True)
        password = row.get("password")
        if password is not None and not isinstance(password, str):
            raise BackupError(
                f"VPN profile '{name}' encrypted password is invalid."
            )
        if len(password or "") > 4096:
            raise BackupError(
                f"VPN profile '{name}' encrypted password is unexpectedly long."
            )
        if not isinstance(row.get("enabled", False), bool):
            raise BackupError(
                f"VPN profile '{name}' enabled flag must be boolean."
            )
        policy = row.get("connection_policy", "always")
        if policy not in ("always", "on_demand"):
            raise BackupError(
                f"VPN profile '{name}' has invalid connection policy."
            )
        if not isinstance(row.get("favorite", False), bool):
            raise BackupError(
                f"VPN profile '{name}' favourite flag must be boolean."
            )
        tags = row.get("tags")
        if tags is not None:
            _require_text(tags, f"VPN profile '{name}' tags", 1000, True)

        for field, limit in (
            ("detected_country_code", 8),
            ("detected_country_name", 120),
            ("detected_region", 120),
            ("detected_city", 120),
            ("detected_location_source", 32),
            ("detected_location_ip", 64),
            ("manual_country", 120),
            ("manual_region", 120),
            ("manual_city", 120),
        ):
            value = row.get(field)
            if value is not None:
                _require_text(
                    value,
                    f"VPN profile '{name}' {field}",
                    limit,
                    True,
                )

        folded = name.casefold()
        if profile_id in profile_ids:
            raise BackupError("Backup contains duplicate VPN profile IDs.")
        if folded in profile_names:
            raise BackupError("Backup contains duplicate VPN profile names.")
        profile_ids.add(profile_id)
        profile_names.add(folded)

        folder = "openvpn" if vpn_type == "openvpn" else "wireguard"
        key = (folder, filename)
        if key in config_keys:
            raise BackupError(
                f"Multiple VPN profiles reference the same config file: {filename}"
            )
        config_keys.add(key)
        if key not in configs:
            raise BackupError(
                f"Backup is missing config for VPN profile '{name}'."
            )

    group_ids = set()
    group_names = set()
    fwmarks = set()
    table_ids = set()

    for index, row in enumerate(groups, 1):
        if not isinstance(row, dict):
            raise BackupError(f"Routing group row {index} is invalid.")

        group_id = _require_int(row.get("id"), f"Routing group {index} ID")
        name = _require_text(row.get("name"), f"Routing group {index} name", 120)
        fallback = row.get("fallback_mode", "block")
        if fallback not in ("block", "wan"):
            raise BackupError(
                f"Routing group '{name}' has invalid fallback mode."
            )

        dns_mode = row.get("dns_mode", "inherit")
        if dns_mode not in ("inherit", "pia", "custom"):
            raise BackupError(
                f"Routing group '{name}' has invalid DNS mode."
            )
        dns_target = row.get("dns_target")
        if dns_mode == "custom":
            try:
                ipaddress.IPv4Address(dns_target)
            except (ipaddress.AddressValueError, TypeError) as exc:
                raise BackupError(
                    f"Routing group '{name}' has invalid custom DNS."
                ) from exc

        target = row.get("vpn_profile_id")
        if target is not None:
            target = _require_int(
                target,
                f"Routing group '{name}' VPN profile ID",
            )
            if target not in profile_ids:
                raise BackupError(
                    f"Routing group '{name}' references a missing VPN profile."
                )

        fwmark = _require_int(row.get("fwmark"), f"Routing group '{name}' fwmark")
        table_id = _require_int(
            row.get("table_id"),
            f"Routing group '{name}' table ID",
        )
        expected_mark = 0x100 + group_id
        expected_table = 10000 + group_id
        if fwmark != expected_mark or table_id != expected_table:
            raise BackupError(
                f"Routing group '{name}' has inconsistent policy allocation."
            )

        folded = name.casefold()
        if group_id in group_ids:
            raise BackupError("Backup contains duplicate routing group IDs.")
        if folded in group_names:
            raise BackupError("Backup contains duplicate routing group names.")
        if fwmark in fwmarks or table_id in table_ids:
            raise BackupError("Backup contains duplicate routing allocations.")

        group_ids.add(group_id)
        group_names.add(folded)
        fwmarks.add(fwmark)
        table_ids.add(table_id)

    assignment_ids = set()
    external_ids = set()
    ipv4_addresses = set()

    for index, row in enumerate(assignments, 1):
        if not isinstance(row, dict):
            raise BackupError(f"Client assignment row {index} is invalid.")

        assignment_id = _require_int(
            row.get("id"),
            f"Client assignment {index} ID",
        )
        external_id = _require_text(
            row.get("external_id"),
            f"Client assignment {index} external ID",
            255,
        )
        client_name = _require_text(
            row.get("client_name"),
            f"Client assignment {index} name",
            255,
        )
        ipv4 = _require_text(
            row.get("ipv4_address"),
            f"Client assignment '{client_name}' IPv4 address",
            64,
        )
        try:
            parsed_ip = ipaddress.IPv4Address(ipv4)
        except ipaddress.AddressValueError as exc:
            raise BackupError(
                f"Client assignment '{client_name}' has invalid IPv4 address."
            ) from exc

        group_id = _require_int(
            row.get("routing_group_id"),
            f"Client assignment '{client_name}' routing group ID",
        )
        if group_id not in group_ids:
            raise BackupError(
                f"Client '{client_name}' references a missing routing group."
            )

        if assignment_id in assignment_ids:
            raise BackupError("Backup contains duplicate assignment IDs.")
        if external_id in external_ids:
            raise BackupError("Backup contains duplicate WG-Easy client IDs.")
        if str(parsed_ip) in ipv4_addresses:
            raise BackupError("Backup contains duplicate assigned IPv4 addresses.")

        assignment_ids.add(assignment_id)
        external_ids.add(external_id)
        ipv4_addresses.add(str(parsed_ip))

    override_ids = set()
    override_external_ids = set()
    for index, row in enumerate(overrides, 1):
        if not isinstance(row, dict):
            raise BackupError(f"Client route override row {index} is invalid.")
        override_id = _require_int(row.get("id"), f"Client route override {index} ID")
        external_id = _require_text(row.get("external_id"), f"Client route override {index} external ID", 255)
        client_name = _require_text(row.get("client_name"), f"Client route override {index} name", 255)
        ipv4 = _require_text(row.get("ipv4_address"), f"Client route override '{client_name}' IPv4 address", 64)
        try:
            ipaddress.IPv4Address(ipv4)
        except ipaddress.AddressValueError as exc:
            raise BackupError(f"Client route override '{client_name}' has invalid IPv4 address.") from exc
        group_id = _require_int(row.get("routing_group_id"), f"Client route override '{client_name}' routing group ID")
        if group_id not in group_ids:
            raise BackupError(f"Client route override '{client_name}' references a missing routing group.")
        expires_at = row.get("expires_at")
        if expires_at is not None:
            try:
                datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            except (TypeError, ValueError) as exc:
                raise BackupError(f"Client route override '{client_name}' has invalid expiry time.") from exc
        if override_id in override_ids:
            raise BackupError("Backup contains duplicate route override IDs.")
        if external_id in override_external_ids:
            raise BackupError("Backup contains duplicate route override client IDs.")
        override_ids.add(override_id)
        override_external_ids.add(external_id)

    unexpected_configs = set(configs) - config_keys
    if unexpected_configs:
        raise BackupError(
            "Backup contains VPN configuration files that are not referenced "
            "by any profile."
        )


def inspect_backup(raw):
    if not raw:
        raise BackupError("The uploaded backup is empty.")
    if len(raw) > MAX_BACKUP_BYTES:
        raise BackupError("Backup archives are limited to 16 MiB.")

    try:
        archive = zipfile.ZipFile(io.BytesIO(raw), "r")
    except zipfile.BadZipFile as exc:
        raise BackupError("The uploaded file is not a valid ZIP backup.") from exc

    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            raise BackupError("Backup contains too many archive members.")

        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise BackupError("Backup contains duplicate archive filenames.")

        uncompressed = sum(info.file_size for info in infos)
        if uncompressed > MAX_UNCOMPRESSED_BYTES:
            raise BackupError(
                "Backup expands beyond the 32 MiB safety limit."
            )

        if "manifest.json" not in names or "data.json" not in names:
            raise BackupError("Backup is missing manifest.json or data.json.")

        allowed_root = {"manifest.json", "data.json", "secret-key.txt"}
        for name in names:
            path = Path(name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in name
                or "\x00" in name
            ):
                raise BackupError("Backup contains an unsafe file path.")

            if name in allowed_root or name.startswith("configs/"):
                continue
            if name.endswith("/") and name.rstrip("/") in (
                "configs",
                "configs/openvpn",
                "configs/wireguard",
            ):
                continue
            raise BackupError(f"Backup contains unexpected file: {name}")

        try:
            manifest = json.loads(archive.read("manifest.json"))
            data = json.loads(archive.read("data.json"))
        except (json.JSONDecodeError, KeyError, UnicodeDecodeError) as exc:
            raise BackupError("Backup metadata is invalid.") from exc

        if not isinstance(manifest, dict) or not isinstance(data, dict):
            raise BackupError("Backup metadata has an invalid structure.")

        if manifest.get("application") != "WG-Easy-VPN-Out":
            raise BackupError("This backup belongs to a different application.")
        if manifest.get("format") != BACKUP_FORMAT:
            raise BackupError(
                f"Unsupported backup format: {manifest.get('format')!r}."
            )

        backup_schema = manifest.get("schema_version", 1)
        backup_schema = _require_int(
            backup_schema,
            "Backup schema version",
            minimum=1,
        )
        if backup_schema > CURRENT_SCHEMA_VERSION:
            raise BackupError(
                f"Backup schema v{backup_schema} is newer than this "
                f"application supports (v{CURRENT_SCHEMA_VERSION}). "
                "Upgrade VPN Router before restoring this backup."
            )

        secret = None
        if manifest.get("secret_key_included"):
            if "secret-key.txt" not in names:
                raise BackupError(
                    "Manifest says SECRET_KEY is included, but it is missing."
                )
            try:
                secret = archive.read("secret-key.txt").decode("utf-8").strip()
            except UnicodeDecodeError as exc:
                raise BackupError("Included SECRET_KEY is not valid text.") from exc
            if not secret:
                raise BackupError("Included SECRET_KEY is empty.")
            if len(secret) > 4096:
                raise BackupError("Included SECRET_KEY is unexpectedly long.")
        elif "secret-key.txt" in names:
            raise BackupError(
                "Backup contains secret-key.txt but the manifest does not "
                "declare SECRET_KEY inclusion."
            )

        configs = {}
        for info in infos:
            name = info.filename
            if not name.startswith("configs/") or name.endswith("/"):
                continue

            parts = Path(name).parts
            if len(parts) != 3 or parts[1] not in ("openvpn", "wireguard"):
                raise BackupError(f"Unexpected configuration path: {name}")
            filename = parts[2]
            if (
                not SAFE_CONFIG_NAME.fullmatch(filename)
                or filename in (".", "..")
            ):
                raise BackupError(f"Unsafe configuration filename: {filename}")
            if info.file_size > 1024 * 1024:
                raise BackupError(f"Configuration file is too large: {name}")

            content = archive.read(info)
            try:
                content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise BackupError(
                    f"VPN configuration is not valid UTF-8 text: {name}"
                ) from exc

            configs[(parts[1], filename)] = content

    _validate_backup_data(data, configs)
    return manifest, data, secret, configs


def restore_backup(
    raw,
    db,
    VPNProfile,
    RoutingGroup,
    ClientAssignment,
    AppSetting=None,
    ClientRouteOverride=None,
):
    manifest, data, included_secret, configs = inspect_backup(raw)
    current_secret = os.getenv("SECRET_KEY", "")
    secret_matches = included_secret is None or included_secret == current_secret

    # inspect_backup() performs complete structural/reference validation
    # before any tunnel or persistent state is touched.

    root = _data_root()
    openvpn_dir = root / "openvpn"
    wireguard_dir = root / "wireguard"
    backups_dir = root / "backups"
    openvpn_dir.mkdir(parents=True, exist_ok=True)
    wireguard_dir.mkdir(parents=True, exist_ok=True)
    backups_dir.mkdir(parents=True, exist_ok=True)

    # Stage and verify all restored config files before stopping live tunnels.
    stage_root = Path(
        tempfile.mkdtemp(prefix="restore-stage-", dir=backups_dir)
    )
    stage_openvpn = stage_root / "openvpn"
    stage_wireguard = stage_root / "wireguard"
    stage_openvpn.mkdir(parents=True)
    stage_wireguard.mkdir(parents=True)

    try:
        for (folder_name, filename), content in configs.items():
            target_dir = (
                stage_openvpn
                if folder_name == "openvpn"
                else stage_wireguard
            )
            target = target_dir / filename
            target.write_bytes(content)
            if target.read_bytes() != content:
                raise BackupError(
                    f"Could not verify staged VPN config: {filename}"
                )

        # Snapshot current files before any replacement.
        old_files = {}
        for folder in (openvpn_dir, wireguard_dir):
            for path in folder.iterdir():
                if path.is_file():
                    old_files[(folder.name, path.name)] = path.read_bytes()

        runtime = VPNRuntimeService()
        current_profiles = db.session.execute(
            db.select(VPNProfile)
        ).scalars().all()
        previously_enabled = [
            profile.id for profile in current_profiles if profile.enabled
        ]

        # Only after validation + staging succeeds do we disturb live tunnels.
        for profile in current_profiles:
            try:
                runtime.stop(profile)
            except Exception:
                # Restore is replacing runtime state anyway; failures here
                # should not corrupt the persistent rollback path.
                pass

        try:
            # Replace ORM-managed persistent configuration as one transaction.
            if AppSetting is not None and "app_settings" in data:
                # Preserve setup state if restoring an older backup with no settings.
                restored_settings = data.get("app_settings", [])
                if restored_settings:
                    db.session.query(AppSetting).delete()
                    db.session.flush()
                    for row in restored_settings:
                        key = str(row.get("key", "")).strip()
                        if not key or len(key) > 120:
                            raise BackupError("Backup contains an invalid application setting key.")
                        db.session.add(AppSetting(
                            key=key,
                            value=row.get("value"),
                            is_secret=bool(row.get("is_secret", False)),
                        ))
                    db.session.flush()

            if ClientRouteOverride is not None:
                db.session.query(ClientRouteOverride).delete()
            db.session.query(ClientAssignment).delete()
            db.session.query(RoutingGroup).delete()
            db.session.query(VPNProfile).delete()
            db.session.flush()

            for row in data["vpn_profiles"]:
                db.session.add(VPNProfile(
                    id=int(row["id"]),
                    name=row["name"].strip(),
                    provider=(row.get("provider") or None),
                    vpn_type=row["vpn_type"],
                    config_filename=row["config_filename"],
                    username=(row.get("username") or None),
                    password=row.get("password"),
                    enabled=bool(row.get("enabled")),
                    connection_policy=row.get("connection_policy", "always"),
                    detected_country_code=row.get("detected_country_code"),
                    detected_country_name=row.get("detected_country_name"),
                    detected_region=row.get("detected_region"),
                    detected_city=row.get("detected_city"),
                    detected_location_source=row.get("detected_location_source"),
                    detected_location_ip=row.get("detected_location_ip"),
                    manual_country=row.get("manual_country"),
                    manual_region=row.get("manual_region"),
                    manual_city=row.get("manual_city"),
                    favorite=bool(row.get("favorite", False)),
                    tags=row.get("tags"),
                ))
            db.session.flush()

            for row in data["routing_groups"]:
                db.session.add(RoutingGroup(
                    id=int(row["id"]),
                    name=row["name"].strip(),
                    vpn_profile_id=(
                        int(row["vpn_profile_id"])
                        if row.get("vpn_profile_id") is not None
                        else None
                    ),
                    fallback_mode=row.get("fallback_mode", "block"),
                    dns_mode=row.get("dns_mode", "inherit"),
                    dns_target=row.get("dns_target"),
                    fwmark=int(row["fwmark"]),
                    table_id=int(row["table_id"]),
                ))
            db.session.flush()

            for row in data["client_assignments"]:
                db.session.add(ClientAssignment(
                    id=int(row["id"]),
                    external_id=row["external_id"].strip(),
                    client_name=row["client_name"].strip(),
                    ipv4_address=str(
                        ipaddress.IPv4Address(row["ipv4_address"])
                    ),
                    routing_group_id=int(row["routing_group_id"]),
                ))
            db.session.flush()

            if ClientRouteOverride is not None:
                for row in data.get("client_route_overrides", []):
                    expires_at = row.get("expires_at")
                    parsed_expiry = None
                    if expires_at:
                        parsed_expiry = datetime.fromisoformat(
                            str(expires_at).replace("Z", "+00:00")
                        ).replace(tzinfo=None)
                    db.session.add(ClientRouteOverride(
                        id=int(row["id"]),
                        external_id=row["external_id"].strip(),
                        client_name=row["client_name"].strip(),
                        ipv4_address=str(ipaddress.IPv4Address(row["ipv4_address"])),
                        routing_group_id=int(row["routing_group_id"]),
                        expires_at=parsed_expiry,
                    ))
                db.session.flush()

            # Swap in verified staged files.
            for folder in (openvpn_dir, wireguard_dir):
                for path in folder.iterdir():
                    if path.is_file():
                        path.unlink()

            for staged_dir, live_dir in (
                (stage_openvpn, openvpn_dir),
                (stage_wireguard, wireguard_dir),
            ):
                for path in staged_dir.iterdir():
                    if path.is_file():
                        (live_dir / path.name).write_bytes(
                            path.read_bytes()
                        )

            db.session.commit()

        except Exception:
            db.session.rollback()

            # Restore prior files.
            for folder in (openvpn_dir, wireguard_dir):
                for path in folder.iterdir():
                    if path.is_file():
                        path.unlink()

            for (folder_name, filename), content in old_files.items():
                target_dir = (
                    openvpn_dir
                    if folder_name == "openvpn"
                    else wireguard_dir
                )
                (target_dir / filename).write_bytes(content)

            # Best-effort recovery of tunnels that were enabled before the
            # failed restore.
            db.session.expire_all()
            for profile_id in previously_enabled:
                profile = db.session.get(VPNProfile, profile_id)
                if profile is None or profile.vpn_type not in ("openvpn", "wireguard"):
                    continue
                try:
                    runtime.start(profile)
                except Exception:
                    pass

            raise

    finally:
        shutil.rmtree(stage_root, ignore_errors=True)

    return {
        "manifest": manifest,
        "included_secret": included_secret,
        "secret_matches": secret_matches,
        "profiles": len(data["vpn_profiles"]),
        "groups": len(data["routing_groups"]),
        "assignments": len(data["client_assignments"]),
        "overrides": len(data.get("client_route_overrides", [])),
        "schema_version": manifest.get("schema_version", 1),
    }
