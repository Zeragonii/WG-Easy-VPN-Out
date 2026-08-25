from __future__ import annotations

import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import zipfile

from .vpn_runtime import VPNRuntimeService


BACKUP_FORMAT = 1
MAX_BACKUP_BYTES = 16 * 1024 * 1024


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


def export_backup(db, VPNProfile, RoutingGroup, ClientAssignment, version, include_secret=False):
    profiles = db.session.execute(
        db.select(VPNProfile).order_by(VPNProfile.id.asc())
    ).scalars().all()
    groups = db.session.execute(
        db.select(RoutingGroup).order_by(RoutingGroup.id.asc())
    ).scalars().all()
    assignments = db.session.execute(
        db.select(ClientAssignment).order_by(ClientAssignment.id.asc())
    ).scalars().all()

    payload = {
        "vpn_profiles": [{
            "id": p.id,
            "name": p.name,
            "provider": p.provider,
            "vpn_type": p.vpn_type,
            "config_filename": p.config_filename,
            "username": p.username,
            "password": p.password,
            "enabled": bool(p.enabled),
            "created_at": _iso(p.created_at),
            "updated_at": _iso(p.updated_at),
        } for p in profiles],
        "routing_groups": [{
            "id": g.id,
            "name": g.name,
            "vpn_profile_id": g.vpn_profile_id,
            "fallback_mode": g.fallback_mode,
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
    }

    manifest = {
        "format": BACKUP_FORMAT,
        "application": "WG-Easy-VPN-Out",
        "application_version": version,
        "created_at": _now().isoformat(),
        "secret_key_included": bool(include_secret),
        "contents": {
            "vpn_profiles": len(profiles),
            "routing_groups": len(groups),
            "client_assignments": len(assignments),
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
        names = archive.namelist()
        if "manifest.json" not in names or "data.json" not in names:
            raise BackupError("Backup is missing manifest.json or data.json.")

        # Reject path traversal and unexpected absolute paths.
        for name in names:
            path = Path(name)
            if path.is_absolute() or ".." in path.parts:
                raise BackupError("Backup contains an unsafe file path.")

        try:
            manifest = json.loads(archive.read("manifest.json"))
            data = json.loads(archive.read("data.json"))
        except (json.JSONDecodeError, KeyError, UnicodeDecodeError) as exc:
            raise BackupError("Backup metadata is invalid.") from exc

        if manifest.get("application") != "WG-Easy-VPN-Out":
            raise BackupError("This backup belongs to a different application.")
        if manifest.get("format") != BACKUP_FORMAT:
            raise BackupError(
                f"Unsupported backup format: {manifest.get('format')!r}."
            )

        for key in ("vpn_profiles", "routing_groups", "client_assignments"):
            if not isinstance(data.get(key), list):
                raise BackupError(f"Backup data is missing '{key}'.")

        secret = None
        if manifest.get("secret_key_included"):
            if "secret-key.txt" not in names:
                raise BackupError(
                    "Manifest says SECRET_KEY is included, but it is missing."
                )
            secret = archive.read("secret-key.txt").decode("utf-8").strip()
            if not secret:
                raise BackupError("Included SECRET_KEY is empty.")

        configs = {}
        for name in names:
            if not name.startswith("configs/") or name.endswith("/"):
                continue
            parts = Path(name).parts
            if len(parts) != 3 or parts[1] not in ("openvpn", "wireguard"):
                raise BackupError(f"Unexpected configuration path: {name}")
            content = archive.read(name)
            if len(content) > 1024 * 1024:
                raise BackupError(f"Configuration file is too large: {name}")
            configs[(parts[1], parts[2])] = content

    return manifest, data, secret, configs


def restore_backup(
    raw,
    db,
    VPNProfile,
    RoutingGroup,
    ClientAssignment,
):
    manifest, data, included_secret, configs = inspect_backup(raw)
    current_secret = os.getenv("SECRET_KEY", "")
    secret_matches = included_secret is None or included_secret == current_secret

    # Validate all references before touching current state.
    profile_ids = {int(p["id"]) for p in data["vpn_profiles"]}
    group_ids = {int(g["id"]) for g in data["routing_groups"]}

    if len(profile_ids) != len(data["vpn_profiles"]):
        raise BackupError("Backup contains duplicate VPN profile IDs.")
    if len(group_ids) != len(data["routing_groups"]):
        raise BackupError("Backup contains duplicate routing group IDs.")

    for group in data["routing_groups"]:
        target = group.get("vpn_profile_id")
        if target is not None and int(target) not in profile_ids:
            raise BackupError(
                f"Routing group '{group.get('name')}' references a missing VPN profile."
            )

    for assignment in data["client_assignments"]:
        if int(assignment["routing_group_id"]) not in group_ids:
            raise BackupError(
                f"Client '{assignment.get('client_name')}' references a missing routing group."
            )

    # Ensure every referenced config exists in the archive.
    for profile in data["vpn_profiles"]:
        folder = "openvpn" if profile["vpn_type"] == "openvpn" else "wireguard"
        key = (folder, profile["config_filename"])
        if key not in configs:
            raise BackupError(
                f"Backup is missing config for VPN profile '{profile['name']}'."
            )

    runtime = VPNRuntimeService()
    current_profiles = db.session.execute(
        db.select(VPNProfile)
    ).scalars().all()

    # Stop current tunnels before replacing policy/database state.
    for profile in current_profiles:
        try:
            runtime.stop(profile)
        except Exception:
            pass

    root = _data_root()
    openvpn_dir = root / "openvpn"
    wireguard_dir = root / "wireguard"
    openvpn_dir.mkdir(parents=True, exist_ok=True)
    wireguard_dir.mkdir(parents=True, exist_ok=True)

    # Snapshot config files in memory for rollback. These are intentionally
    # limited to the app's small text config directories.
    old_files = {}
    for folder in (openvpn_dir, wireguard_dir):
        for path in folder.iterdir():
            if path.is_file():
                old_files[(folder.name, path.name)] = path.read_bytes()

    try:
        # Replace ORM-managed persistent configuration as one DB transaction.
        db.session.query(ClientAssignment).delete()
        db.session.query(RoutingGroup).delete()
        db.session.query(VPNProfile).delete()
        db.session.flush()

        for row in data["vpn_profiles"]:
            db.session.add(VPNProfile(
                id=int(row["id"]),
                name=row["name"],
                provider=row.get("provider"),
                vpn_type=row["vpn_type"],
                config_filename=row["config_filename"],
                username=row.get("username"),
                password=row.get("password"),
                enabled=bool(row.get("enabled")),
            ))
        db.session.flush()

        for row in data["routing_groups"]:
            db.session.add(RoutingGroup(
                id=int(row["id"]),
                name=row["name"],
                vpn_profile_id=(
                    int(row["vpn_profile_id"])
                    if row.get("vpn_profile_id") is not None
                    else None
                ),
                fallback_mode=row.get("fallback_mode", "block"),
                fwmark=row.get("fwmark"),
                table_id=row.get("table_id"),
            ))
        db.session.flush()

        for row in data["client_assignments"]:
            db.session.add(ClientAssignment(
                id=int(row["id"]),
                external_id=row["external_id"],
                client_name=row["client_name"],
                ipv4_address=row["ipv4_address"],
                routing_group_id=int(row["routing_group_id"]),
            ))

        # Replace config directories only after DB validation has succeeded.
        for folder in (openvpn_dir, wireguard_dir):
            for path in folder.iterdir():
                if path.is_file():
                    path.unlink()

        for (folder_name, filename), content in configs.items():
            target_dir = openvpn_dir if folder_name == "openvpn" else wireguard_dir
            (target_dir / filename).write_bytes(content)

        db.session.commit()

    except Exception:
        db.session.rollback()

        # Restore original config files if replacement failed.
        for folder in (openvpn_dir, wireguard_dir):
            for path in folder.iterdir():
                if path.is_file():
                    path.unlink()
        for (folder_name, filename), content in old_files.items():
            target_dir = openvpn_dir if folder_name == "openvpn" else wireguard_dir
            (target_dir / filename).write_bytes(content)
        raise

    return {
        "manifest": manifest,
        "included_secret": included_secret,
        "secret_matches": secret_matches,
        "profiles": len(data["vpn_profiles"]),
        "groups": len(data["routing_groups"]),
        "assignments": len(data["client_assignments"]),
    }
