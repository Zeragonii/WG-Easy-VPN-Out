from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import sqlite3


CURRENT_SCHEMA_VERSION = 7


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    apply: callable


def _migration_1_baseline(connection):
    """
    v1 is the schema produced by releases through v0.9.1.

    Legacy databases already have these tables. Fresh installs have them
    created from SQLAlchemy metadata before this migration is recorded.
    """
    required = {
        "users",
        "vpn_profiles",
        "routing_groups",
        "client_assignments",
    }
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    existing = {row[0] for row in rows}

    missing = sorted(required - existing)
    if missing:
        raise MigrationError(
            "Cannot establish schema v1; required tables are missing: "
            + ", ".join(missing)
        )



def _migration_2_application_settings(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key VARCHAR(120) PRIMARY KEY,
            value TEXT,
            is_secret BOOLEAN NOT NULL DEFAULT 0,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)



def _migration_3_routing_events(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS routing_events (
            id INTEGER PRIMARY KEY,
            routing_group_id INTEGER NOT NULL,
            state VARCHAR(32) NOT NULL,
            effective_exit VARCHAR(255) NOT NULL,
            detail TEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(routing_group_id) REFERENCES routing_groups(id)
        )
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS ix_routing_events_routing_group_id
        ON routing_events(routing_group_id)
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS ix_routing_events_created_at
        ON routing_events(created_at)
    """)



def _migration_4_dns_policy(connection):
    columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(routing_groups)"
        ).fetchall()
    }
    if "dns_mode" not in columns:
        connection.execute(
            "ALTER TABLE routing_groups "
            "ADD COLUMN dns_mode VARCHAR(16) NOT NULL DEFAULT 'inherit'"
        )
    if "dns_target" not in columns:
        connection.execute(
            "ALTER TABLE routing_groups "
            "ADD COLUMN dns_target VARCHAR(64)"
        )



def _migration_5_connection_policy(connection):
    columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(vpn_profiles)"
        ).fetchall()
    }
    if "connection_policy" not in columns:
        connection.execute(
            "ALTER TABLE vpn_profiles "
            "ADD COLUMN connection_policy VARCHAR(16) NOT NULL DEFAULT 'always'"
        )


def _migration_6_temporary_routing_overrides(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS client_route_overrides (
            id INTEGER PRIMARY KEY,
            external_id VARCHAR(255) NOT NULL UNIQUE,
            client_name VARCHAR(255) NOT NULL,
            ipv4_address VARCHAR(64) NOT NULL,
            routing_group_id INTEGER NOT NULL,
            expires_at DATETIME,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(routing_group_id) REFERENCES routing_groups(id)
        )
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS ix_client_route_overrides_external_id
        ON client_route_overrides(external_id)
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS ix_client_route_overrides_routing_group_id
        ON client_route_overrides(routing_group_id)
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS ix_client_route_overrides_expires_at
        ON client_route_overrides(expires_at)
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS route_override_events (
            id INTEGER PRIMARY KEY,
            external_id VARCHAR(255) NOT NULL,
            client_name VARCHAR(255) NOT NULL,
            event_type VARCHAR(24) NOT NULL,
            routing_group_id INTEGER,
            routing_group_name VARCHAR(120),
            detail TEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(routing_group_id) REFERENCES routing_groups(id)
        )
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS ix_route_override_events_external_id
        ON route_override_events(external_id)
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS ix_route_override_events_event_type
        ON route_override_events(event_type)
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS ix_route_override_events_routing_group_id
        ON route_override_events(routing_group_id)
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS ix_route_override_events_created_at
        ON route_override_events(created_at)
    """)


def _migration_7_profile_location_intelligence(connection):
    columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(vpn_profiles)"
        ).fetchall()
    }
    additions = (
        ("detected_country_code", "VARCHAR(8)"),
        ("detected_country_name", "VARCHAR(120)"),
        ("detected_region", "VARCHAR(120)"),
        ("detected_city", "VARCHAR(120)"),
        ("detected_location_source", "VARCHAR(32)"),
        ("detected_location_ip", "VARCHAR(64)"),
        ("manual_country", "VARCHAR(120)"),
        ("manual_region", "VARCHAR(120)"),
        ("manual_city", "VARCHAR(120)"),
    )
    for name, sql_type in additions:
        if name not in columns:
            connection.execute(
                f"ALTER TABLE vpn_profiles ADD COLUMN {name} {sql_type}"
            )


MIGRATIONS = (
    Migration(1, "baseline", _migration_1_baseline),
    Migration(2, "application-settings", _migration_2_application_settings),
    Migration(3, "routing-health-history", _migration_3_routing_events),
    Migration(4, "routing-group-dns-policy", _migration_4_dns_policy),
    Migration(5, "vpn-connection-policy", _migration_5_connection_policy),
    Migration(6, "temporary-routing-overrides", _migration_6_temporary_routing_overrides),
    Migration(7, "vpn-profile-location-intelligence", _migration_7_profile_location_intelligence),
)


def _connection(db):
    raw = db.engine.raw_connection()
    # SQLAlchemy may return a proxy; sqlite pragmas/DDL work through it.
    return raw


def _ensure_migration_table(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
    """)
    connection.commit()


def current_schema_version(db):
    connection = _connection(db)
    try:
        _ensure_migration_table(connection)
        row = connection.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()
        return int(row[0] or 0)
    finally:
        connection.close()


def migration_history(db):
    connection = _connection(db)
    try:
        _ensure_migration_table(connection)
        rows = connection.execute(
            "SELECT version, name, applied_at "
            "FROM schema_migrations ORDER BY version"
        ).fetchall()
        return [
            {
                "version": int(row[0]),
                "name": row[1],
                "applied_at": row[2],
            }
            for row in rows
        ]
    finally:
        connection.close()


def run_migrations(db, logger=None):
    """
    Apply all pending schema migrations in order.

    SQLAlchemy metadata creation remains only a fresh-install bootstrap. Once
    the migration table exists, schema evolution belongs here.
    """
    connection = _connection(db)
    try:
        _ensure_migration_table(connection)
        row = connection.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()
        current = int(row[0] or 0)

        if current > CURRENT_SCHEMA_VERSION:
            raise MigrationError(
                f"Database schema v{current} is newer than this application "
                f"supports (v{CURRENT_SCHEMA_VERSION})."
            )

        applied = []
        for migration in MIGRATIONS:
            if migration.version <= current:
                continue

            try:
                connection.execute("BEGIN IMMEDIATE")
                migration.apply(connection)
                connection.execute(
                    "INSERT INTO schema_migrations(version, name, applied_at) "
                    "VALUES (?, ?, ?)",
                    (
                        migration.version,
                        migration.name,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

            applied.append(migration.version)
            current = migration.version
            if logger:
                logger.info(
                    "Applied database migration v%s (%s).",
                    migration.version,
                    migration.name,
                )

        return {
            "current": current,
            "supported": CURRENT_SCHEMA_VERSION,
            "applied": applied,
        }
    finally:
        connection.close()
