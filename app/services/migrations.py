from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import sqlite3


CURRENT_SCHEMA_VERSION = 2


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


MIGRATIONS = (
    Migration(1, "baseline", _migration_1_baseline),
    Migration(2, "application-settings", _migration_2_application_settings),
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
