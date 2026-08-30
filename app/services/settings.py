from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os

from .secrets import decrypt_secret, encrypt_secret


@dataclass(frozen=True, slots=True)
class SettingDefinition:
    key: str
    env: str | None
    default: str
    value_type: str = "text"
    secret: bool = False
    label: str = ""
    section: str = "General"


DEFINITIONS = {
    d.key: d for d in (
        SettingDefinition("wg_easy_url", "WG_EASY_URL", "http://127.0.0.1:51821", label="WG-Easy URL", section="WG-Easy"),
        SettingDefinition("wg_easy_username", "WG_EASY_USERNAME", "", label="WG-Easy username", section="WG-Easy"),
        SettingDefinition("wg_easy_password", "WG_EASY_PASSWORD", "", secret=True, label="WG-Easy password", section="WG-Easy"),
        SettingDefinition("wg_easy_verify_tls", "WG_EASY_VERIFY_TLS", "true", "bool", label="Verify TLS certificates", section="WG-Easy"),
        SettingDefinition("routing_reconcile_interval", "ROUTING_RECONCILE_INTERVAL", "3", "float", label="Routing reconciliation interval (seconds)", section="Routing"),
        SettingDefinition("wan_hairpin_enabled", "WAN_HAIRPIN_ENABLED", "true", "bool", label="Enable WAN hairpin compatibility for routed WG clients", section="Routing"),
        SettingDefinition("wan_hairpin_public_ip", "WAN_HAIRPIN_PUBLIC_IP", "", "ipv4_optional", label="Public WAN IPv4 override (blank = auto-detect)", section="Routing"),
        SettingDefinition("vpn_retry_check_interval", "VPN_RETRY_CHECK_INTERVAL", "2", "float", label="Retry check interval (seconds)", section="VPN resilience"),
        SettingDefinition("vpn_retry_base_seconds", "VPN_RETRY_BASE_SECONDS", "5", "float", label="Initial retry delay (seconds)", section="VPN resilience"),
        SettingDefinition("vpn_retry_max_seconds", "VPN_RETRY_MAX_SECONDS", "300", "float", label="Maximum retry delay (seconds)", section="VPN resilience"),
        SettingDefinition("vpn_retry_max_failures", "VPN_RETRY_MAX_FAILURES", "0", "int", label="Maximum retry failures (0 = unlimited)", section="VPN resilience"),
        SettingDefinition("vpn_connect_timeout_seconds", "VPN_CONNECT_TIMEOUT_SECONDS", "45", "float", label="Connecting timeout (seconds, 0 = disabled)", section="VPN resilience"),
        SettingDefinition("exit_ip_probe_interval", "EXIT_IP_PROBE_INTERVAL", "60", "float", label="Exit-IP probe interval (seconds)", section="Observability"),
        SettingDefinition("traffic_sample_interval", "TRAFFIC_SAMPLE_INTERVAL", "1", "float", label="Traffic sample interval (seconds)", section="Observability"),
        SettingDefinition("dns_leak_probe_interval", "DNS_LEAK_PROBE_INTERVAL", "900", "float", label="DNS leak probe interval (seconds, 0 = manual only)", section="Observability"),
        SettingDefinition("update_check_cache_seconds", "UPDATE_CHECK_CACHE_SECONDS", "900", "float", label="Update-check cache (seconds)", section="Observability"),
        SettingDefinition("update_version_url", "UPDATE_VERSION_URL", "https://raw.githubusercontent.com/Zeragonii/WG-Easy-VPN-Out/main/VERSION", label="Version URL", section="Observability"),
        SettingDefinition("update_repository_url", "UPDATE_REPOSITORY_URL", "https://github.com/Zeragonii/WG-Easy-VPN-Out", label="Repository URL", section="Observability"),
    )
}

SETUP_COMPLETE_KEY = "setup_completed"


class SettingsError(ValueError):
    pass


def _coerce(definition, value):
    value = "" if value is None else str(value).strip()
    try:
        if definition.value_type == "bool":
            if value.lower() in {"1", "true", "yes", "on"}:
                return True
            if value.lower() in {"0", "false", "no", "off"}:
                return False
            raise ValueError
        if definition.value_type == "int":
            return int(value)
        if definition.value_type == "float":
            return float(value)
        if definition.value_type == "ipv4_optional":
            if not value:
                return ""
            return str(ipaddress.IPv4Address(value))
        return value
    except ValueError as exc:
        raise SettingsError(f"{definition.label or definition.key} has an invalid value.") from exc


class SettingsService:
    def __init__(self, db, AppSetting):
        self.db = db
        self.AppSetting = AppSetting

    def _row(self, key):
        return self.db.session.get(self.AppSetting, key)

    def raw(self, key, reveal_secret=True):
        definition = DEFINITIONS[key]
        row = self._row(key)
        if row is not None:
            if definition.secret and row.value and reveal_secret:
                return decrypt_secret(row.value)
            return row.value

        # Legacy environment variables are bootstrap/fallback inputs only.
        # Once a DB row exists, UI configuration is authoritative.
        if definition.env and definition.env in os.environ:
            return os.environ.get(definition.env, "")
        return definition.default

    def get(self, key):
        definition = DEFINITIONS[key]
        return _coerce(definition, self.raw(key))

    def source(self, key):
        if self._row(key) is not None:
            return "Database"
        definition = DEFINITIONS[key]
        if definition.env and definition.env in os.environ:
            return "Legacy environment"
        return "Built-in default"

    def set(self, key, value, commit=True):
        definition = DEFINITIONS[key]
        # Validate before persistence.
        _coerce(definition, value)
        stored = str(value).strip()
        if definition.value_type == "bool":
            stored = "true" if _coerce(definition, value) else "false"
        if definition.secret:
            stored = encrypt_secret(stored) if stored else None

        row = self._row(key)
        if row is None:
            row = self.AppSetting(key=key)
            self.db.session.add(row)
        row.value = stored
        row.is_secret = definition.secret
        if commit:
            self.db.session.commit()
        return row

    def set_many(self, values):
        for key, value in values.items():
            if key in DEFINITIONS:
                self.set(key, value, commit=False)
        self.db.session.commit()

    def setup_complete(self):
        row = self._row(SETUP_COMPLETE_KEY)
        return bool(row and row.value == "true")

    def mark_setup_complete(self):
        row = self._row(SETUP_COMPLETE_KEY)
        if row is None:
            row = self.AppSetting(key=SETUP_COMPLETE_KEY, is_secret=False)
            self.db.session.add(row)
        row.value = "true"
        self.db.session.commit()

    def migrate_legacy_environment(self):
        changed = []
        for key, definition in DEFINITIONS.items():
            if self._row(key) is not None:
                continue
            if not definition.env or definition.env not in os.environ:
                continue
            value = os.environ.get(definition.env, "")
            self.set(key, value, commit=False)
            changed.append(key)
        if changed:
            self.db.session.commit()
        return changed

    def sections(self):
        result = {}
        for definition in DEFINITIONS.values():
            result.setdefault(definition.section, []).append(definition)
        return result
