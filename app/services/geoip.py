from __future__ import annotations

from dataclasses import dataclass, asdict
import ipaddress
import os
from pathlib import Path
import threading

import maxminddb


@dataclass(slots=True)
class GeoLocation:
    country_code: str | None = None
    country_name: str | None = None
    region: str | None = None
    city: str | None = None
    database: str | None = None

    def to_dict(self):
        return asdict(self)


class GeoIPService:
    """Lazy, on-box MaxMind-compatible MMDB lookup service."""

    def __init__(self):
        data_root = Path(os.getenv("VPN_ROUTER_DATA_DIR", "/data"))
        explicit = os.getenv("VPN_ROUTER_GEOIP_DB", "").strip()
        candidates = []
        if explicit:
            candidates.append(Path(explicit))
        candidates.extend([
            data_root / "geoip" / "GeoLite2-City.mmdb",
            data_root / "geoip" / "GeoIP2-City.mmdb",
            data_root / "geoip" / "GeoLite2-Country.mmdb",
            data_root / "geoip" / "GeoIP2-Country.mmdb",
        ])
        self.path = next((p for p in candidates if p.is_file()), None)
        self._reader = None
        self._lock = threading.RLock()
        self._error = None

    def available(self):
        return self.path is not None

    def status(self):
        return {
            "available": self.available(),
            "path": str(self.path) if self.path else None,
            "error": self._error,
        }

    def _get_reader(self):
        if not self.path:
            return None
        with self._lock:
            if self._reader is None:
                try:
                    self._reader = maxminddb.open_database(str(self.path))
                except Exception as exc:
                    self._error = str(exc)[-300:]
                    return None
            return self._reader

    def lookup(self, value):
        try:
            ip = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return None
        if not ip.is_global:
            return None

        reader = self._get_reader()
        if reader is None:
            return None

        try:
            record = reader.get(str(ip)) or {}
        except Exception as exc:
            self._error = str(exc)[-300:]
            return None

        country = record.get("country") or record.get("registered_country") or {}
        subdivisions = record.get("subdivisions") or []
        region = subdivisions[0] if subdivisions else {}
        city = record.get("city") or {}

        def english_name(node):
            names = node.get("names") or {}
            return names.get("en") or next(iter(names.values()), None)

        result = GeoLocation(
            country_code=country.get("iso_code"),
            country_name=english_name(country),
            region=english_name(region),
            city=english_name(city),
            database=self.path.name if self.path else None,
        )
        if not any((result.country_code, result.country_name, result.region, result.city)):
            return None
        return result

    def close(self):
        with self._lock:
            if self._reader is not None:
                try:
                    self._reader.close()
                except Exception:
                    pass
                self._reader = None


_SOURCE_PRIORITY = {
    None: 0,
    "endpoint_geoip": 10,
    "exit_geoip": 20,
}


def apply_detected_location(db, profile, geoip, ip_value, source):
    """
    Persist an automatic location observation without touching manual overrides.

    Verified exit-IP GeoIP outranks endpoint-IP GeoIP.
    """
    if source not in ("endpoint_geoip", "exit_geoip"):
        raise ValueError("Unsupported location source.")

    current_priority = _SOURCE_PRIORITY.get(profile.detected_location_source, 0)
    new_priority = _SOURCE_PRIORITY[source]
    if new_priority < current_priority:
        return False

    location = geoip.lookup(ip_value) if geoip else None
    if location is None:
        return False

    values = {
        "detected_country_code": location.country_code,
        "detected_country_name": location.country_name,
        "detected_region": location.region,
        "detected_city": location.city,
        "detected_location_source": source,
        "detected_location_ip": str(ip_value),
    }
    changed = any(getattr(profile, key) != value for key, value in values.items())
    if not changed:
        return False

    for key, value in values.items():
        setattr(profile, key, value)
    db.session.flush()
    return True


def effective_location(profile, config_region_hint=None):
    if profile.has_manual_location:
        return {
            "country": profile.manual_country,
            "region": profile.manual_region,
            "city": profile.manual_city,
            "source": "manual",
            "country_code": None,
        }

    if profile.detected_country_name or profile.detected_region or profile.detected_city:
        return {
            "country": profile.detected_country_name,
            "region": profile.detected_region,
            "city": profile.detected_city,
            "source": profile.detected_location_source,
            "country_code": profile.detected_country_code,
        }

    if config_region_hint:
        return {
            "country": None,
            "region": config_region_hint,
            "city": None,
            "source": "config_hint",
            "country_code": None,
        }

    return {
        "country": None,
        "region": None,
        "city": None,
        "source": None,
        "country_code": None,
    }
