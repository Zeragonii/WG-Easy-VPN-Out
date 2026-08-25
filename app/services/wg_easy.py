from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import requests
from requests.auth import HTTPBasicAuth


class WGEasyError(RuntimeError):
    """Base error for WG-Easy integration."""


class WGEasyConfigurationError(WGEasyError):
    pass


class WGEasyAuthenticationError(WGEasyError):
    pass


class WGEasyConnectionError(WGEasyError):
    pass


@dataclass(slots=True)
class WGEasyClient:
    external_id: str
    name: str
    ipv4_address: str
    enabled: bool
    online: bool | None
    latest_handshake_at: str | None
    transfer_rx: int | None
    transfer_tx: int | None
    endpoint: str | None

    @property
    def connection_state(self) -> str:
        """
        WireGuard has no conventional persistent 'connected' state.
        Infer a useful UI state from the latest handshake age.
        """
        age = self.handshake_age_seconds

        if age is None:
            return "never"

        if age < 180:
            return "online"

        if age < 600:
            return "recent"

        return "offline"

    @property
    def handshake_age_seconds(self) -> float | None:
        if not self.latest_handshake_at:
            return None

        try:
            value = self.latest_handshake_at.replace("Z", "+00:00")
            dt = datetime.fromisoformat(value)

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

            return max(
                0.0,
                (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds(),
            )
        except (TypeError, ValueError):
            return None

    @property
    def handshake_age_display(self) -> str:
        age = self.handshake_age_seconds

        if age is None:
            return "Never"

        seconds = int(age)

        if seconds < 60:
            return f"{seconds}s ago"

        minutes = seconds // 60
        if minutes < 60:
            return f"{minutes}m ago"

        hours = minutes // 60
        if hours < 24:
            return f"{hours}h ago"

        days = hours // 24
        return f"{days}d ago"

    @staticmethod
    def _format_bytes(value: int | None) -> str:
        if value is None:
            return "—"

        size = float(value)
        units = ["B", "KB", "MB", "GB", "TB", "PB"]

        for unit in units:
            if size < 1024 or unit == units[-1]:
                if unit == "B":
                    return f"{int(size)} {unit}"
                return f"{size:.1f} {unit}"
            size /= 1024

        return f"{value} B"

    @property
    def transfer_rx_display(self) -> str:
        return self._format_bytes(self.transfer_rx)

    @property
    def transfer_tx_display(self) -> str:
        return self._format_bytes(self.transfer_tx)


def _first(data: dict[str, Any], *names: str, default=None):
    for name in names:
        if name in data and data[name] is not None:
            return data[name]
    return default


def _normalise_ip(value: Any) -> str:
    if not value:
        return "Unknown"
    value = str(value)
    return value.split("/", 1)[0]


def _parse_timestamp(value: Any) -> str | None:
    if value in (None, "", 0, "0"):
        return None

    # Preserve strings because WG-Easy has changed timestamp representation
    # between releases. Convert Unix timestamps where practical.
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
        except (ValueError, OSError, OverflowError):
            return str(value)

    return str(value)


def _normalise_client(raw: dict[str, Any], index: int) -> WGEasyClient:
    external_id = str(_first(raw, "id", "clientId", "client_id", default=index))
    name = str(_first(raw, "name", "clientName", "client_name", default=f"Client {external_id}"))

    ipv4 = _first(
        raw,
        "ipv4Address",
        "ipv4_address",
        "address",
        "ip",
        default="Unknown",
    )

    enabled = bool(_first(raw, "enabled", "enable", default=True))

    online_value = _first(raw, "online", "connected", "isOnline", "is_online", default=None)
    online = None if online_value is None else bool(online_value)

    latest_handshake = _parse_timestamp(
        _first(
            raw,
            "latestHandshakeAt",
            "latest_handshake_at",
            "lastHandshakeAt",
            "last_handshake_at",
            "lastHandshake",
            "last_handshake",
            default=None,
        )
    )

    rx = _first(
        raw,
        "transferRx",
        "transfer_rx",
        "receivedBytes",
        "received_bytes",
        "rxBytes",
        "rx_bytes",
        default=None,
    )
    tx = _first(
        raw,
        "transferTx",
        "transfer_tx",
        "sentBytes",
        "sent_bytes",
        "txBytes",
        "tx_bytes",
        default=None,
    )

    endpoint = _first(
        raw,
        "endpoint",
        "remoteEndpoint",
        "remote_endpoint",
        default=None,
    )

    try:
        rx = int(rx) if rx is not None else None
    except (TypeError, ValueError):
        rx = None

    try:
        tx = int(tx) if tx is not None else None
    except (TypeError, ValueError):
        tx = None

    return WGEasyClient(
        external_id=external_id,
        name=name,
        ipv4_address=_normalise_ip(ipv4),
        enabled=enabled,
        online=online,
        latest_handshake_at=latest_handshake,
        transfer_rx=rx,
        transfer_tx=tx,
        endpoint=str(endpoint) if endpoint else None,
    )


class WGEasyService:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        timeout: float = 4.0,
        verify_tls: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verify_tls = verify_tls

    def _validate_config(self) -> None:
        if not self.base_url:
            raise WGEasyConfigurationError("WG_EASY_URL is not configured.")
        if not self.username or not self.password:
            raise WGEasyConfigurationError(
                "WG-Easy API credentials are not configured. "
                "Set WG_EASY_USERNAME and WG_EASY_PASSWORD."
            )

    def get_clients(self) -> list[WGEasyClient]:
        self._validate_config()

        url = f"{self.base_url}/api/client"

        try:
            response = requests.get(
                url,
                auth=HTTPBasicAuth(self.username, self.password),
                timeout=self.timeout,
                verify=self.verify_tls,
                headers={"Accept": "application/json"},
            )
        except requests.RequestException as exc:
            raise WGEasyConnectionError(
                f"Could not connect to WG-Easy at {self.base_url}."
            ) from exc

        if response.status_code in (401, 403):
            raise WGEasyAuthenticationError(
                "WG-Easy rejected the API credentials. "
                "Check the username/password and ensure 2FA is disabled for this account."
            )

        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise WGEasyConnectionError(
                f"WG-Easy API returned HTTP {response.status_code}."
            ) from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise WGEasyConnectionError(
                "WG-Easy returned a non-JSON response."
            ) from exc

        # v15 currently returns the client collection directly. Accept a few
        # wrapped forms too, so an API response-envelope change is isolated here.
        if isinstance(payload, list):
            raw_clients = payload
        elif isinstance(payload, dict):
            raw_clients = None
            for key in ("clients", "data", "items"):
                value = payload.get(key)
                if isinstance(value, list):
                    raw_clients = value
                    break
            if raw_clients is None:
                raise WGEasyConnectionError(
                    "WG-Easy returned an unexpected client response shape."
                )
        else:
            raise WGEasyConnectionError(
                "WG-Easy returned an unexpected client response type."
            )

        clients = []
        for index, raw in enumerate(raw_clients, start=1):
            if isinstance(raw, dict):
                clients.append(_normalise_client(raw, index))

        return clients
