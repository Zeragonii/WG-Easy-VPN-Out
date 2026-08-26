
from __future__ import annotations
from dataclasses import dataclass, asdict
import ipaddress
from .providers import detect_provider

@dataclass(slots=True)
class ProfileIntelligence:
    provider_detected: str | None = None
    provider_key: str | None = None
    provider_confidence: str | None = None
    provider_reason: str | None = None
    endpoint_host: str | None = None
    endpoint_port: int | None = None
    protocol: str | None = None
    device: str | None = None
    transport: str | None = None
    auth_mode: str | None = None
    cipher: str | None = None
    tls_mode: str | None = None
    remote_count: int = 0
    region_hint: str | None = None
    endpoint_is_ip: bool = False

    def to_dict(self):
        return asdict(self)

def _clean(line: str) -> str:
    line = line.strip()
    if not line or line.startswith(("#", ";")):
        return ""
    return line

def _apply_provider_metadata(meta: ProfileIntelligence, content: str):
    match = detect_provider(meta.endpoint_host, content)
    adapter = match.adapter
    meta.provider_key = getattr(adapter, "key", "generic")
    meta.provider_confidence = match.confidence
    meta.provider_reason = match.reason

    if meta.provider_key != "generic":
        meta.provider_detected = adapter.display_name
        meta.region_hint = adapter.region_hint(meta.endpoint_host)

    return meta

def parse_openvpn(content: str) -> ProfileIntelligence:
    remotes = []
    proto = dev = auth_mode = cipher = tls_mode = None

    for raw in content.splitlines():
        line = _clean(raw)
        if not line or line.startswith("<"):
            continue
        parts = line.split()
        if not parts:
            continue
        key = parts[0].lower()

        if key == "remote" and len(parts) >= 2:
            port = None
            if len(parts) >= 3:
                try:
                    port = int(parts[2])
                except ValueError:
                    pass
            remotes.append((parts[1], port))
        elif key == "proto" and len(parts) >= 2:
            proto = parts[1].lower()
        elif key == "dev" and len(parts) >= 2:
            dev = parts[1]
        elif key in ("cipher", "data-ciphers") and len(parts) >= 2 and not cipher:
            cipher = " ".join(parts[1:])
        elif key == "auth-user-pass":
            auth_mode = "Username/password"
        elif key == "auth-nocache" and auth_mode is None:
            auth_mode = "Credential auth"
        elif key in ("tls-auth", "tls-crypt", "tls-crypt-v2"):
            tls_mode = key

    host, port = remotes[0] if remotes else (None, None)
    endpoint_is_ip = False
    if host:
        try:
            ipaddress.ip_address(host)
            endpoint_is_ip = True
        except ValueError:
            pass

    transport = None
    if proto:
        transport = "UDP" if "udp" in proto else ("TCP" if "tcp" in proto else proto.upper())

    return _apply_provider_metadata(
        ProfileIntelligence(
            endpoint_host=host,
            endpoint_port=port,
            protocol=proto.upper() if proto else None,
            device=dev,
            transport=transport,
            auth_mode=auth_mode,
            cipher=cipher,
            tls_mode=tls_mode,
            remote_count=len(remotes),
            endpoint_is_ip=endpoint_is_ip,
        ),
        content,
    )

def parse_wireguard(content: str) -> ProfileIntelligence:
    endpoint = None
    for raw in content.splitlines():
        line = _clean(raw)
        if line.lower().startswith("endpoint") and "=" in line:
            endpoint = line.split("=", 1)[1].strip()
            break

    host = None
    port = None
    if endpoint:
        raw_port = None
        if endpoint.startswith("[") and "]:" in endpoint:
            host, raw_port = endpoint[1:].split("]:", 1)
        elif endpoint.count(":") == 1:
            host, raw_port = endpoint.rsplit(":", 1)
        else:
            host = endpoint

        if raw_port:
            try:
                port = int(raw_port)
            except ValueError:
                pass

    endpoint_is_ip = False
    if host:
        try:
            ipaddress.ip_address(host)
            endpoint_is_ip = True
        except ValueError:
            pass

    return _apply_provider_metadata(
        ProfileIntelligence(
            endpoint_host=host,
            endpoint_port=port,
            protocol="WireGuard",
            device="wg",
            transport="UDP",
            auth_mode="Public key",
            remote_count=1 if endpoint else 0,
            endpoint_is_ip=endpoint_is_ip,
        ),
        content,
    )

def inspect_profile(profile, content: str) -> ProfileIntelligence:
    if profile.vpn_type == "openvpn":
        return parse_openvpn(content)
    if profile.vpn_type == "wireguard":
        return parse_wireguard(content)
    return ProfileIntelligence()

def display_provider(profile, intelligence: ProfileIntelligence) -> str:
    return profile.provider or intelligence.provider_detected or "Unknown"

def endpoint_label(intelligence: ProfileIntelligence) -> str:
    if not intelligence.endpoint_host:
        return "—"
    if intelligence.endpoint_port:
        return f"{intelligence.endpoint_host}:{intelligence.endpoint_port}"
    return intelligence.endpoint_host
