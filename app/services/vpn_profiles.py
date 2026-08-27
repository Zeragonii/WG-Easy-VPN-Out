from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import re
class VPNProfileValidationError(ValueError): pass
@dataclass(slots=True)
class ValidationResult:
    valid: bool
    summary: list[str]
    warnings: list[str]
OPENVPN_REMOTE_RE=re.compile(r"^\s*remote\s+(\S+)(?:\s+(\d+))?",re.I|re.M)
WG_INTERFACE_RE=re.compile(r"^\s*\[Interface\]\s*$",re.I|re.M)
WG_PEER_RE=re.compile(r"^\s*\[Peer\]\s*$",re.I|re.M)
WG_ENDPOINT_RE=re.compile(r"^\s*Endpoint\s*=\s*(.+)$",re.I|re.M)
def safe_filename(name:str)->str:
    name=Path(name).name
    cleaned=re.sub(r"[^A-Za-z0-9._-]+","_",name).strip("._")
    if not cleaned: raise VPNProfileValidationError("The uploaded filename is not usable.")
    return cleaned[:180]
def detect_type(filename:str,content:str)->str:
    suffix=Path(filename).suffix.lower()
    if suffix=='.ovpn': return 'openvpn'
    if suffix=='.conf' and WG_INTERFACE_RE.search(content) and WG_PEER_RE.search(content): return 'wireguard'
    if OPENVPN_REMOTE_RE.search(content) and re.search(r"^\s*client\s*$",content,re.I|re.M): return 'openvpn'
    if WG_INTERFACE_RE.search(content) and WG_PEER_RE.search(content): return 'wireguard'
    raise VPNProfileValidationError("Could not identify this as an OpenVPN or WireGuard client config.")
def validate_openvpn(content:str)->ValidationResult:
    summary=[]; warnings=[]; remotes=OPENVPN_REMOTE_RE.findall(content)
    if not remotes: raise VPNProfileValidationError("OpenVPN configuration has no remote endpoint.")
    host,port=remotes[0]; summary.append(f"Remote endpoint found: {host}:{port or 'default'}")
    if re.search(r"^\s*dev\s+tun",content,re.I|re.M): summary.append("TUN mode detected.")
    elif re.search(r"^\s*dev\s+tap",content,re.I|re.M): warnings.append("TAP mode detected; this project is intended for routed TUN VPNs.")
    else: warnings.append("No explicit dev tun/tap directive found.")
    if re.search(r"^\s*redirect-gateway\b",content,re.I|re.M): warnings.append("redirect-gateway is present; v0.3.1 will suppress global default-route takeover.")
    if re.search(r"^\s*auth-user-pass(?:\s|$)",content,re.I|re.M): summary.append("Username/password authentication requested.")
    if '<ca>' in content.lower() or re.search(r"^\s*ca\s+",content,re.I|re.M): summary.append("CA configuration found.")
    return ValidationResult(True,summary,warnings)
def validate_wireguard(content:str)->ValidationResult:
    summary=[]; warnings=[]
    if not WG_INTERFACE_RE.search(content):
        raise VPNProfileValidationError("WireGuard configuration has no [Interface] section.")
    if not WG_PEER_RE.search(content):
        raise VPNProfileValidationError("WireGuard configuration has no [Peer] section.")

    endpoint=WG_ENDPOINT_RE.search(content)
    if endpoint:
        summary.append(f"Peer endpoint found: {endpoint.group(1).strip()}")
    else:
        raise VPNProfileValidationError("WireGuard configuration has no Endpoint= line.")

    if re.search(r"^\s*PrivateKey\s*=",content,re.I|re.M):
        summary.append("Private key found.")
    else:
        raise VPNProfileValidationError("WireGuard configuration has no PrivateKey= line.")

    address = re.search(r"^\s*Address\s*=\s*(.+)$", content, re.I|re.M)
    if not address:
        raise VPNProfileValidationError("WireGuard configuration has no Address= line.")
    if not any(":" not in item for item in address.group(1).split(",")):
        raise VPNProfileValidationError("WireGuard runtime currently requires an IPv4 Address= value.")
    summary.append(f"Interface address found: {address.group(1).strip()}")

    allowed = re.search(r"^\s*AllowedIPs\s*=\s*(.+)$", content, re.I|re.M)
    if not allowed:
        raise VPNProfileValidationError("WireGuard configuration has no AllowedIPs= line.")
    if "0.0.0.0/0" in allowed.group(1):
        summary.append("Full-tunnel IPv4 AllowedIPs detected.")
        warnings.append(
            "The provider default route will be isolated inside VPN Router policy tables; "
            "the host default route will not be replaced."
        )
    else:
        warnings.append(
            "AllowedIPs does not include 0.0.0.0/0. Internet policy routing may not work "
            "unless the provider config permits the destination ranges you need."
        )

    if re.search(r"^\s*(PostUp|PostDown|PreUp|PreDown)\s*=", content, re.I|re.M):
        warnings.append(
            "wg-quick hook commands are intentionally ignored; VPN Router owns routing/NAT lifecycle."
        )

    if re.search(r"^\s*DNS\s*=", content, re.I|re.M):
        summary.append(
            "Provider DNS declaration found; imported for visibility only. "
            "Routing Group DNS policy remains authoritative."
        )

    return ValidationResult(True,summary,warnings)
def validate_config(filename:str,content:str,vpn_type:str|None=None):
    detected=vpn_type or detect_type(filename,content)
    if detected=='openvpn': return detected,validate_openvpn(content)
    if detected=='wireguard': return detected,validate_wireguard(content)
    raise VPNProfileValidationError(f"Unsupported VPN type: {detected}")
