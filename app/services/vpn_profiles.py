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
    if not WG_INTERFACE_RE.search(content): raise VPNProfileValidationError("WireGuard configuration has no [Interface] section.")
    if not WG_PEER_RE.search(content): raise VPNProfileValidationError("WireGuard configuration has no [Peer] section.")
    endpoint=WG_ENDPOINT_RE.search(content)
    if endpoint: summary.append(f"Peer endpoint found: {endpoint.group(1).strip()}")
    else: warnings.append("No Endpoint= line found.")
    if re.search(r"^\s*PrivateKey\s*=",content,re.I|re.M): summary.append("Private key found.")
    else: warnings.append("No PrivateKey= line found.")
    if re.search(r"^\s*AllowedIPs\s*=\s*.*0\.0\.0\.0/0",content,re.I|re.M): warnings.append("AllowedIPs includes 0.0.0.0/0; later startup will isolate it from the host default route.")
    return ValidationResult(True,summary,warnings)
def validate_config(filename:str,content:str,vpn_type:str|None=None):
    detected=vpn_type or detect_type(filename,content)
    if detected=='openvpn': return detected,validate_openvpn(content)
    if detected=='wireguard': return detected,validate_wireguard(content)
    raise VPNProfileValidationError(f"Unsupported VPN type: {detected}")
