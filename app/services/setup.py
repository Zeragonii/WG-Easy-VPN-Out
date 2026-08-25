from __future__ import annotations
import os
from pathlib import Path
import secrets


def token_path():
    root = Path(os.getenv("VPN_ROUTER_DATA_DIR", "/data")) / "runtime"
    root.mkdir(parents=True, exist_ok=True)
    return root / "setup-token"


def ensure_setup_token(logger=None):
    path = token_path()
    try:
        existing = path.read_text(encoding="utf-8").strip()
    except OSError:
        existing = ""
    if existing:
        return existing

    token = "-".join(
        secrets.token_hex(2).upper()
        for _ in range(4)
    )
    path.write_text(token + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    if logger:
        logger.warning("=" * 72)
        logger.warning("INITIAL SETUP REQUIRED")
        logger.warning("Setup token: %s", token)
        logger.warning("Open the VPN Router web UI and enter this token.")
        logger.warning("=" * 72)
    return token


def validate_setup_token(candidate):
    try:
        expected = token_path().read_text(encoding="utf-8").strip()
    except OSError:
        return False
    return bool(expected and secrets.compare_digest(expected, (candidate or "").strip()))


def remove_setup_token():
    try:
        token_path().unlink(missing_ok=True)
    except OSError:
        pass
