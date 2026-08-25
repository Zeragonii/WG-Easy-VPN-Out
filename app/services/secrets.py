from __future__ import annotations

import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken


PREFIX = "enc:v1:"


def _fernet() -> Fernet:
    secret_key = os.environ["SECRET_KEY"].encode("utf-8")
    digest = hashlib.sha256(secret_key).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(value: str | None) -> str | None:
    if not value:
        return None
    if value.startswith(PREFIX):
        return value
    token = _fernet().encrypt(value.encode("utf-8")).decode("ascii")
    return PREFIX + token


def decrypt_secret(value: str | None) -> str | None:
    if not value:
        return None
    if not value.startswith(PREFIX):
        # Legacy v0.3.x plaintext value. Startup migration will normally
        # convert these, but accepting them keeps upgrades recoverable.
        return value
    token = value[len(PREFIX):]
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError(
            "Stored VPN credential cannot be decrypted. "
            "Has SECRET_KEY changed since it was saved?"
        ) from exc


def migrate_legacy_profile_passwords(db, VPNProfile) -> int:
    changed = 0
    profiles = db.session.execute(
        db.select(VPNProfile).where(VPNProfile.password.is_not(None))
    ).scalars().all()

    for profile in profiles:
        if profile.password and not profile.password.startswith(PREFIX):
            profile.password = encrypt_secret(profile.password)
            changed += 1

    if changed:
        db.session.commit()

    return changed
