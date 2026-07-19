from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet

from .config import get_settings

logger = logging.getLogger(__name__)


def _normalize_fernet_key(value: str) -> bytes:
    raw = value.encode("utf-8")
    try:
        Fernet(raw)
        return raw
    except Exception:
        digest = hashlib.sha256(raw).digest()
        return base64.urlsafe_b64encode(digest)


def _load_or_create_fernet_key(value: str | None, key_file: str) -> bytes:
    if value:
        return _normalize_fernet_key(value)

    path = Path(key_file).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        stored = path.read_text(encoding="utf-8").strip()
        if stored:
            return _normalize_fernet_key(stored)

    generated = Fernet.generate_key()
    try:
        with path.open("xb") as handle:
            handle.write(generated + b"\n")
    except FileExistsError:
        stored = path.read_text(encoding="utf-8").strip()
        if stored:
            return _normalize_fernet_key(stored)
        path.write_bytes(generated + b"\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        logger.warning("Could not restrict permissions on gateway secret key file %s", path)
    logger.info("Generated persistent gateway encryption key at %s", path)
    return generated


_settings = get_settings()
_fernet = Fernet(_load_or_create_fernet_key(_settings.gateway_secret_key, _settings.gateway_secret_key_file))


def encrypt_text(value: str) -> str:
    return _fernet.encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_text(value: str) -> str:
    return _fernet.decrypt(value.encode("ascii")).decode("utf-8")


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_token(prefix: str = "") -> str:
    token = secrets.token_urlsafe(32)
    return f"{prefix}{token}" if prefix else token
