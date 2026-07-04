from __future__ import annotations

import base64
import hashlib
import logging
import secrets

from cryptography.fernet import Fernet

from .config import get_settings

logger = logging.getLogger(__name__)


def _normalize_fernet_key(value: str | None) -> bytes:
    if value:
        raw = value.encode("utf-8")
        try:
            Fernet(raw)
            return raw
        except Exception:
            digest = hashlib.sha256(raw).digest()
            return base64.urlsafe_b64encode(digest)
    generated = Fernet.generate_key()
    logger.warning("GATEWAY_SECRET_KEY is not set. Encrypted blobs are tied to this process only.")
    return generated


_fernet = Fernet(_normalize_fernet_key(get_settings().gateway_secret_key))


def encrypt_text(value: str) -> str:
    return _fernet.encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_text(value: str) -> str:
    return _fernet.decrypt(value.encode("ascii")).decode("utf-8")


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_token(prefix: str = "") -> str:
    token = secrets.token_urlsafe(32)
    return f"{prefix}{token}" if prefix else token
