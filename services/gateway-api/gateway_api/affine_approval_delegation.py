from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .config import Settings, get_settings

AFFINE_APPROVAL_ASSERTION_AUDIENCE = "chatgpt-mcp-gateway:affine-approval-v1"
AFFINE_APPROVAL_ASSERTION_VERSION = 1


class AffineApprovalVoteAssertion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    v: Literal[1] = AFFINE_APPROVAL_ASSERTION_VERSION
    ts: int
    nonce: str = Field(min_length=16, max_length=160)
    m: Literal["POST"]
    p: str = Field(min_length=1, max_length=512)
    aud: Literal["chatgpt-mcp-gateway:affine-approval-v1"] = (
        AFFINE_APPROVAL_ASSERTION_AUDIENCE
    )
    affine_user_id: str = Field(min_length=1, max_length=160)
    approval_request_id: str = Field(min_length=1, max_length=160)
    decision: Literal["approve", "reject"]
    reason_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class AffineApprovalDelegationConfig:
    enabled: bool
    reviewer_map: dict[str, str]
    public_key_files: tuple[str, ...]
    assertion_ttl_seconds: int
    assertion_clock_skew_seconds: int

    @classmethod
    def from_settings(
        cls, settings: Settings | None = None
    ) -> AffineApprovalDelegationConfig:
        settings = settings or get_settings()
        try:
            raw_map = json.loads(
                settings.gateway_affine_approval_reviewer_map_json or "{}"
            )
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "AFFiNE approval reviewer map must be valid JSON"
            ) from exc
        if not isinstance(raw_map, dict):
            raise TypeError("AFFiNE approval reviewer map must be a JSON object")
        reviewer_map: dict[str, str] = {}
        for raw_subject, raw_user_id in raw_map.items():
            if not isinstance(raw_subject, str) or not isinstance(raw_user_id, str):
                raise TypeError("AFFiNE approval reviewer map entries must be strings")
            subject = raw_subject.strip()
            user_id = raw_user_id.strip()
            if not subject or not user_id:
                raise RuntimeError(
                    "AFFiNE approval reviewer map entries must be non-empty"
                )
            if len(subject) > 255 or len(user_id) > 160:
                raise RuntimeError(
                    "AFFiNE approval reviewer map entries exceed length limits"
                )
            if subject in reviewer_map:
                raise RuntimeError("AFFiNE approval reviewer subjects must be unique")
            reviewer_map[subject] = user_id
        reverse = list(reviewer_map.values())
        if len(set(reverse)) != len(reverse):
            raise RuntimeError("AFFiNE approval reviewer user ids must be one-to-one")
        public_key_files = tuple(
            value.strip()
            for value in settings.gateway_affine_approval_public_key_files.split(",")
            if value.strip()
        )
        if len(public_key_files) > 2:
            raise RuntimeError(
                "AFFiNE approval vote bridge supports at most two public keys"
            )
        config = cls(
            enabled=settings.gateway_affine_approval_vote_bridge_enabled,
            reviewer_map=reviewer_map,
            public_key_files=public_key_files,
            assertion_ttl_seconds=settings.gateway_affine_approval_assertion_ttl_seconds,
            assertion_clock_skew_seconds=settings.gateway_affine_approval_assertion_clock_skew_seconds,
        )
        if config.enabled:
            if not config.reviewer_map:
                raise RuntimeError(
                    "AFFiNE approval vote bridge requires reviewer mappings"
                )
            if not config.public_key_files:
                raise RuntimeError(
                    "AFFiNE approval vote bridge requires public key files"
                )
        return config

    def gateway_subject_for_user(self, affine_user_id: str) -> str | None:
        matches = [
            subject
            for subject, user_id in self.reviewer_map.items()
            if user_id == affine_user_id
        ]
        return matches[0] if len(matches) == 1 else None


def reason_sha256(reason: str | None) -> str:
    return hashlib.sha256((reason or "").encode("utf-8")).hexdigest()


def reviewer_bindings(
    subjects: list[str], *, config: AffineApprovalDelegationConfig
) -> tuple[list[dict[str, str]], int]:
    bindings: list[dict[str, str]] = []
    unmapped = 0
    for subject in subjects:
        affine_user_id = config.reviewer_map.get(subject)
        if affine_user_id is None:
            unmapped += 1
            continue
        bindings.append({"gateway_subject": subject, "affine_user_id": affine_user_id})
    return bindings, unmapped


def _verify_signature(data: bytes, signature: bytes, public_key_file: str) -> bool:
    try:
        key = load_pem_public_key(Path(public_key_file).read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError(
            f"Unable to load configured AFFiNE approval public key: {public_key_file}"
        ) from exc
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            if not isinstance(key.curve, ec.SECP256R1):
                raise TypeError("AFFiNE approval EC public key must use P-256")
            key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, data)
        else:
            raise TypeError("AFFiNE approval public key must be EC or Ed25519")
    except InvalidSignature:
        return False
    return True


def verify_affine_approval_assertion(
    assertion: str,
    *,
    method: str,
    path: str,
    approval_request_id: str,
    decision: Literal["approve", "reject"],
    reason: str | None,
    settings: Settings | None = None,
    now_ms: int | None = None,
) -> tuple[AffineApprovalVoteAssertion, str]:
    config = AffineApprovalDelegationConfig.from_settings(settings)
    if not config.enabled:
        raise HTTPException(
            status_code=404, detail="AFFiNE approval vote bridge is disabled"
        )
    try:
        data_text, signature_text = assertion.rsplit(",", 1)
        data = data_text.encode("utf-8")
        signature = base64.b64decode(signature_text, validate=True)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=401, detail="Invalid AFFiNE approval assertion"
        ) from exc
    if not any(
        _verify_signature(data, signature, public_key_file)
        for public_key_file in config.public_key_files
    ):
        raise HTTPException(status_code=401, detail="Invalid AFFiNE approval assertion")
    try:
        payload = json.loads(
            base64.urlsafe_b64decode(data_text + "=" * (-len(data_text) % 4))
        )
        parsed = AffineApprovalVoteAssertion.model_validate(payload)
    except (ValueError, TypeError, json.JSONDecodeError, ValidationError) as exc:
        raise HTTPException(
            status_code=401, detail="Invalid AFFiNE approval assertion"
        ) from exc
    now_ms = int(time.time() * 1000) if now_ms is None else int(now_ms)
    age_ms = now_ms - parsed.ts
    max_age_ms = config.assertion_ttl_seconds * 1000
    skew_ms = config.assertion_clock_skew_seconds * 1000
    if age_ms < -skew_ms or age_ms > max_age_ms + skew_ms:
        raise HTTPException(status_code=401, detail="Expired AFFiNE approval assertion")
    if parsed.m != method.upper() or parsed.p != path:
        raise HTTPException(
            status_code=401, detail="AFFiNE approval assertion target mismatch"
        )
    if parsed.approval_request_id != approval_request_id:
        raise HTTPException(
            status_code=401, detail="AFFiNE approval assertion request mismatch"
        )
    if parsed.decision != decision or parsed.reason_sha256 != reason_sha256(reason):
        raise HTTPException(
            status_code=401, detail="AFFiNE approval assertion payload mismatch"
        )
    subject = config.gateway_subject_for_user(parsed.affine_user_id)
    if subject is None:
        raise HTTPException(
            status_code=403, detail="AFFiNE reviewer identity is not mapped"
        )
    return parsed, subject
