import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException
from gateway_api.affine_approval_delegation import (
    AFFINE_APPROVAL_ASSERTION_AUDIENCE,
    AffineApprovalDelegationConfig,
    reason_sha256,
    reviewer_bindings,
    verify_affine_approval_assertion,
)
from gateway_api.config import Settings


def _keypair(
    tmp_path: Path, name: str = "affine"
) -> tuple[ec.EllipticCurvePrivateKey, Path]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_file = tmp_path / f"{name}.public.pem"
    public_key_file.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_key, public_key_file


def _settings(public_key_file: Path, **overrides) -> Settings:
    values = {
        "gateway_affine_approval_vote_bridge_enabled": True,
        "gateway_affine_approval_reviewer_map_json": json.dumps(
            {"gateway-reviewer": "affine-user-1"}
        ),
        "gateway_affine_approval_public_key_files": str(public_key_file),
        "gateway_affine_approval_assertion_ttl_seconds": 60,
        "gateway_affine_approval_assertion_clock_skew_seconds": 5,
    }
    values.update(overrides)
    return Settings(**values)


def _assertion(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    now_ms: int,
    request_id: str = "approval-1",
    decision: str = "approve",
    reason: str | None = "looks good",
    path: str = "/api/agent-autonomy/affine/v1/approvals/approval-1/votes",
    affine_user_id: str = "affine-user-1",
) -> str:
    payload = {
        "v": 1,
        "ts": now_ms,
        "nonce": "nonce-1234567890abcdef",
        "m": "POST",
        "p": path,
        "aud": AFFINE_APPROVAL_ASSERTION_AUDIENCE,
        "affine_user_id": affine_user_id,
        "approval_request_id": request_id,
        "decision": decision,
        "reason_sha256": reason_sha256(reason),
    }
    encoded = (
        base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )
    signature = private_key.sign(encoded.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return f"{encoded},{base64.b64encode(signature).decode('ascii')}"


def test_affine_vote_assertion_verifies_bound_identity_and_payload(
    tmp_path: Path,
) -> None:
    private_key, public_key_file = _keypair(tmp_path)
    now_ms = 1_800_000_000_000
    assertion = _assertion(private_key, now_ms=now_ms)

    parsed, subject = verify_affine_approval_assertion(
        assertion,
        method="POST",
        path="/api/agent-autonomy/affine/v1/approvals/approval-1/votes",
        approval_request_id="approval-1",
        decision="approve",
        reason="looks good",
        settings=_settings(public_key_file),
        now_ms=now_ms + 1_000,
    )

    assert subject == "gateway-reviewer"
    assert parsed.affine_user_id == "affine-user-1"
    assert parsed.approval_request_id == "approval-1"


@pytest.mark.parametrize(
    ("field", "value", "detail"),
    [
        (
            "path",
            "/api/agent-autonomy/affine/v1/approvals/other/votes",
            "target mismatch",
        ),
        ("approval_request_id", "other", "request mismatch"),
        ("reason", "changed", "payload mismatch"),
        ("decision", "reject", "payload mismatch"),
    ],
)
def test_affine_vote_assertion_rejects_bound_payload_tampering(
    tmp_path: Path, field: str, value: str, detail: str
) -> None:
    private_key, public_key_file = _keypair(tmp_path)
    now_ms = 1_800_000_000_000
    assertion = _assertion(private_key, now_ms=now_ms)
    arguments = {
        "method": "POST",
        "path": "/api/agent-autonomy/affine/v1/approvals/approval-1/votes",
        "approval_request_id": "approval-1",
        "decision": "approve",
        "reason": "looks good",
        "settings": _settings(public_key_file),
        "now_ms": now_ms,
    }
    arguments[field] = value
    with pytest.raises(HTTPException, match=detail):
        verify_affine_approval_assertion(assertion, **arguments)


def test_affine_vote_assertion_rejects_expiry_and_wrong_key(tmp_path: Path) -> None:
    private_key, public_key_file = _keypair(tmp_path, "expected")
    _, wrong_public_key_file = _keypair(tmp_path, "wrong")
    now_ms = 1_800_000_000_000
    assertion = _assertion(private_key, now_ms=now_ms)
    common = {
        "method": "POST",
        "path": "/api/agent-autonomy/affine/v1/approvals/approval-1/votes",
        "approval_request_id": "approval-1",
        "decision": "approve",
        "reason": "looks good",
    }

    with pytest.raises(HTTPException, match="Expired"):
        verify_affine_approval_assertion(
            assertion,
            settings=_settings(public_key_file),
            now_ms=now_ms + 66_000,
            **common,
        )
    with pytest.raises(HTTPException, match="Invalid AFFiNE approval assertion"):
        verify_affine_approval_assertion(
            assertion,
            settings=_settings(wrong_public_key_file),
            now_ms=now_ms,
            **common,
        )


def test_affine_delegation_config_is_one_to_one_and_rotation_is_bounded(
    tmp_path: Path,
) -> None:
    _, public_key_file = _keypair(tmp_path, "one")
    _, second = _keypair(tmp_path, "two")
    _, third = _keypair(tmp_path, "three")

    with pytest.raises(RuntimeError, match="one-to-one"):
        AffineApprovalDelegationConfig.from_settings(
            _settings(
                public_key_file,
                gateway_affine_approval_reviewer_map_json=json.dumps(
                    {"reviewer-a": "affine-user", "reviewer-b": "affine-user"}
                ),
            )
        )
    with pytest.raises(RuntimeError, match="at most two"):
        AffineApprovalDelegationConfig.from_settings(
            _settings(
                public_key_file,
                gateway_affine_approval_public_key_files=",".join(
                    [str(public_key_file), str(second), str(third)]
                ),
            )
        )


def test_reviewer_bindings_expose_only_explicit_mappings() -> None:
    config = AffineApprovalDelegationConfig(
        enabled=False,
        reviewer_map={"reviewer-a": "affine-a"},
        public_key_files=(),
        assertion_ttl_seconds=60,
        assertion_clock_skew_seconds=5,
    )
    bindings, unmapped = reviewer_bindings(
        ["reviewer-a", "reviewer-unmapped"], config=config
    )
    assert bindings == [{"gateway_subject": "reviewer-a", "affine_user_id": "affine-a"}]
    assert unmapped == 1
