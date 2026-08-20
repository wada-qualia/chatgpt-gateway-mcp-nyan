from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Self

import pytest

script_path = Path(__file__).resolve().parents[3] / "scripts" / "upload_outbox_history_batch.py"
spec = importlib.util.spec_from_file_location("upload_outbox_history_batch", script_path)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
build_ssl_context = module.build_ssl_context
load_manifest = module.load_manifest
verify_batch_file = module.verify_batch_file
verify_receipt = module.verify_receipt


def manifest_payload() -> dict:
    return {
        "schema": "gateway.outbox.history.batch.v1",
        "batch_id": "11111111-1111-4111-8111-111111111111",
        "event_count": 3,
        "attempt_count": 4,
        "realtime_reference_count": 2,
        "plaintext": {
            "sha256": "a" * 64,
            "size_bytes": 4096,
        },
    }


def receipt_payload() -> dict:
    return {
        "schema": "gateway.outbox.history.receipt.v1",
        "batch_id": "11111111-1111-4111-8111-111111111111",
        "durable": True,
        "queryable": True,
        "event_count": 3,
        "attempt_count": 4,
        "realtime_reference_count": 2,
        "plaintext_sha256": "a" * 64,
        "ciphertext_sha256": "b" * 64,
        "ciphertext_size_bytes": 4200,
        "encryption": "AES-256-GCM",
        "key_id": "gateway-history-v1",
        "imported_at": "2026-08-19T20:00:00+00:00",
    }


def test_verify_receipt_accepts_exact_durable_queryable_binding(tmp_path: Path) -> None:
    manifest = manifest_payload()
    manifest_path = tmp_path / "batch.manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    loaded = load_manifest(manifest_path)
    receipt = receipt_payload()
    assert verify_receipt(loaded, receipt) == receipt


def test_verify_batch_file_rejects_same_size_tamper(tmp_path: Path) -> None:
    batch_path = tmp_path / "batch.sqlite3"
    expected = b"expected"
    batch_path.write_bytes(expected)
    manifest = manifest_payload()
    manifest["plaintext"] = {
        "sha256": hashlib.sha256(expected).hexdigest(),
        "size_bytes": len(expected),
    }
    verify_batch_file(manifest, batch_path)
    batch_path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="SHA-256"):
        verify_batch_file(manifest, batch_path)


def test_verify_receipt_rejects_mismatched_or_incomplete_binding() -> None:
    manifest = manifest_payload()
    for key, value in (
        ("batch_id", "22222222-2222-4222-8222-222222222222"),
        ("durable", False),
        ("queryable", False),
        ("event_count", 2),
        ("attempt_count", 3),
        ("realtime_reference_count", 1),
        ("plaintext_sha256", "c" * 64),
        ("encryption", "none"),
    ):
        receipt = receipt_payload()
        receipt[key] = value
        with pytest.raises(ValueError, match=key):
            verify_receipt(manifest, receipt)
    receipt = receipt_payload()
    receipt["ciphertext_sha256"] = "short"
    with pytest.raises(ValueError, match="ciphertext SHA-256"):
        verify_receipt(manifest, receipt)
    receipt = receipt_payload()
    receipt["ciphertext_size_bytes"] = 0
    with pytest.raises(ValueError, match="ciphertext size"):
        verify_receipt(manifest, receipt)
    receipt = receipt_payload()
    receipt["key_id"] = ""
    with pytest.raises(ValueError, match="key id"):
        verify_receipt(manifest, receipt)


def test_build_ssl_context_loads_ca_and_client_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, str] = {}

    class FakeContext:
        def load_cert_chain(self, *, certfile: str, keyfile: str) -> None:
            calls["certfile"] = certfile
            calls["keyfile"] = keyfile

    context = FakeContext()

    def fake_create_default_context(*, cafile: str) -> FakeContext:
        calls["cafile"] = cafile
        return context

    monkeypatch.setattr(module.ssl, "create_default_context", fake_create_default_context)
    result = build_ssl_context(
        ca_cert_path=Path("/pki/ca.crt"),
        client_cert_path=Path("/pki/writer.crt"),
        client_key_path=Path("/pki/writer.key"),
    )

    assert result is context
    assert calls == {
        "cafile": "/pki/ca.crt",
        "certfile": "/pki/writer.crt",
        "keyfile": "/pki/writer.key",
    }


def test_upload_batch_passes_bound_mtls_context_to_httpx(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ssl_context = object()
    client_kwargs: dict = {}
    post_kwargs: dict = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return expected_receipt

    class FakeClient:
        def __init__(self, **kwargs) -> None:
            client_kwargs.update(kwargs)

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args) -> None:
            return None

        def post(self, path: str, **kwargs) -> FakeResponse:
            post_kwargs["path"] = path
            post_kwargs.update(kwargs)
            return FakeResponse()

    manifest = manifest_payload()
    batch_path = tmp_path / "batch.sqlite3"
    batch_path.write_bytes(b"payload")
    manifest["plaintext"] = {
        "sha256": hashlib.sha256(b"payload").hexdigest(),
        "size_bytes": len(b"payload"),
    }
    expected_receipt = receipt_payload()
    expected_receipt["plaintext_sha256"] = manifest["plaintext"]["sha256"]
    manifest_path = tmp_path / "batch.manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(module, "build_ssl_context", lambda **kwargs: ssl_context)
    monkeypatch.setattr(module.httpx, "Client", FakeClient)

    receipt = module.upload_batch(
        base_url="https://history.example",
        manifest_path=manifest_path,
        batch_path=batch_path,
        ca_cert_path=Path("/pki/ca.crt"),
        client_cert_path=Path("/pki/writer.crt"),
        client_key_path=Path("/pki/writer.key"),
        timeout_seconds=15.0,
    )

    assert receipt == expected_receipt
    assert client_kwargs["verify"] is ssl_context
    assert "cert" not in client_kwargs
    assert post_kwargs["path"] == "/v1/batches/import"
    assert "manifest_json" in post_kwargs["data"]
    assert "batch" in post_kwargs["files"]
