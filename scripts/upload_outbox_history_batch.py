from __future__ import annotations

import argparse
import hashlib
import json
import ssl
from pathlib import Path
from typing import Any

import httpx


def load_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != "gateway.outbox.history.batch.v1":
        raise ValueError("unsupported outbox history manifest schema")
    if not payload.get("batch_id"):
        raise ValueError("outbox history manifest is missing batch_id")
    plaintext = payload.get("plaintext") or {}
    if len(str(plaintext.get("sha256") or "")) != 64:
        raise ValueError("outbox history manifest plaintext SHA-256 is invalid")
    return payload


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_batch_file(manifest: dict[str, Any], batch_path: Path) -> None:
    expected_size = int(manifest["plaintext"]["size_bytes"])
    if batch_path.stat().st_size != expected_size:
        raise ValueError("history batch size does not match manifest")
    if sha256_file(batch_path) != str(manifest["plaintext"]["sha256"]):
        raise ValueError("history batch SHA-256 does not match manifest")


def verify_receipt(manifest: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "schema": "gateway.outbox.history.receipt.v1",
        "batch_id": manifest["batch_id"],
        "durable": True,
        "queryable": True,
        "event_count": int(manifest["event_count"]),
        "attempt_count": int(manifest["attempt_count"]),
        "realtime_reference_count": int(manifest.get("realtime_reference_count") or 0),
        "plaintext_sha256": manifest["plaintext"]["sha256"],
        "encryption": "AES-256-GCM",
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise ValueError(f"history store receipt mismatch for {key}")
    ciphertext_sha256 = str(receipt.get("ciphertext_sha256") or "")
    if len(ciphertext_sha256) != 64:
        raise ValueError("history store receipt ciphertext SHA-256 is invalid")
    if int(receipt.get("ciphertext_size_bytes") or 0) <= 0:
        raise ValueError("history store receipt ciphertext size is invalid")
    if not str(receipt.get("key_id") or ""):
        raise ValueError("history store receipt key id is missing")
    if not str(receipt.get("imported_at") or ""):
        raise ValueError("history store receipt import timestamp is missing")
    return receipt


def build_ssl_context(
    *,
    ca_cert_path: Path,
    client_cert_path: Path,
    client_key_path: Path,
) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(ca_cert_path))
    context.load_cert_chain(
        certfile=str(client_cert_path),
        keyfile=str(client_key_path),
    )
    return context


def upload_batch(
    *,
    base_url: str,
    manifest_path: Path,
    batch_path: Path,
    ca_cert_path: Path,
    client_cert_path: Path,
    client_key_path: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    verify_batch_file(manifest, batch_path)
    ssl_context = build_ssl_context(
        ca_cert_path=ca_cert_path,
        client_cert_path=client_cert_path,
        client_key_path=client_key_path,
    )
    with (
        httpx.Client(
            base_url=base_url.rstrip("/"),
            verify=ssl_context,
            timeout=httpx.Timeout(
                connect=min(timeout_seconds, 10.0),
                read=timeout_seconds,
                write=timeout_seconds,
                pool=min(timeout_seconds, 10.0),
            ),
            follow_redirects=False,
        ) as client,
        batch_path.open("rb") as batch_handle,
    ):
        response = client.post(
            "/v1/batches/import",
            data={"manifest_json": json.dumps(manifest, separators=(",", ":"), sort_keys=True)},
            files={
                "batch": (
                    batch_path.name,
                    batch_handle,
                    "application/octet-stream",
                )
            },
        )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise TypeError("history store receipt payload is invalid")
    return verify_receipt(manifest, payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--batch", required=True)
    parser.add_argument("--ca-cert", required=True)
    parser.add_argument("--client-cert", required=True)
    parser.add_argument("--client-key", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=3600.0)
    args = parser.parse_args()
    if not args.base_url.startswith("https://"):
        raise SystemExit("--base-url must use HTTPS")
    if args.timeout_seconds < 1.0:
        raise SystemExit("--timeout-seconds must be at least 1")
    receipt = upload_batch(
        base_url=args.base_url,
        manifest_path=Path(args.manifest),
        batch_path=Path(args.batch),
        ca_cert_path=Path(args.ca_cert),
        client_cert_path=Path(args.client_cert),
        client_key_path=Path(args.client_key),
        timeout_seconds=args.timeout_seconds,
    )
    print(json.dumps(receipt, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
