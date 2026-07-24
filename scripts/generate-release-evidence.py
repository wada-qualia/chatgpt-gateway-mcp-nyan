#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_image(reference: str) -> dict:
    raw = subprocess.check_output(["docker", "image", "inspect", reference], text=True)
    payload = json.loads(raw)
    if not isinstance(payload, list) or len(payload) != 1:
        raise ValueError("expected exactly one Docker image")
    return payload[0]


def docker_archive_config_digest(path: Path, expected_reference: str) -> str:
    with tarfile.open(path, mode="r:gz") as archive:
        manifest_member = archive.getmember("manifest.json")
        if not manifest_member.isfile() or manifest_member.size > 1024 * 1024:
            raise ValueError("invalid Docker archive manifest")
        manifest_handle = archive.extractfile(manifest_member)
        if manifest_handle is None:
            raise ValueError("missing Docker archive manifest")
        manifest = json.loads(manifest_handle.read().decode("utf-8"))
        if not isinstance(manifest, list):
            raise ValueError("invalid Docker archive manifest payload")
        matches = [
            entry
            for entry in manifest
            if isinstance(entry, dict)
            and expected_reference in (entry.get("RepoTags") or [])
        ]
        if len(matches) != 1:
            raise ValueError("expected exactly one matching image in Docker archive")
        config_name = matches[0].get("Config")
        if not isinstance(config_name, str):
            raise ValueError("Docker archive config path is missing")
        config_path = PurePosixPath(config_name)
        if config_path.is_absolute() or ".." in config_path.parts:
            raise ValueError("unsafe Docker archive config path")
        config_member = archive.getmember(config_name)
        if not config_member.isfile() or config_member.size > 16 * 1024 * 1024:
            raise ValueError("invalid Docker archive image config")
        config_handle = archive.extractfile(config_member)
        if config_handle is None:
            raise ValueError("missing Docker archive image config")
        config_bytes = config_handle.read()
    config: Any = json.loads(config_bytes.decode("utf-8"))
    if not isinstance(config, dict):
        raise ValueError("invalid Docker archive image config payload")
    return f"sha256:{hashlib.sha256(config_bytes).hexdigest()}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--production-audit", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    image = inspect_image(args.image)
    labels = image.get("Config", {}).get("Labels") or {}
    if labels.get("org.opencontainers.image.revision") != args.commit:
        raise ValueError("image revision label mismatch")
    if labels.get("org.opencontainers.image.version") != args.version:
        raise ValueError("image version label mismatch")

    audit = json.loads(args.production_audit.read_text(encoding="utf-8"))
    vulnerabilities = audit.get("metadata", {}).get("vulnerabilities")
    if not isinstance(vulnerabilities, dict) or vulnerabilities.get("total") != 0:
        raise ValueError("production dependency audit is not clean")

    saved_config_digest = docker_archive_config_digest(args.archive, args.image)

    public_key_fingerprint = subprocess.check_output(
        ["ssh-keygen", "-lf", str(args.public_key), "-E", "sha256"],
        text=True,
    ).split()[1]

    manifest = {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "release": {
            "name": "chatgpt-mcp-ssh-gateway",
            "version": args.version,
            "source_commit": args.commit,
        },
        "image": {
            "reference": args.image,
            "image_id": image["Id"],
            "saved_config_digest": saved_config_digest,
            "os": image["Os"],
            "architecture": image["Architecture"],
            "size_bytes": image["Size"],
            "created_at": image["Created"],
            "labels": {
                "org.opencontainers.image.version": labels[
                    "org.opencontainers.image.version"
                ],
                "org.opencontainers.image.revision": labels[
                    "org.opencontainers.image.revision"
                ],
            },
        },
        "archive": {
            "filename": args.archive.name,
            "format": "docker-image-save+gzip-n",
            "sha256": sha256(args.archive),
            "size_bytes": args.archive.stat().st_size,
        },
        "security": {
            "production_dependency_audit": {
                "filename": args.production_audit.name,
                "sha256": sha256(args.production_audit),
                "vulnerabilities": vulnerabilities,
            }
        },
        "deployment": {
            "pipeline": "origin/prod -> Jenkins -> MKS two-phase blue-green",
            "candidate_requires_signed_thin_client_compatibility": True,
            "candidate_restart_executed_by_jenkins": True,
            "production_router_switched": False,
        },
        "signing": {
            "format": "OpenSSH SSHSIG",
            "namespace": "gateway-release",
            "public_key_filename": "release-signing-key.pub",
            "public_key_fingerprint": public_key_fingerprint,
            "private_key_exported": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "manifest": str(args.output),
                "image_id": image["Id"],
                "saved_config_digest": saved_config_digest,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
