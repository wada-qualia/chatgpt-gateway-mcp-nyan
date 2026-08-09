from __future__ import annotations

import hashlib
import json
import sys
import tomllib
import zipfile
from dataclasses import dataclass
from email.parser import Parser
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class PythonSdkArtifactSpec:
    label: str
    tool_key: str
    artifact_dir: str
    package: str
    version: str
    requires_python: str
    source_commit: str
    publication_channel: str


def _fail(spec: PythonSdkArtifactSpec, message: str) -> None:
    raise SystemExit(f"{spec.label} SDK verification failed: {message}")


def verify_python_sdk_artifact(
    root: Path, spec: PythonSdkArtifactSpec
) -> dict[str, Any]:
    if not ((3, 12) <= sys.version_info[:2] < (3, 15)):
        _fail(
            spec,
            f"Python {sys.version_info.major}.{sys.version_info.minor} is outside >=3.12,<3.15",
        )

    artifact_dir = root / spec.artifact_dir
    manifest_path = artifact_dir / "python-sdk-release.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        _fail(spec, f"invalid release manifest: {error}")

    try:
        project_metadata = tomllib.loads(
            (root / "pyproject.toml").read_text(encoding="utf-8")
        )
        sdk_metadata = project_metadata["tool"]["klab"][spec.tool_key]
    except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        _fail(spec, f"invalid project SDK metadata: {error}")

    wheel_info = manifest.get("wheel") or {}
    source_info = manifest.get("source") or {}
    publication = manifest.get("publication") or {}
    if manifest.get("package") != spec.package:
        _fail(spec, "unexpected package name")
    if manifest.get("version") != spec.version:
        _fail(spec, "unexpected package version")
    if manifest.get("requires_python") != spec.requires_python:
        _fail(spec, "unexpected Python compatibility range")
    if source_info.get("commit") != spec.source_commit:
        _fail(spec, "source commit is not the qualified immutable commit")
    if publication.get("channel") != spec.publication_channel:
        _fail(spec, "unexpected publication channel")
    if (
        publication.get("immutable") is not True
        or publication.get("public_index_allowed") is not False
    ):
        _fail(spec, "publication policy is not immutable and internal-only")

    project_dependencies = project_metadata.get("project", {}).get("dependencies", [])
    normalized_package = spec.package.lower().replace("_", "-")
    for dependency in project_dependencies:
        normalized_dependency = str(dependency).lower().replace("_", "-")
        if normalized_package in normalized_dependency:
            _fail(spec, "internal SDK must not be resolved through a package index")

    filename = wheel_info.get("filename")
    if not isinstance(filename, str) or Path(filename).name != filename:
        _fail(spec, "invalid wheel filename")
    expected_sdk_metadata = {
        "package": spec.package,
        "version": spec.version,
        "artifact": f"{spec.artifact_dir}/{filename}",
        "sha256": wheel_info.get("sha256"),
        "source-commit": spec.source_commit,
        "publication-channel": spec.publication_channel,
        "public-index-allowed": False,
    }
    if sdk_metadata != expected_sdk_metadata:
        _fail(spec, "project SDK metadata does not match immutable release evidence")

    wheel_path = artifact_dir / filename
    if not wheel_path.is_file():
        _fail(spec, "wheel is missing")
    payload = wheel_path.read_bytes()
    if len(payload) != wheel_info.get("size"):
        _fail(spec, "wheel size does not match release manifest")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != wheel_info.get("sha256"):
        _fail(spec, "wheel SHA-256 does not match release manifest")

    checksum_path = wheel_path.with_suffix(wheel_path.suffix + ".sha256")
    try:
        checksum_fields = checksum_path.read_text(encoding="utf-8").strip().split()
    except OSError as error:
        _fail(spec, f"adjacent checksum evidence is unreadable: {error}")
    if not checksum_fields or checksum_fields[0] != digest:
        _fail(spec, "adjacent checksum evidence does not match wheel")

    try:
        with zipfile.ZipFile(wheel_path) as archive:
            metadata_names = [
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_names) != 1:
                _fail(spec, "wheel must contain exactly one METADATA document")
            metadata = Parser().parsestr(
                archive.read(metadata_names[0]).decode("utf-8")
            )
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile) as error:
        _fail(spec, f"wheel metadata is unreadable: {error}")

    if metadata.get("Name") != spec.package:
        _fail(spec, "wheel metadata package name mismatch")
    if metadata.get("Version") != spec.version:
        _fail(spec, "wheel metadata version mismatch")
    metadata_requires_python = (metadata.get("Requires-Python") or "").replace(" ", "")
    if metadata_requires_python != spec.requires_python:
        _fail(spec, "wheel metadata Python compatibility mismatch")

    return {
        "status": "ok",
        "package": spec.package,
        "wheel": filename,
        "sha256": digest,
        "source_commit": spec.source_commit,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }
