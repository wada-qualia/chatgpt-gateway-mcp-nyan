from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from fastapi import HTTPException, status

from ..config import Settings


@dataclass
class DockerResult:
    container_id: str | None
    status: str
    detail: str


def safe_container_name(name: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_.-]+", "-", name.strip().lower()).strip("-")
    return value[:120] or "workspace"


class DockerAdapter:
    def __init__(self, settings: Settings):
        self.settings = settings

    def ensure_image_allowed(self, image: str) -> None:
        if image not in self.settings.docker_allowed_images:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Image is not allowlisted: {image}")

    def create_workspace(self, *, image: str, container_name: str) -> DockerResult:
        self.ensure_image_allowed(image)
        if not self.settings.gateway_docker_enabled:
            return DockerResult(container_id=None, status="pending", detail="Docker execution disabled; metadata recorded only.")
        result = subprocess.run(
            ["docker", "run", "-d", "--name", container_name, image, "sleep", "infinity"],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=result.stderr.strip() or "docker run failed")
        return DockerResult(container_id=result.stdout.strip(), status="running", detail="container started")

    def clone_workspace(self, *, source_container_id: str | None, image: str, container_name: str) -> DockerResult:
        self.ensure_image_allowed(image)
        if not self.settings.gateway_docker_enabled:
            return DockerResult(container_id=None, status="pending", detail="Docker clone disabled; metadata recorded only.")
        if not source_container_id:
            raise HTTPException(status_code=400, detail="Source workspace has no container_id")
        snapshot_image = f"{container_name}:snapshot"
        commit = subprocess.run(
            ["docker", "commit", source_container_id, snapshot_image],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if commit.returncode != 0:
            raise HTTPException(status_code=500, detail=commit.stderr.strip() or "docker commit failed")
        run = subprocess.run(
            ["docker", "run", "-d", "--name", container_name, snapshot_image, "sleep", "infinity"],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if run.returncode != 0:
            raise HTTPException(status_code=500, detail=run.stderr.strip() or "docker run clone failed")
        return DockerResult(container_id=run.stdout.strip(), status="running", detail="clone started")
