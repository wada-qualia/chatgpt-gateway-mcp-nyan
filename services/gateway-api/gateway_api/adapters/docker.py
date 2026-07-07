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


@dataclass
class DockerExecResult:
    exit_code: int
    output: str


def safe_container_name(name: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_.-]+", "-", name.strip().lower()).strip("-")
    return value[:120] or "workspace"


class DockerAdapter:
    def __init__(self, settings: Settings):
        self.settings = settings

    def ensure_image_allowed(self, image: str) -> None:
        if image not in self.settings.docker_allowed_images:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Image is not allowlisted: {image}")

    def _run(self, args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result

    def create_workspace(self, *, image: str, container_name: str) -> DockerResult:
        self.ensure_image_allowed(image)
        if not self.settings.gateway_docker_enabled:
            return DockerResult(container_id=None, status="pending", detail="Docker execution disabled; metadata recorded only.")
        result = self._run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                container_name,
                "--label",
                "chatgpt-mcp-ssh-gateway.workspace=true",
                "--workdir",
                "/workspace",
                image,
                "sh",
                "-lc",
                "mkdir -p /workspace && sleep infinity",
            ],
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
        commit = self._run(
            ["docker", "commit", source_container_id, snapshot_image],
            timeout=120,
        )
        if commit.returncode != 0:
            raise HTTPException(status_code=500, detail=commit.stderr.strip() or "docker commit failed")
        run = self._run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                container_name,
                "--label",
                "chatgpt-mcp-ssh-gateway.workspace=true",
                "--workdir",
                "/workspace",
                snapshot_image,
                "sh",
                "-lc",
                "mkdir -p /workspace && sleep infinity",
            ],
            timeout=60,
        )
        if run.returncode != 0:
            raise HTTPException(status_code=500, detail=run.stderr.strip() or "docker run clone failed")
        return DockerResult(container_id=run.stdout.strip(), status="running", detail="clone started")

    def exec_workspace(self, *, container_id: str | None, command: str, workdir: str = "/workspace", timeout_seconds: int | None = None) -> DockerExecResult:
        if not self.settings.gateway_docker_enabled:
            raise HTTPException(status_code=400, detail="Docker execution disabled")
        if not container_id:
            raise HTTPException(status_code=400, detail="Workspace has no container_id")
        timeout = min(timeout_seconds or self.settings.max_command_timeout_seconds, self.settings.max_command_timeout_seconds)
        result = self._run(
            ["docker", "exec", "-w", workdir, container_id, "sh", "-lc", command],
            timeout=timeout,
        )
        output = (result.stdout + result.stderr)[: self.settings.max_output_chars]
        return DockerExecResult(exit_code=result.returncode, output=output)

    def stop_workspace(self, *, container_id: str | None) -> DockerResult:
        if not self.settings.gateway_docker_enabled:
            return DockerResult(container_id=container_id, status="stopped", detail="Docker execution disabled; metadata marked stopped.")
        if not container_id:
            raise HTTPException(status_code=400, detail="Workspace has no container_id")
        result = self._run(["docker", "stop", container_id], timeout=60)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=result.stderr.strip() or "docker stop failed")
        return DockerResult(container_id=container_id, status="stopped", detail="container stopped")

    def start_workspace(self, *, container_id: str | None) -> DockerResult:
        if not self.settings.gateway_docker_enabled:
            return DockerResult(container_id=container_id, status="pending", detail="Docker execution disabled; metadata marked pending.")
        if not container_id:
            raise HTTPException(status_code=400, detail="Workspace has no container_id")
        result = self._run(["docker", "start", container_id], timeout=60)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=result.stderr.strip() or "docker start failed")
        return DockerResult(container_id=container_id, status="running", detail="container started")

    def rename_workspace(self, *, container_id: str | None, new_container_name: str) -> str:
        if not self.settings.gateway_docker_enabled:
            return "Docker execution disabled; metadata renamed only."
        if not container_id:
            raise HTTPException(status_code=400, detail="Workspace has no container_id")
        result = self._run(["docker", "rename", container_id, new_container_name], timeout=60)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=result.stderr.strip() or "docker rename failed")
        return f"container renamed to {new_container_name}"

    def remove_workspace(self, *, container_id: str | None) -> str:
        if not self.settings.gateway_docker_enabled or not container_id:
            return "metadata removed"
        result = self._run(["docker", "rm", "-f", container_id], timeout=60)
        if result.returncode != 0 and "No such container" not in result.stderr:
            raise HTTPException(status_code=500, detail=result.stderr.strip() or "docker rm failed")
        return result.stdout.strip() or "container removed"
