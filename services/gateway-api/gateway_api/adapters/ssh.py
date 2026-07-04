from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from fastapi import HTTPException, status


@dataclass
class SshTarget:
    username: str
    host: str
    port: int


def parse_ssh_target(target: str) -> SshTarget:
    match = re.fullmatch(r"(?P<user>[^@\s]+)@(?P<host>[^:\s]+)(:(?P<port>\d+))?", target.strip())
    if not match:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Expected SSH target user@host:port")
    port = int(match.group("port") or "22")
    if port < 1 or port > 65535:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SSH port is out of range")
    return SshTarget(username=match.group("user"), host=match.group("host"), port=port)


def verify_ssh_key_connection(target: SshTarget) -> str:
    result = subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-p",
            str(target.port),
            f"{target.username}@{target.host}",
            "true",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise HTTPException(status_code=400, detail=result.stderr.strip() or "SSH verification failed")
    return "verified"
