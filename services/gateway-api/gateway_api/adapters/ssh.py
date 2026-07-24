from __future__ import annotations

import ast
import io
import json
import os
import re
import shutil
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from ..config import get_settings
from ..crypto import decrypt_text
from ..models import Device, SecretBlob


@dataclass(frozen=True)
class SshTarget:
    username: str
    host: str
    port: int


@dataclass(frozen=True)
class SshCredentials:
    auth_type: str
    secret: str | None = None
    passphrase: str | None = None


@dataclass(frozen=True)
class SshCommandResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""


class SshClientProtocol(Protocol):
    def set_missing_host_key_policy(self, policy: Any) -> None: ...

    def load_system_host_keys(self) -> None: ...

    def load_host_keys(self, filename: str) -> None: ...

    def connect(self, **kwargs: Any) -> None: ...

    def exec_command(
        self, command: str, timeout: int | float | None = None
    ) -> tuple[Any, Any, Any]: ...

    def close(self) -> None: ...


SshClientFactory = Callable[[], SshClientProtocol]


def parse_ssh_target(target: str) -> SshTarget:
    match = re.fullmatch(
        r"(?P<user>[^@\s]+)@(?P<host>[^:\s]+)(:(?P<port>\d+))?", target.strip()
    )
    if not match:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Expected SSH target user@host:port",
        )
    port = int(match.group("port") or "22")
    if port < 1 or port > 65535:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="SSH port is out of range",
        )
    return SshTarget(username=match.group("user"), host=match.group("host"), port=port)


def serialize_ssh_secret(secret_value: str, passphrase: str | None = None) -> str:
    return json.dumps(
        {"secret": secret_value, "passphrase": passphrase},
        ensure_ascii=False,
        separators=(",", ":"),
    )


def parse_ssh_secret_payload(raw_payload: str, *, auth_type: str) -> SshCredentials:
    try:
        decoded = json.loads(raw_payload)
    except json.JSONDecodeError:
        try:
            decoded = ast.literal_eval(raw_payload)
        except (SyntaxError, ValueError) as exc:
            raise HTTPException(
                status_code=400, detail="Stored SSH credential payload is not readable"
            ) from exc
    if not isinstance(decoded, dict):
        raise HTTPException(
            status_code=400, detail="Stored SSH credential payload has invalid shape"
        )
    secret = decoded.get("secret")
    passphrase = decoded.get("passphrase")
    if secret is not None and not isinstance(secret, str):
        raise HTTPException(
            status_code=400, detail="Stored SSH credential secret has invalid shape"
        )
    if passphrase is not None and not isinstance(passphrase, str):
        raise HTTPException(
            status_code=400, detail="Stored SSH credential passphrase has invalid shape"
        )
    if auth_type != "agent" and not secret:
        raise HTTPException(status_code=400, detail="Stored SSH credential is missing")
    return SshCredentials(auth_type=auth_type, secret=secret, passphrase=passphrase)


def load_device_credentials(device: Device, db: Session) -> SshCredentials:
    if device.auth_type == "agent":
        return SshCredentials(auth_type="agent")
    if not device.credential_secret_id:
        raise HTTPException(status_code=400, detail="Device credential is missing")
    secret = db.get(SecretBlob, device.credential_secret_id)
    if secret is None or secret.owner_subject != device.owner_subject:
        raise HTTPException(status_code=400, detail="Device credential is missing")
    expected_kind = f"ssh:{device.auth_type}"
    if secret.kind != expected_kind:
        raise HTTPException(
            status_code=400,
            detail="Device credential kind does not match device auth type",
        )
    decrypted = decrypt_text(secret.ciphertext)
    return parse_ssh_secret_payload(decrypted, auth_type=device.auth_type)


def check_ssh_tcp_connection(target: SshTarget, timeout: float = 5.0) -> str:
    try:
        with socket.create_connection((target.host, target.port), timeout=timeout):
            return "reachable"
    except OSError:
        return "unreachable"


def _load_paramiko() -> Any:
    try:
        import paramiko
    except ImportError as exc:
        raise HTTPException(
            status_code=500, detail="SSH execution dependency is not installed"
        ) from exc
    return paramiko


def _private_key_from_text(paramiko: Any, key_text: str, passphrase: str | None) -> Any:
    key_errors: list[str] = []
    for key_class_name in ("Ed25519Key", "ECDSAKey", "RSAKey", "DSSKey"):
        key_class = getattr(paramiko, key_class_name, None)
        if key_class is None:
            continue
        try:
            return key_class.from_private_key(
                io.StringIO(key_text), password=passphrase
            )
        except (
            Exception
        ) as exc:  # pragma: no cover - exact Paramiko exceptions differ by key class.
            key_errors.append(f"{key_class_name}: {exc}")
    raise HTTPException(
        status_code=400, detail="Stored SSH private key could not be loaded"
    )


def _status_from_ssh_exception(exc: Exception) -> int:
    message = str(exc).lower()
    if "not found in known_hosts" in message or (
        "host key for server" in message and "does not match" in message
    ):
        return 409
    if "authentication" in message or "auth" in message or "not a valid" in message:
        return 401
    if "timed out" in message or "timeout" in message:
        return 504
    return 502


def _managed_known_hosts_path(raw_path: str | None) -> Path:
    path = Path(raw_path or "./data/ssh/known_hosts").expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        bootstrap_path = Path("/etc/gateway/ssh_known_hosts")
        try:
            if bootstrap_path.is_file() and bootstrap_path.resolve() != path.resolve():
                shutil.copyfile(bootstrap_path, path)
            else:
                with path.open("x", encoding="utf-8"):
                    pass
        except FileExistsError:
            pass
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def _configure_host_key_verification(client: SshClientProtocol, paramiko: Any) -> None:
    settings = get_settings()
    client.load_system_host_keys()
    known_hosts_path = _managed_known_hosts_path(settings.gateway_ssh_known_hosts_path)
    client.load_host_keys(str(known_hosts_path))
    if settings.gateway_ssh_known_hosts_policy == "accept-new":
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())


def _ssh_client(
    device: Device,
    credentials: SshCredentials,
    *,
    timeout_seconds: int | float,
    client_factory: SshClientFactory | None = None,
) -> SshClientProtocol:
    paramiko = None if client_factory else _load_paramiko()
    client = client_factory() if client_factory else paramiko.SSHClient()
    try:
        if paramiko is not None:
            _configure_host_key_verification(client, paramiko)
        else:
            settings = get_settings()
            client.load_system_host_keys()
            client.load_host_keys(
                str(_managed_known_hosts_path(settings.gateway_ssh_known_hosts_path))
            )
    except OSError as exc:
        client.close()
        raise HTTPException(
            status_code=500, detail="SSH known_hosts file could not be loaded"
        ) from exc
    connect_kwargs: dict[str, Any] = {
        "hostname": device.host,
        "port": device.port,
        "username": device.username,
        "timeout": timeout_seconds,
        "banner_timeout": timeout_seconds,
        "auth_timeout": timeout_seconds,
        "look_for_keys": credentials.auth_type == "agent",
        "allow_agent": credentials.auth_type == "agent",
    }
    if credentials.auth_type == "password":
        connect_kwargs["password"] = credentials.secret
        connect_kwargs["look_for_keys"] = False
        connect_kwargs["allow_agent"] = False
    elif credentials.auth_type == "private_key":
        if paramiko is None:
            connect_kwargs["pkey"] = credentials.secret
        else:
            connect_kwargs["pkey"] = _private_key_from_text(
                paramiko, credentials.secret or "", credentials.passphrase
            )
        connect_kwargs["look_for_keys"] = False
        connect_kwargs["allow_agent"] = False
    elif credentials.auth_type != "agent":
        raise HTTPException(status_code=400, detail="Unsupported SSH auth type")
    try:
        client.connect(**connect_kwargs)
    except Exception as exc:
        status_code = _status_from_ssh_exception(exc)
        detail = (
            "SSH host key is not trusted"
            if status_code == 409
            else "SSH connection failed"
        )
        raise HTTPException(status_code=status_code, detail=detail) from exc
    return client


def verify_ssh_connection(
    device: Device,
    credentials: SshCredentials,
    *,
    timeout_seconds: int | float = 15,
    client_factory: SshClientFactory | None = None,
) -> str:
    client = _ssh_client(
        device,
        credentials,
        timeout_seconds=timeout_seconds,
        client_factory=client_factory,
    )
    try:
        return "verified"
    finally:
        client.close()


def _read_stream(stream: Any) -> str:
    data = stream.read()
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data or "")


def run_ssh_command(
    device: Device,
    credentials: SshCredentials,
    *,
    command: str,
    timeout_seconds: int | float = 30,
    client_factory: SshClientFactory | None = None,
) -> SshCommandResult:
    if not command.strip():
        raise HTTPException(status_code=400, detail="SSH command must not be empty")
    client = _ssh_client(
        device,
        credentials,
        timeout_seconds=timeout_seconds,
        client_factory=client_factory,
    )
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout_seconds)
        stdout_text = _read_stream(stdout)
        stderr_text = _read_stream(stderr)
        exit_status = 0
        channel = getattr(stdout, "channel", None)
        if channel is not None and hasattr(channel, "recv_exit_status"):
            exit_status = int(channel.recv_exit_status())
        return SshCommandResult(
            exit_code=exit_status, stdout=stdout_text, stderr=stderr_text
        )
    except Exception as exc:
        raise HTTPException(
            status_code=_status_from_ssh_exception(exc),
            detail="SSH command execution failed",
        ) from exc
    finally:
        client.close()
