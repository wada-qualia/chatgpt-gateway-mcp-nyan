from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from gateway_api import config
from gateway_api.adapters.ssh import SshCredentials, run_ssh_command


class FakeExitChannel:
    def recv_exit_status(self) -> int:
        return 0


class FakeInputChannel:
    def __init__(self) -> None:
        self.shutdown_called = False

    def shutdown_write(self) -> None:
        self.shutdown_called = True


class FakeInput:
    def __init__(self) -> None:
        self.channel = FakeInputChannel()
        self.writes: list[str] = []
        self.flushed = False

    def write(self, value: str) -> None:
        self.writes.append(value)

    def flush(self) -> None:
        self.flushed = True


class FakeOutput:
    channel = FakeExitChannel()

    def __init__(self, data: str) -> None:
        self.data = data

    def read(self) -> str:
        return self.data


class FakeClient:
    def __init__(self) -> None:
        self.command = ""
        self.stdin = FakeInput()
        self.closed = False

    def set_missing_host_key_policy(self, policy) -> None:
        pass

    def load_system_host_keys(self) -> None:
        pass

    def load_host_keys(self, filename: str) -> None:
        pass

    def connect(self, **kwargs) -> None:
        pass

    def exec_command(self, command: str, timeout=None):
        self.command = command
        return self.stdin, FakeOutput("uid=0(root)\n"), FakeOutput("")

    def close(self) -> None:
        self.closed = True


def test_sudo_uses_backend_credential_only_via_stdin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("192.0.2.10 ssh-ed25519 test-key\n", encoding="utf-8")
    monkeypatch.setenv("GATEWAY_SSH_KNOWN_HOSTS_PATH", str(known_hosts))
    config.get_settings.cache_clear()

    client = FakeClient()
    device = SimpleNamespace(
        host="192.0.2.10",
        port=2222,
        username="robot",
        auth_type="password",
    )
    credential_value = "backend-only-secret"
    credentials = SshCredentials(auth_type="password", secret=credential_value)

    result = run_ssh_command(
        device,
        credentials,
        command="sudo -n id",
        timeout_seconds=7,
        client_factory=lambda: client,
    )

    assert client.command == (
        "sudo -k -S -p '' -- sh -lc 'exec </dev/null; sudo -n id'"
    )
    assert credential_value not in client.command
    assert client.stdin.writes == [credential_value + "\n"]
    assert client.stdin.flushed is True
    assert client.stdin.channel.shutdown_called is True
    assert credential_value not in result.stdout
    assert credential_value not in result.stderr
    assert result.stdout == "uid=0(root)\n"
    assert client.closed is True
    config.get_settings.cache_clear()


def test_non_privileged_command_does_not_write_authentication_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("192.0.2.10 ssh-ed25519 test-key\n", encoding="utf-8")
    monkeypatch.setenv("GATEWAY_SSH_KNOWN_HOSTS_PATH", str(known_hosts))
    config.get_settings.cache_clear()

    client = FakeClient()
    device = SimpleNamespace(
        host="192.0.2.10",
        port=2222,
        username="robot",
        auth_type="password",
    )
    credentials = SshCredentials(auth_type="password", secret="backend-only-secret")

    run_ssh_command(
        device,
        credentials,
        command="id",
        timeout_seconds=7,
        client_factory=lambda: client,
    )

    assert client.command == "id"
    assert client.stdin.writes == []
    assert client.closed is True
    config.get_settings.cache_clear()


def test_privileged_execution_requires_password_authenticated_device() -> None:
    device = SimpleNamespace(
        host="192.0.2.10",
        port=2222,
        username="robot",
        auth_type="private_key",
    )
    credentials = SshCredentials(auth_type="private_key", secret="test-key")

    with pytest.raises(HTTPException) as exc_info:
        run_ssh_command(
            device,
            credentials,
            command="sudo id",
            client_factory=lambda: pytest.fail("SSH client must not be opened"),
        )

    assert exc_info.value.status_code == 400
    assert "privilege credential" in str(exc_info.value.detail)


def test_privileged_execution_rejects_line_break_in_credential() -> None:
    device = SimpleNamespace(
        host="192.0.2.10",
        port=2222,
        username="robot",
        auth_type="password",
    )
    credentials = SshCredentials(
        auth_type="password",
        secret="first-line\nsecond-line",
    )

    with pytest.raises(HTTPException) as exc_info:
        run_ssh_command(
            device,
            credentials,
            command="sudo id",
            client_factory=lambda: pytest.fail("SSH client must not be opened"),
        )

    assert exc_info.value.status_code == 400
    assert "line breaks" in str(exc_info.value.detail)
