from __future__ import annotations

import ast
import io
import json
from pathlib import Path

import pytest

_GATEWAY_API = Path(__file__).resolve().parents[1] / "gateway_api"


def _offloaded_monitoring_methods(source: str, function_name: str) -> set[str]:
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function_name
    )
    methods: set[str] = set()
    for node in ast.walk(function):
        if not isinstance(node, ast.Await) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        func = call.func
        if not (
            isinstance(func, ast.Attribute)
            and func.attr == "to_thread"
            and isinstance(func.value, ast.Name)
            and func.value.id == "asyncio"
            and call.args
        ):
            continue
        target = call.args[0]
        if (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == "monitoring_service"
        ):
            methods.add(target.attr)
    return methods


def test_thin_client_session_persistence_is_offloaded_from_event_loop() -> None:
    source = (_GATEWAY_API / "routers" / "thin_clients.py").read_text()
    methods = _offloaded_monitoring_methods(source, "websocket_control")
    assert {"append_output", "finish_session"} <= methods


def test_mcp_background_tail_collection_is_offloaded_from_event_loop() -> None:
    source = (_GATEWAY_API / "routers" / "mcp.py").read_text()
    methods = _offloaded_monitoring_methods(source, "mcp")
    assert "background_tails_detached" in methods


class _CountingBytesIO(io.BytesIO):
    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        chunk = super().read(size)
        self.bytes_read += len(chunk)
        return chunk

    def close(self) -> None:
        pass


def test_jsonl_tail_reader_reads_only_a_bounded_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gateway_api import monitoring

    prefix = b"".join(
        json.dumps({"line": index, "text": "x" * 80}).encode("utf-8") + b"\n"
        for index in range(25_000)
    )
    suffix_records = [
        {"line": 25_000 + index, "text": f"tail-{index}"} for index in range(10)
    ]
    payload = prefix + b"".join(
        json.dumps(record).encode("utf-8") + b"\n" for record in suffix_records
    )
    stream = _CountingBytesIO(payload)
    target = Path("/virtual/large-command-session.jsonl")
    original_open = Path.open

    def fake_open(path: Path, mode: str = "r", *args, **kwargs):
        if path == target and mode == "rb":
            stream.seek(0)
            stream.bytes_read = 0
            return stream
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fake_open)
    records = monitoring._read_jsonl_tail(target, 5)

    assert [record["text"] for record in records] == [
        "tail-5",
        "tail-6",
        "tail-7",
        "tail-8",
        "tail-9",
    ]
    assert stream.bytes_read <= monitoring._JSONL_TAIL_CHUNK_BYTES * 2
    assert stream.bytes_read < len(payload) // 10
