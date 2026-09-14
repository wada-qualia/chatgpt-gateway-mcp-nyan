from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from gateway_api.mcp_upstream import (
    UpstreamMcpError,
    _list_session_prompt_catalog,
    _list_session_prompt_catalog_stable,
    _record_upstream_catalog_change_notification,
)
from mcp import types
from mcp.shared.exceptions import MCPError


class _Dumpable:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def model_dump(self, **_: Any) -> dict[str, Any]:
        return dict(self.payload)


class _PromptSession:
    def __init__(self) -> None:
        self.cursors: list[str | None] = []

    async def list_prompts(self, *, params: Any = None) -> Any:
        cursor = getattr(params, "cursor", None) if params is not None else None
        self.cursors.append(cursor)
        if cursor is None:
            return SimpleNamespace(
                prompts=[_Dumpable({"name": "review", "description": "Review input"})],
                next_cursor="page-2",
            )
        return SimpleNamespace(
            prompts=[
                _Dumpable(
                    {
                        "name": "summarize",
                        "arguments": [{"name": "text", "required": True}],
                    }
                )
            ],
            next_cursor=None,
        )


class _LegacyPromptSession:
    async def list_prompts(self, *, params: Any = None) -> Any:
        del params
        raise MCPError(-32601, "Method not found")


def test_remote_prompt_catalog_paginates() -> None:
    session = _PromptSession()
    prompts = asyncio.run(_list_session_prompt_catalog(session))

    assert [item["name"] for item in prompts] == ["review", "summarize"]
    assert session.cursors == [None, "page-2"]


def test_remote_prompt_catalog_legacy_method_not_found_is_empty() -> None:
    assert asyncio.run(_list_session_prompt_catalog(_LegacyPromptSession())) == []


class _ChangingPromptSession:
    def __init__(self, prompts_changed: asyncio.Event, *, continuous: bool) -> None:
        self.prompts_changed = prompts_changed
        self.continuous = continuous
        self.calls = 0

    async def list_prompts(self, *, params: Any = None) -> Any:
        assert params is None
        self.calls += 1
        if self.calls == 1 or self.continuous:
            _record_upstream_catalog_change_notification(
                types.PromptListChangedNotification(),
                tools_changed=asyncio.Event(),
                prompts_changed=self.prompts_changed,
            )
        return SimpleNamespace(
            prompts=[_Dumpable({"name": "review", "description": f"v{self.calls}"})],
            next_cursor=None,
        )


def test_real_sdk_prompt_list_changed_forces_stable_remote_relist() -> None:
    changed = asyncio.Event()
    session = _ChangingPromptSession(changed, continuous=False)
    snapshot, seen = asyncio.run(
        _list_session_prompt_catalog_stable(session, prompts_changed=changed)
    )
    assert seen is True
    assert session.calls == 2
    assert snapshot == [{"name": "review", "description": "v2"}]


def test_continuous_real_sdk_prompt_list_changed_fails_closed() -> None:
    changed = asyncio.Event()
    session = _ChangingPromptSession(changed, continuous=True)
    with pytest.raises(UpstreamMcpError) as exc_info:
        asyncio.run(_list_session_prompt_catalog_stable(session, prompts_changed=changed))
    assert exc_info.value.code == "MCP_PROMPT_CATALOG_UNSTABLE"
    assert exc_info.value.http_status == 409
    assert exc_info.value.retryable is True
    assert session.calls == 3
