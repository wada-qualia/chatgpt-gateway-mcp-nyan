from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import AsyncIterator
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any, Self

import httpx
import uvicorn
from gateway_api.affine_research_provider import (
    AffineProviderSettings,
    AffineResearchService,
    build_mcp,
)
from gateway_api.mcp_upstream import UpstreamMcpManager
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client


class _StaticTokenProvider:
    def get_token(self) -> str:
        return "bridge-access-token"


class _BridgeConflict(RuntimeError):
    def __init__(self, expected_hash: str, current_hash: str) -> None:
        super().__init__("Document content changed")
        self.status_code = 409
        self.details = {
            "code": "DOCUMENT_CONTENT_CONFLICT",
            "expected_content_hash": expected_hash,
            "current_content_hash": current_hash,
        }


class _BridgeTitleConflict(RuntimeError):
    def __init__(self, expected_title: str, current_title: str) -> None:
        super().__init__("Document title changed")
        self.status_code = 409
        self.details = {
            "code": "DOCUMENT_TITLE_CONFLICT",
            "expected_title": expected_title,
            "current_title": current_title,
        }


class _FakeBridgeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.conflict: tuple[str, str] | None = None
        self.title_conflict: tuple[str, str] | None = None

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def ready(self) -> dict[str, str]:
        self.calls.append(("ready", {}))
        return {"status": "ready"}

    async def read_affine_document_content(self, note_id: str, **kwargs: Any) -> Any:
        self.calls.append(("read", {"note_id": note_id, **kwargs}))
        return SimpleNamespace(
            workspace_id="workspace-1",
            doc_id=note_id,
            content="# Note\n",
            content_hash="a" * 64,
            format="markdown",
            web_url=f"https://affine.example/workspace-1/{note_id}",
        )

    async def read_affine_document_metadata(self, note_id: str, **kwargs: Any) -> Any:
        self.calls.append(("metadata", {"note_id": note_id, **kwargs}))
        return SimpleNamespace(
            workspace_id="workspace-1",
            doc_id=note_id,
            title="Research note",
            tags=["research", "graph"],
            tags_hash="d" * 64,
            web_url=f"https://affine.example/workspace-1/{note_id}",
        )

    async def search_affine_documents(self, query: str, **kwargs: Any) -> list[Any]:
        self.calls.append(("search", {"query": query, **kwargs}))
        return [
            SimpleNamespace(
                doc_id="note-1",
                title="Research note",
                created_at="2026-08-09T00:00:00Z",
                content="Matched content",
            )
        ]

    async def list_affine_global_spaces(self, **kwargs: Any) -> Any:
        self.calls.append(("global_space_list", kwargs))
        return SimpleNamespace(
            visibility_mode="all_documents",
            spaces=[
                SimpleNamespace(
                    workspace_id="workspace-1",
                    name="Research",
                    created_at="2026-08-09T00:00:00Z",
                    space_ref="rk://affine/workspace-1",
                ),
                SimpleNamespace(
                    workspace_id="workspace-2",
                    name="Ordinary",
                    created_at="2026-08-10T00:00:00Z",
                    space_ref="rk://affine/workspace-2",
                ),
            ],
            next_cursor=None,
        )

    async def list_affine_global_documents(self, **kwargs: Any) -> Any:
        self.calls.append(("global_document_list", kwargs))
        return SimpleNamespace(
            visibility_mode="all_documents",
            documents=[
                SimpleNamespace(
                    workspace_id="workspace-2",
                    doc_id="ordinary-1",
                    title="Ordinary document",
                    created_at="2026-08-10T00:00:00Z",
                    updated_at="2026-08-11T00:00:00Z",
                    document_ref="rk://affine/workspace-2/ordinary-1",
                )
            ],
            next_cursor=None,
        )

    async def read_affine_global_document(
        self, workspace_id: str, document_id: str
    ) -> Any:
        self.calls.append(
            (
                "global_document_read",
                {"workspace_id": workspace_id, "document_id": document_id},
            )
        )
        return SimpleNamespace(
            workspace_id=workspace_id,
            doc_id=document_id,
            title="Ordinary document",
            content="ordinary cross-workspace content",
            content_hash="9" * 64,
            format="markdown",
            web_url=f"https://affine.example/{workspace_id}/{document_id}",
            document_ref=f"rk://affine/{workspace_id}/{document_id}",
        )

    async def read_affine_global_document_metadata(
        self, workspace_id: str, document_id: str
    ) -> Any:
        self.calls.append(
            (
                "global_document_metadata",
                {"workspace_id": workspace_id, "document_id": document_id},
            )
        )
        return SimpleNamespace(
            workspace_id=workspace_id,
            doc_id=document_id,
            title="Ordinary document",
            tags=[],
            tags_hash="8" * 64,
            web_url=f"https://affine.example/{workspace_id}/{document_id}",
            document_ref=f"rk://affine/{workspace_id}/{document_id}",
        )

    async def search_affine_global_documents(self, query: str, **kwargs: Any) -> Any:
        self.calls.append(("global_document_search", {"query": query, **kwargs}))
        return SimpleNamespace(
            visibility_mode="all_documents",
            mode=kwargs.get("mode", "keyword"),
            results=[
                SimpleNamespace(
                    workspace_id="workspace-2",
                    doc_id="ordinary-1",
                    title="Ordinary document",
                    created_at="2026-08-10T00:00:00Z",
                    content="ordinary cross-workspace content",
                    document_ref="rk://affine/workspace-2/ordinary-1",
                )
            ],
        )

    async def create_affine_document(self, **kwargs: Any) -> Any:
        self.calls.append(("create", kwargs))
        workspace_id = str(kwargs["workspace_id"])
        return SimpleNamespace(
            doc_id="note-created",
            web_url=f"https://affine.example/{workspace_id}/note-created",
            content_hash="b" * 64,
            operation_id="operation-create",
            replayed=False,
        )

    async def update_affine_document_content(
        self, note_id: str, content: str, **kwargs: Any
    ) -> Any:
        self.calls.append(
            ("update_content", {"note_id": note_id, "content": content, **kwargs})
        )
        if self.conflict is not None:
            raise _BridgeConflict(*self.conflict)
        workspace_id = str(kwargs["workspace_id"])
        return SimpleNamespace(
            doc_id=note_id,
            web_url=f"https://affine.example/{workspace_id}/{note_id}",
            content_hash="c" * 64,
            operation_id="operation-update",
            replayed=False,
        )

    async def append_affine_document_content(
        self, note_id: str, content: str, **kwargs: Any
    ) -> Any:
        self.calls.append(
            ("append", {"note_id": note_id, "content": content, **kwargs})
        )
        if self.conflict is not None:
            raise _BridgeConflict(*self.conflict)
        workspace_id = str(kwargs["workspace_id"])
        return SimpleNamespace(
            doc_id=note_id,
            web_url=f"https://affine.example/{workspace_id}/{note_id}",
            content_hash="e" * 64,
            operation_id="operation-append",
            replayed=False,
        )

    async def update_affine_document_tags(
        self, note_id: str, tags: list[str], **kwargs: Any
    ) -> Any:
        self.calls.append(("update_tags", {"note_id": note_id, "tags": tags, **kwargs}))
        workspace_id = str(kwargs["workspace_id"])
        return SimpleNamespace(
            doc_id=note_id,
            web_url=f"https://affine.example/{workspace_id}/{note_id}",
            content_hash=None,
            tags=tags,
            tags_hash="f" * 64,
            operation_id="operation-tags",
            replayed=False,
        )

    async def update_affine_document_title(
        self, note_id: str, title: str, **kwargs: Any
    ) -> Any:
        self.calls.append(
            ("update_title", {"note_id": note_id, "title": title, **kwargs})
        )
        if self.title_conflict is not None:
            raise _BridgeTitleConflict(*self.title_conflict)
        workspace_id = str(kwargs["workspace_id"])
        return SimpleNamespace(
            doc_id=note_id,
            web_url=f"https://affine.example/{workspace_id}/{note_id}",
            content_hash=None,
            operation_id="operation-title",
            replayed=False,
        )


def _settings(*, access_mode: str = "read_only") -> AffineProviderSettings:
    scope = "affine.documents.read affine.graphql"
    if access_mode == "read_write":
        scope += " affine.documents.write"
    return AffineProviderSettings(
        bridge_url="http://bridge.internal:18086",
        workspace_id="workspace-1",
        keycloak_token_url="https://keycloak.internal/token",
        keycloak_client_id="gateway-affine-provider",
        keycloak_client_secret="bridge-client-secret",
        keycloak_scope=scope,
        internal_bearer_token="gateway-provider-secret",
        access_mode=access_mode,
        host="127.0.0.1",
        auth_issuer_url="http://provider.internal",
        auth_resource_url="http://provider.internal:8010",
    )


def test_provider_file_backed_secrets_are_supported_and_unambiguous() -> None:
    with TemporaryDirectory() as directory:
        keycloak_path = f"{directory}/keycloak-client-secret"
        bearer_path = f"{directory}/internal-bearer-token"
        with open(keycloak_path, "w", encoding="utf-8") as handle:
            handle.write("file-keycloak-secret\n")
        with open(bearer_path, "w", encoding="utf-8") as handle:
            handle.write("file-bearer-token\n")

        settings = AffineProviderSettings(
            bridge_url="http://bridge.internal:18086",
            workspace_id="workspace-1",
            keycloak_token_url="https://keycloak.internal/token",
            keycloak_client_id="gateway-affine-provider",
            keycloak_client_secret_file=keycloak_path,
            internal_bearer_token_file=bearer_path,
        )
        settings.validate_runtime()
        assert settings.resolved_keycloak_client_secret() == "file-keycloak-secret"
        assert settings.resolved_internal_bearer_token() == "file-bearer-token"

        ambiguous = AffineProviderSettings(
            bridge_url="http://bridge.internal:18086",
            workspace_id="workspace-1",
            keycloak_token_url="https://keycloak.internal/token",
            keycloak_client_id="gateway-affine-provider",
            keycloak_client_secret="direct-secret",
            keycloak_client_secret_file=keycloak_path,
            internal_bearer_token_file=bearer_path,
        )
        try:
            ambiguous.validate_runtime()
        except RuntimeError as error:
            assert "not both" in str(error)
            assert "direct-secret" not in str(error)
        else:
            raise AssertionError("ambiguous secret source was accepted")


def _service(
    settings: AffineProviderSettings, fake: _FakeBridgeClient
) -> AffineResearchService:
    return AffineResearchService(
        settings,
        token_provider=_StaticTokenProvider(),
        client_factory=lambda *_args, **_kwargs: fake,
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextlib.asynccontextmanager
async def _running_provider(
    *, access_mode: str
) -> AsyncIterator[tuple[str, _FakeBridgeClient]]:
    settings = _settings(access_mode=access_mode)
    fake = _FakeBridgeClient()
    mcp = build_mcp(settings, service=_service(settings, fake))
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            mcp.streamable_http_app(),
            host="127.0.0.1",
            port=port,
            lifespan="on",
            log_level="critical",
            timeout_graceful_shutdown=1,
        )
    )
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(300):
            if server.started:
                break
            if task.done():
                await task
            await asyncio.sleep(0.01)
        else:
            raise RuntimeError("AFFiNE research provider did not start")
        yield f"http://127.0.0.1:{port}/mcp", fake
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, timeout=5)


@contextlib.asynccontextmanager
async def _provider_session(url: str) -> AsyncIterator[ClientSession]:
    async with (
        httpx.AsyncClient(
            headers={"Authorization": "Bearer gateway-provider-secret"}
        ) as http_client,
        streamable_http_client(
            url, http_client=http_client, terminate_on_close=False
        ) as (read_stream, write_stream, _),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        yield session


async def _test_provider_requires_internal_bearer_and_exposes_stable_tool_contract() -> (
    None
):
    async with _running_provider(access_mode="read_only") as (url, fake):
        ready_url = url.removesuffix("/mcp") + "/ready"
        async with httpx.AsyncClient() as client:
            unauthorized_mcp = await client.get(url)
            unauthorized_ready = await client.get(ready_url)
        assert unauthorized_mcp.status_code == 401
        assert unauthorized_ready.status_code == 401
        async with httpx.AsyncClient(
            headers={"Authorization": "Bearer gateway-provider-secret"}
        ) as client:
            ready = await client.get(ready_url)
        assert ready.status_code == 200
        assert ready.json() == {"status": "ready"}
        assert ("ready", {}) in fake.calls
        async with _provider_session(url) as session:
            page = await session.list_tools()
            tools = {tool.name: tool for tool in page.tools}
            assert set(tools) == {
                "research_v1_provider_capabilities",
                "research_v1_space_list",
                "research_v1_document_list",
                "research_v1_document_read",
                "research_v1_document_metadata",
                "research_v1_document_search",
                "research_v1_document_create",
                "research_v1_document_update_content",
                "research_v1_document_append",
                "research_v1_document_set_tags",
                "research_v1_document_link",
                "research_v1_document_add_source",
                "research_v1_document_update_title",
                "research_v1_note_read",
                "research_v1_note_metadata",
                "research_v1_note_search",
                "research_v1_note_create",
                "research_v1_note_update_content",
                "research_v1_note_append",
                "research_v1_note_set_tags",
                "research_v1_note_link",
                "research_v1_note_add_source",
                "research_v1_note_update_title",
            }
            assert tools["research_v1_note_read"].annotations.readOnlyHint is True
            assert tools["research_v1_document_read"].annotations.readOnlyHint is True
            assert (
                tools["research_v1_note_update_content"].annotations.readOnlyHint
                is False
            )
            update_schema = tools["research_v1_note_update_content"].inputSchema
            assert set(update_schema["required"]) == {
                "note_id",
                "content",
                "expected_content_hash",
            }
            assert "idempotency_key" not in update_schema.get("properties", {})
            document_create_schema = tools["research_v1_document_create"].inputSchema
            assert set(document_create_schema["required"]) == {
                "workspace_id",
                "title",
                "content",
            }
            document_update_schema = tools[
                "research_v1_document_update_content"
            ].inputSchema
            assert set(document_update_schema["required"]) == {
                "workspace_id",
                "document_id",
                "content",
                "expected_content_hash",
            }
            document_title_schema = tools[
                "research_v1_document_update_title"
            ].inputSchema
            assert set(document_title_schema["required"]) == {
                "workspace_id",
                "document_id",
                "title",
                "expected_title",
            }
            capabilities = await session.call_tool(
                "research_v1_provider_capabilities", {}
            )
            assert capabilities.isError is False
            assert (
                capabilities.structuredContent["contract_version"]
                == "research-knowledge/v1"
            )
            assert capabilities.structuredContent["access_mode"] == "read_only"
            assert {
                "space_list",
                "document_list",
                "document_read",
                "document_metadata",
                "document_search",
            } <= set(capabilities.structuredContent["operations"])


async def _test_provider_read_tools_use_affine_sdk_boundary() -> None:
    async with _running_provider(access_mode="read_only") as (url, fake):
        async with _provider_session(url) as session:
            read = await session.call_tool(
                "research_v1_note_read", {"note_id": "note-1"}
            )
            assert read.isError is False
            assert read.structuredContent["note_id"] == "note-1"
            assert read.structuredContent["content_hash"] == "a" * 64
            search = await session.call_tool(
                "research_v1_note_search", {"query": "graph", "mode": "semantic"}
            )
            assert search.isError is False
            assert search.structuredContent["matches"][0]["note_id"] == "note-1"
        assert fake.calls == [
            ("read", {"note_id": "note-1", "workspace_id": "workspace-1"}),
            (
                "search",
                {
                    "query": "graph",
                    "mode": "semantic",
                    "workspace_id": "workspace-1",
                },
            ),
        ]


async def _test_provider_global_document_tools_use_affine_sdk_boundary() -> None:
    async with _running_provider(access_mode="read_only") as (url, fake):
        async with _provider_session(url) as session:
            spaces = await session.call_tool("research_v1_space_list", {"limit": 10})
            assert spaces.isError is False
            assert spaces.structuredContent["visibility_mode"] == "all_documents"
            assert spaces.structuredContent["spaces"][1]["space_ref"] == (
                "rk://affine/workspace-2"
            )

            documents = await session.call_tool(
                "research_v1_document_list",
                {"workspace_id": "workspace-2", "limit": 25},
            )
            assert documents.isError is False
            assert documents.structuredContent["documents"][0]["document_ref"] == (
                "rk://affine/workspace-2/ordinary-1"
            )

            read = await session.call_tool(
                "research_v1_document_read",
                {"workspace_id": "workspace-2", "document_id": "ordinary-1"},
            )
            assert read.isError is False
            assert read.structuredContent["workspace_id"] == "workspace-2"
            assert (
                read.structuredContent["content"] == "ordinary cross-workspace content"
            )
            assert read.structuredContent["content_hash"] == "9" * 64

            metadata = await session.call_tool(
                "research_v1_document_metadata",
                {"workspace_id": "workspace-2", "document_id": "ordinary-1"},
            )
            assert metadata.isError is False
            assert metadata.structuredContent["tags"] == []
            assert metadata.structuredContent["tags_hash"] == "8" * 64

            search = await session.call_tool(
                "research_v1_document_search",
                {"query": "ordinary", "mode": "keyword"},
            )
            assert search.isError is False
            assert search.structuredContent["visibility_mode"] == "all_documents"
            assert search.structuredContent["matches"][0]["workspace_id"] == (
                "workspace-2"
            )
            assert search.structuredContent["matches"][0]["document_id"] == (
                "ordinary-1"
            )

        assert fake.calls == [
            ("global_space_list", {"cursor": None, "limit": 10}),
            (
                "global_document_list",
                {"workspace_id": "workspace-2", "cursor": None, "limit": 25},
            ),
            (
                "global_document_read",
                {"workspace_id": "workspace-2", "document_id": "ordinary-1"},
            ),
            (
                "global_document_metadata",
                {"workspace_id": "workspace-2", "document_id": "ordinary-1"},
            ),
            (
                "global_document_search",
                {
                    "query": "ordinary",
                    "mode": "keyword",
                    "workspace_id": None,
                    "limit": 20,
                },
            ),
        ]


async def _test_provider_write_is_fail_closed_in_read_only_mode() -> None:
    async with _running_provider(access_mode="read_only") as (url, fake):
        async with _provider_session(url) as session:
            legacy = await session.call_tool(
                "research_v1_note_create",
                {"title": "Blocked", "content": "No write"},
                meta={"gateway": {"idempotency_key": "mcp-action:blocked"}},
            )
            document = await session.call_tool(
                "research_v1_document_link",
                {
                    "workspace_id": "workspace-2",
                    "document_id": "ordinary-1",
                    "target_workspace_id": "workspace-3",
                    "target_document_id": "target-1",
                    "expected_content_hash": "9" * 64,
                },
                meta={"gateway": {"idempotency_key": "mcp-action:blocked-document"}},
            )
        for result in (legacy, document):
            assert result.isError is True
            assert "AFFINE_PROVIDER_READ_ONLY" in result.content[0].text
        assert fake.calls == []


async def _test_provider_write_requires_and_forwards_gateway_bound_idempotency() -> (
    None
):
    async with _running_provider(access_mode="read_write") as (url, fake):
        async with _provider_session(url) as session:
            missing = await session.call_tool(
                "research_v1_note_create", {"title": "Missing", "content": "metadata"}
            )
            assert missing.isError is True
            assert "GATEWAY_IDEMPOTENCY_REQUIRED" in missing.content[0].text
            created = await session.call_tool(
                "research_v1_note_create",
                {"title": "Created", "content": "body"},
                meta={
                    "gateway": {
                        "idempotency_key": "mcp-action:preparation-123",
                        "preparation_id": "preparation-123",
                    }
                },
            )
            assert created.isError is False
            assert created.structuredContent["note_id"] == "note-created"
        create_calls = [payload for name, payload in fake.calls if name == "create"]
        assert len(create_calls) == 1
        assert create_calls[0]["idempotency_key"] == "mcp-action:preparation-123"
        assert create_calls[0]["workspace_id"] == "workspace-1"


async def _test_provider_preserves_authoritative_content_conflict_as_tool_error() -> (
    None
):
    expected = "d" * 64
    current = "e" * 64
    async with _running_provider(access_mode="read_write") as (url, fake):
        fake.conflict = (expected, current)
        async with _provider_session(url) as session:
            result = await session.call_tool(
                "research_v1_note_update_content",
                {
                    "note_id": "note-1",
                    "content": "stale replacement",
                    "expected_content_hash": expected,
                },
                meta={"gateway": {"idempotency_key": "mcp-action:stale"}},
            )
        assert result.isError is True
        error_text = result.content[0].text
        assert "DOCUMENT_CONTENT_CONFLICT" in error_text
        assert expected in error_text
        assert current in error_text
        update_calls = [
            payload for name, payload in fake.calls if name == "update_content"
        ]
        assert len(update_calls) == 1
        assert update_calls[0]["expected_content_hash"] == expected
        assert update_calls[0]["idempotency_key"] == "mcp-action:stale"


async def _test_provider_preserves_authoritative_title_conflict_as_tool_error() -> None:
    expected = "Original title"
    current = "Current title"
    async with _running_provider(access_mode="read_write") as (url, fake):
        fake.title_conflict = (expected, current)
        async with _provider_session(url) as session:
            result = await session.call_tool(
                "research_v1_note_update_title",
                {
                    "note_id": "note-1",
                    "title": "Replacement title",
                    "expected_title": expected,
                },
                meta={"gateway": {"idempotency_key": "mcp-action:stale-title"}},
            )
        assert result.isError is True
        error_text = result.content[0].text
        assert "DOCUMENT_TITLE_CONFLICT" in error_text
        assert expected in error_text
        assert current in error_text
        update_calls = [
            payload for name, payload in fake.calls if name == "update_title"
        ]
        assert len(update_calls) == 1
        assert update_calls[0]["expected_title"] == expected
        assert update_calls[0]["idempotency_key"] == "mcp-action:stale-title"


async def _test_provider_expanded_write_tools_use_affine_sdk_boundary() -> None:
    async with _running_provider(access_mode="read_write") as (url, fake):
        async with _provider_session(url) as session:
            metadata = await session.call_tool(
                "research_v1_note_metadata", {"note_id": "note-1"}
            )
            appended = await session.call_tool(
                "research_v1_note_append",
                {
                    "note_id": "note-1",
                    "content": "append body",
                    "expected_content_hash": "a" * 64,
                },
                meta={"gateway": {"idempotency_key": "mcp-action:append"}},
            )
            tagged = await session.call_tool(
                "research_v1_note_set_tags",
                {
                    "note_id": "note-1",
                    "tags": ["research", "graph"],
                    "expected_tags_hash": "d" * 64,
                },
                meta={"gateway": {"idempotency_key": "mcp-action:tags"}},
            )
            linked = await session.call_tool(
                "research_v1_note_link",
                {
                    "note_id": "note-1",
                    "target_note_id": "note-2",
                    "expected_content_hash": "e" * 64,
                },
                meta={"gateway": {"idempotency_key": "mcp-action:link"}},
            )
            sourced = await session.call_tool(
                "research_v1_note_add_source",
                {
                    "note_id": "note-1",
                    "url": "https://example.test/paper",
                    "title": "Paper",
                    "locator": "p. 12",
                    "expected_content_hash": "e" * 64,
                },
                meta={"gateway": {"idempotency_key": "mcp-action:source"}},
            )

        assert metadata.isError is False
        assert metadata.structuredContent["tags"] == ["research", "graph"]
        assert appended.isError is False
        assert appended.structuredContent["content_hash"] == "e" * 64
        assert tagged.isError is False
        assert tagged.structuredContent["tags_hash"] == "f" * 64
        assert linked.isError is False
        assert sourced.isError is False

        calls = fake.calls
        assert any(
            name == "append" and payload["idempotency_key"] == "mcp-action:append"
            for name, payload in calls
        )
        assert any(
            name == "update_tags" and payload["expected_tags_hash"] == "d" * 64
            for name, payload in calls
        )
        link_append = next(
            payload
            for name, payload in calls
            if name == "append" and payload["idempotency_key"] == "mcp-action:link"
        )
        assert "research-link:v1" in link_append["content"]
        assert "note-2" in link_append["content"]
        source_append = next(
            payload
            for name, payload in calls
            if name == "append" and payload["idempotency_key"] == "mcp-action:source"
        )
        assert "research-source:v1" in source_append["content"]
        assert "https://example.test/paper" in source_append["content"]


async def _test_provider_global_write_tools_use_explicit_workspace_boundary() -> None:
    async with _running_provider(access_mode="read_write") as (url, fake):
        async with _provider_session(url) as session:
            created = await session.call_tool(
                "research_v1_document_create",
                {
                    "workspace_id": "workspace-2",
                    "title": "Created globally",
                    "content": "body",
                },
                meta={"gateway": {"idempotency_key": "mcp-action:global-create"}},
            )
            updated = await session.call_tool(
                "research_v1_document_update_content",
                {
                    "workspace_id": "workspace-2",
                    "document_id": "ordinary-1",
                    "content": "replacement",
                    "expected_content_hash": "9" * 64,
                },
                meta={"gateway": {"idempotency_key": "mcp-action:global-update"}},
            )
            appended = await session.call_tool(
                "research_v1_document_append",
                {
                    "workspace_id": "workspace-2",
                    "document_id": "ordinary-1",
                    "content": "append",
                    "expected_content_hash": "c" * 64,
                },
                meta={"gateway": {"idempotency_key": "mcp-action:global-append"}},
            )
            tagged = await session.call_tool(
                "research_v1_document_set_tags",
                {
                    "workspace_id": "workspace-2",
                    "document_id": "ordinary-1",
                    "tags": ["global"],
                    "expected_tags_hash": "8" * 64,
                },
                meta={"gateway": {"idempotency_key": "mcp-action:global-tags"}},
            )
            linked = await session.call_tool(
                "research_v1_document_link",
                {
                    "workspace_id": "workspace-2",
                    "document_id": "ordinary-1",
                    "target_workspace_id": "workspace-3",
                    "target_document_id": "target-1",
                    "expected_content_hash": "e" * 64,
                },
                meta={"gateway": {"idempotency_key": "mcp-action:global-link"}},
            )
            sourced = await session.call_tool(
                "research_v1_document_add_source",
                {
                    "workspace_id": "workspace-2",
                    "document_id": "ordinary-1",
                    "url": "https://example.test/global",
                    "title": "Global source",
                    "expected_content_hash": "e" * 64,
                },
                meta={"gateway": {"idempotency_key": "mcp-action:global-source"}},
            )
            titled = await session.call_tool(
                "research_v1_document_update_title",
                {
                    "workspace_id": "workspace-2",
                    "document_id": "ordinary-1",
                    "title": "Updated globally",
                    "expected_title": "Ordinary document",
                },
                meta={"gateway": {"idempotency_key": "mcp-action:global-title"}},
            )
            blank = await session.call_tool(
                "research_v1_document_create",
                {"workspace_id": "   ", "title": "Blocked", "content": "body"},
                meta={"gateway": {"idempotency_key": "mcp-action:blank-workspace"}},
            )

        for result in (created, updated, appended, tagged, linked, sourced, titled):
            assert result.isError is False
            assert result.structuredContent["workspace_id"] == "workspace-2"
        assert created.structuredContent["document_id"] == "note-created"
        assert blank.isError is True
        assert "workspace_id must not be empty" in blank.content[0].text

        write_calls = [
            (name, payload)
            for name, payload in fake.calls
            if name in {"create", "update_content", "append", "update_tags", "update_title"}
        ]
        assert write_calls
        assert all(payload["workspace_id"] == "workspace-2" for _, payload in write_calls)
        assert not any(payload.get("workspace_id") == "workspace-1" for _, payload in write_calls)
        assert (
            "global_document_metadata",
            {"workspace_id": "workspace-3", "document_id": "target-1"},
        ) in fake.calls


async def _test_upstream_protocol_call_forwards_non_secret_gateway_meta() -> None:
    captured: dict[str, Any] = {}

    class FakeSession:
        _request_id = 7

        async def call_tool(
            self,
            name: str,
            arguments: dict[str, Any],
            *,
            meta: dict[str, Any] | None = None,
        ) -> types.CallToolResult:
            captured.update({"name": name, "arguments": arguments, "meta": meta})
            return types.CallToolResult(
                content=[types.TextContent(type="text", text="ok")], isError=False
            )

    manager = object.__new__(UpstreamMcpManager)
    manager._active_calls = set()
    manager.cancellation_grace_seconds = 0.1
    meta = {
        "gateway": {
            "idempotency_key": "mcp-action:preparation-123",
            "correlation_id": "correlation-1",
            "preparation_id": "preparation-123",
            "approval_request_id": "approval-1",
            "execution_permit_id": "permit-1",
        }
    }
    result = await manager._call_with_protocol_timeout(
        FakeSession(),
        "research_v1_note_create",
        {"title": "A", "content": "B"},
        1.0,
        meta=meta,
    )
    assert result.isError is False
    assert captured == {
        "name": "research_v1_note_create",
        "arguments": {"title": "A", "content": "B"},
        "meta": meta,
    }


def test_provider_requires_internal_bearer_and_exposes_stable_tool_contract() -> None:
    asyncio.run(
        _test_provider_requires_internal_bearer_and_exposes_stable_tool_contract()
    )


def test_provider_read_tools_use_affine_sdk_boundary() -> None:
    asyncio.run(_test_provider_read_tools_use_affine_sdk_boundary())


def test_provider_global_document_tools_use_affine_sdk_boundary() -> None:
    asyncio.run(_test_provider_global_document_tools_use_affine_sdk_boundary())


def test_provider_write_is_fail_closed_in_read_only_mode() -> None:
    asyncio.run(_test_provider_write_is_fail_closed_in_read_only_mode())


def test_provider_write_requires_and_forwards_gateway_bound_idempotency() -> None:
    asyncio.run(_test_provider_write_requires_and_forwards_gateway_bound_idempotency())


def test_provider_preserves_authoritative_content_conflict_as_tool_error() -> None:
    asyncio.run(_test_provider_preserves_authoritative_content_conflict_as_tool_error())


def test_provider_preserves_authoritative_title_conflict_as_tool_error() -> None:
    asyncio.run(_test_provider_preserves_authoritative_title_conflict_as_tool_error())


def test_provider_expanded_write_tools_use_affine_sdk_boundary() -> None:
    asyncio.run(_test_provider_expanded_write_tools_use_affine_sdk_boundary())


def test_provider_global_write_tools_use_explicit_workspace_boundary() -> None:
    asyncio.run(_test_provider_global_write_tools_use_explicit_workspace_boundary())


def test_upstream_protocol_call_forwards_non_secret_gateway_meta() -> None:
    asyncio.run(_test_upstream_protocol_call_forwards_non_secret_gateway_meta())
