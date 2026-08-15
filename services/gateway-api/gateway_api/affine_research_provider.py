from __future__ import annotations

import asyncio
import json
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal, Protocol, Self

from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl, BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.requests import Request
from starlette.responses import JSONResponse

from .client_credentials import ClientCredentialsTokenProvider
from .research_knowledge_contract import (
    ResearchLink,
    ResearchSourceReference,
    render_note_link,
    render_source_reference,
)


class AffineProviderSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AFFINE_PROVIDER_", extra="ignore")

    bridge_url: AnyHttpUrl | None = None
    workspace_id: str = ""
    keycloak_token_url: AnyHttpUrl | None = None
    keycloak_client_id: str = ""
    keycloak_client_secret: SecretStr = SecretStr("")
    keycloak_client_secret_file: str | None = None
    keycloak_scope: str = "affine.documents.read affine.graphql"
    internal_bearer_token: SecretStr = SecretStr("")
    internal_bearer_token_file: str | None = None
    access_mode: Literal["read_only", "read_write"] = "read_only"
    ca_bundle: str | None = None
    timeout_seconds: float = Field(default=20.0, gt=0, le=120)
    host: str = "0.0.0.0"
    port: int = Field(default=8010, ge=1, le=65535)
    auth_issuer_url: AnyHttpUrl = "http://affine-research-provider.internal"
    auth_resource_url: AnyHttpUrl = "http://affine-research-provider:8010"

    @staticmethod
    def _resolve_secret(direct: SecretStr, file_path: str | None, label: str) -> str:
        direct_value = direct.get_secret_value()
        if direct_value and file_path:
            raise RuntimeError(
                f"{label} must use either a direct value or a file, not both"
            )
        value = direct_value
        if file_path:
            try:
                value = Path(file_path).read_text(encoding="utf-8").strip()
            except OSError as error:
                raise RuntimeError(f"{label} file is unreadable") from error
        if not value:
            raise RuntimeError(f"{label} is not configured")
        if len(value) > 131072 or "\n" in value or "\r" in value:
            raise RuntimeError(f"{label} has an invalid value")
        return value

    def resolved_keycloak_client_secret(self) -> str:
        return self._resolve_secret(
            self.keycloak_client_secret,
            self.keycloak_client_secret_file,
            "AFFINE_PROVIDER_KEYCLOAK_CLIENT_SECRET",
        )

    def resolved_internal_bearer_token(self) -> str:
        return self._resolve_secret(
            self.internal_bearer_token,
            self.internal_bearer_token_file,
            "AFFINE_PROVIDER_INTERNAL_BEARER_TOKEN",
        )

    def validate_runtime(self) -> None:
        missing = [
            name
            for name, value in (
                ("AFFINE_PROVIDER_BRIDGE_URL", self.bridge_url),
                ("AFFINE_PROVIDER_WORKSPACE_ID", self.workspace_id),
                ("AFFINE_PROVIDER_KEYCLOAK_TOKEN_URL", self.keycloak_token_url),
                ("AFFINE_PROVIDER_KEYCLOAK_CLIENT_ID", self.keycloak_client_id),
            )
            if not value
        ]
        if missing:
            raise RuntimeError(
                "AFFiNE research provider configuration is incomplete: "
                + ",".join(missing)
            )
        self.resolved_keycloak_client_secret()
        self.resolved_internal_bearer_token()
        if self.access_mode == "read_write" and "affine.documents.write" not in {
            item.strip() for item in self.keycloak_scope.split() if item.strip()
        }:
            raise RuntimeError(
                "AFFINE_PROVIDER_KEYCLOAK_SCOPE must include affine.documents.write in read_write mode"
            )


class ProviderCapabilities(BaseModel):
    contract_version: Literal["research-knowledge/v1"] = "research-knowledge/v1"
    provider: Literal["affine"] = "affine"
    workspace_id: str
    access_mode: Literal["read_only", "read_write"]
    operations: list[str]
    conflict_detection: Literal["sha256-content-cas"] = "sha256-content-cas"
    idempotency: Literal["gateway-bound"] = "gateway-bound"


class ResearchNoteContent(BaseModel):
    provider: Literal["affine"] = "affine"
    workspace_id: str
    note_id: str
    content: str
    content_hash: str
    format: str
    canonical_url: str


class ResearchNoteMetadata(BaseModel):
    provider: Literal["affine"] = "affine"
    workspace_id: str
    note_id: str
    title: str
    tags: list[str]
    tags_hash: str
    canonical_url: str


class ResearchSearchMatch(BaseModel):
    note_id: str | None = None
    title: str | None = None
    created_at: str | None = None
    content: str


class ResearchSearchReply(BaseModel):
    provider: Literal["affine"] = "affine"
    workspace_id: str
    mode: Literal["keyword", "semantic"]
    matches: list[ResearchSearchMatch]


class ResearchSpaceRef(BaseModel):
    provider: Literal["affine"] = "affine"
    workspace_id: str
    name: str | None = None
    created_at: str
    space_ref: str


class ResearchSpacePage(BaseModel):
    provider: Literal["affine"] = "affine"
    visibility_mode: Literal["all_documents", "native_acl"]
    spaces: list[ResearchSpaceRef]
    next_cursor: str | None = None


class ResearchDocumentSummary(BaseModel):
    provider: Literal["affine"] = "affine"
    workspace_id: str
    document_id: str
    title: str | None = None
    created_at: str
    updated_at: str
    document_ref: str


class ResearchDocumentPage(BaseModel):
    provider: Literal["affine"] = "affine"
    visibility_mode: Literal["all_documents", "native_acl"]
    documents: list[ResearchDocumentSummary]
    next_cursor: str | None = None


class ResearchDocumentContent(BaseModel):
    provider: Literal["affine"] = "affine"
    workspace_id: str
    document_id: str
    title: str | None = None
    content: str
    content_hash: str
    format: str
    canonical_url: str
    document_ref: str


class ResearchDocumentMetadata(BaseModel):
    provider: Literal["affine"] = "affine"
    workspace_id: str
    document_id: str
    title: str
    tags: list[str]
    tags_hash: str
    canonical_url: str
    document_ref: str


class ResearchDocumentSearchMatch(BaseModel):
    workspace_id: str
    document_id: str | None = None
    title: str | None = None
    created_at: str | None = None
    content: str | None = None
    document_ref: str | None = None


class ResearchDocumentSearchReply(BaseModel):
    provider: Literal["affine"] = "affine"
    visibility_mode: Literal["all_documents", "native_acl"]
    mode: Literal["keyword", "semantic"]
    matches: list[ResearchDocumentSearchMatch]


class ResearchMutationReply(BaseModel):
    provider: Literal["affine"] = "affine"
    workspace_id: str
    note_id: str
    canonical_url: str
    content_hash: str | None = None
    tags: list[str] | None = None
    tags_hash: str | None = None
    operation_id: str | None = None
    replayed: bool = False


class ResearchDocumentMutationReply(BaseModel):
    provider: Literal["affine"] = "affine"
    workspace_id: str
    document_id: str
    canonical_url: str
    content_hash: str | None = None
    tags: list[str] | None = None
    tags_hash: str | None = None
    operation_id: str | None = None
    replayed: bool = False


class _BridgeClient(Protocol):
    async def ready(self) -> dict[str, Any]: ...

    async def create_affine_document(self, **kwargs: Any) -> Any: ...

    async def read_affine_document_content(
        self, note_id: str, **kwargs: Any
    ) -> Any: ...

    async def read_affine_document_metadata(
        self, note_id: str, **kwargs: Any
    ) -> Any: ...

    async def search_affine_documents(self, query: str, **kwargs: Any) -> list[Any]: ...

    async def list_affine_global_spaces(self, **kwargs: Any) -> Any: ...

    async def list_affine_global_documents(self, **kwargs: Any) -> Any: ...

    async def read_affine_global_document(
        self, workspace_id: str, document_id: str
    ) -> Any: ...

    async def read_affine_global_document_metadata(
        self, workspace_id: str, document_id: str
    ) -> Any: ...

    async def search_affine_global_documents(
        self, query: str, **kwargs: Any
    ) -> Any: ...

    async def update_affine_document_content(
        self, note_id: str, content: str, **kwargs: Any
    ) -> Any: ...

    async def append_affine_document_content(
        self, note_id: str, content: str, **kwargs: Any
    ) -> Any: ...

    async def update_affine_document_tags(
        self, note_id: str, tags: list[str], **kwargs: Any
    ) -> Any: ...

    async def update_affine_document_title(
        self, note_id: str, title: str, **kwargs: Any
    ) -> Any: ...

    async def __aenter__(self) -> Self: ...

    async def __aexit__(self, *args: object) -> None: ...


class _StaticBearerVerifier:
    def __init__(self, token: str) -> None:
        self._token = token

    async def verify_token(self, token: str) -> AccessToken | None:
        if not secrets.compare_digest(token, self._token):
            return None
        return AccessToken(
            token=token,
            client_id="chatgpt-mcp-gateway",
            scopes=["research:access"],
        )


class AffineResearchService:
    def __init__(
        self,
        settings: AffineProviderSettings,
        *,
        token_provider: ClientCredentialsTokenProvider | None = None,
        client_factory: Any | None = None,
    ) -> None:
        settings.validate_runtime()
        self.settings = settings
        self._token_provider = token_provider or ClientCredentialsTokenProvider(
            token_url=str(settings.keycloak_token_url),
            client_id=settings.keycloak_client_id,
            client_secret=settings.resolved_keycloak_client_secret(),
            scope=settings.keycloak_scope,
            timeout_seconds=min(settings.timeout_seconds, 30.0),
            ca_bundle=settings.ca_bundle,
            error_label="AFFiNE provider application token",
        )
        self._client_factory = client_factory

    @asynccontextmanager
    async def client(self) -> AsyncIterator[_BridgeClient]:
        token = await asyncio.to_thread(self._token_provider.get_token)
        factory = self._client_factory
        if factory is None:
            from affine_py_sdk import AffineBridgeClient

            factory = AffineBridgeClient
        client = factory(
            str(self.settings.bridge_url),
            workspace_id=self.settings.workspace_id,
            access_token=token,
            timeout=self.settings.timeout_seconds,
        )
        async with client as entered:
            yield entered

    async def ready(self) -> bool:
        try:
            async with self.client() as client:
                payload = await client.ready()
        except Exception:  # noqa: BLE001 - readiness must fail closed on any bridge failure.
            return False
        return isinstance(payload, dict) and payload.get("status") == "ready"

    def require_write(self) -> None:
        if self.settings.access_mode != "read_write":
            raise ToolError(
                json.dumps(
                    {
                        "error": {
                            "code": "AFFINE_PROVIDER_READ_ONLY",
                            "message": "AFFiNE provider writes are disabled by runtime policy",
                        }
                    },
                    sort_keys=True,
                )
            )

    @staticmethod
    def gateway_idempotency_key(ctx: Context) -> str:
        meta = ctx.request_context.meta
        data = meta.model_dump(mode="python") if meta is not None else {}
        gateway = data.get("gateway") if isinstance(data, dict) else None
        value = gateway.get("idempotency_key") if isinstance(gateway, dict) else None
        if not isinstance(value, str) or not value or len(value) > 240:
            raise ToolError(
                json.dumps(
                    {
                        "error": {
                            "code": "GATEWAY_IDEMPOTENCY_REQUIRED",
                            "message": "Write calls require Gateway-bound idempotency metadata",
                        }
                    },
                    sort_keys=True,
                )
            )
        return value

    @staticmethod
    def bridge_error(error: Exception) -> ToolError:
        status_code = getattr(error, "status_code", None)
        details = getattr(error, "details", None)
        safe_details: dict[str, Any] = {}
        if isinstance(details, dict):
            for key in (
                "code",
                "expected_content_hash",
                "current_content_hash",
                "expected_title",
                "current_title",
                "expected_tags_hash",
                "current_tags_hash",
                "operation_id",
                "replayed",
            ):
                value = details.get(key)
                if isinstance(value, (str, int, float, bool)) or value is None:
                    safe_details[key] = value
        code = safe_details.get("code") or "AFFINE_BRIDGE_ERROR"
        payload = {
            "error": {
                "code": code,
                "status_code": status_code,
                "details": safe_details,
            }
        }
        return ToolError(json.dumps(payload, sort_keys=True))


READ_ONLY = ToolAnnotations(
    title="Research knowledge read",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)
WRITE = ToolAnnotations(
    title="Research knowledge write",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)


def build_mcp(
    settings: AffineProviderSettings | None = None,
    *,
    service: AffineResearchService | None = None,
) -> FastMCP:
    resolved = settings or AffineProviderSettings()
    resolved.validate_runtime()
    active_service = service or AffineResearchService(resolved)
    internal_bearer_token = resolved.resolved_internal_bearer_token()
    mcp = FastMCP(
        name="affine-research-knowledge-provider",
        instructions=(
            "Provider-neutral research document facade backed by AFFiNE. "
            "Writes use explicit workspace targets, authoritative AFFiNE CAS and Gateway-bound idempotency."
        ),
        host=resolved.host,
        port=resolved.port,
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        auth=AuthSettings(
            issuer_url=resolved.auth_issuer_url,
            resource_server_url=resolved.auth_resource_url,
            required_scopes=["research:access"],
        ),
        token_verifier=_StaticBearerVerifier(internal_bearer_token),
    )

    @mcp.custom_route("/ready", methods=["GET"], include_in_schema=False)
    async def provider_ready(request: Request) -> JSONResponse:
        authorization = request.headers.get("authorization", "")
        scheme, separator, presented_token = authorization.partition(" ")
        if (
            scheme.casefold() != "bearer"
            or not separator
            or not presented_token
            or not secrets.compare_digest(presented_token, internal_bearer_token)
        ):
            return JSONResponse(
                {"error": {"code": "UNAUTHORIZED"}},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        ready = await active_service.ready()
        return JSONResponse(
            {"status": "ready" if ready else "not_ready"},
            status_code=200 if ready else 503,
        )

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    async def research_v1_provider_capabilities() -> ProviderCapabilities:
        operations = [
            "capabilities",
            "read",
            "metadata",
            "search",
            "space_list",
            "document_list",
            "document_read",
            "document_metadata",
            "document_search",
        ]
        if resolved.access_mode == "read_write":
            operations.extend(
                [
                    "create",
                    "update_content",
                    "append",
                    "update_tags",
                    "link",
                    "source_reference",
                    "update_title",
                ]
            )
        return ProviderCapabilities(
            workspace_id=resolved.workspace_id,
            access_mode=resolved.access_mode,
            operations=operations,
        )

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    async def research_v1_space_list(
        cursor: str | None = None,
        limit: int = 50,
    ) -> ResearchSpacePage:
        if limit < 1 or limit > 100:
            raise ToolError("limit must be between 1 and 100")
        try:
            async with active_service.client() as client:
                value = await client.list_affine_global_spaces(
                    cursor=cursor,
                    limit=limit,
                )
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchSpacePage(
            visibility_mode=value.visibility_mode,
            spaces=[
                ResearchSpaceRef(
                    workspace_id=item.workspace_id,
                    name=item.name,
                    created_at=item.created_at,
                    space_ref=item.space_ref,
                )
                for item in value.spaces
            ],
            next_cursor=value.next_cursor,
        )

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    async def research_v1_document_list(
        workspace_id: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> ResearchDocumentPage:
        if limit < 1 or limit > 100:
            raise ToolError("limit must be between 1 and 100")
        try:
            async with active_service.client() as client:
                value = await client.list_affine_global_documents(
                    workspace_id=workspace_id,
                    cursor=cursor,
                    limit=limit,
                )
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchDocumentPage(
            visibility_mode=value.visibility_mode,
            documents=[
                ResearchDocumentSummary(
                    workspace_id=item.workspace_id,
                    document_id=item.doc_id,
                    title=item.title,
                    created_at=item.created_at,
                    updated_at=item.updated_at,
                    document_ref=item.document_ref,
                )
                for item in value.documents
            ],
            next_cursor=value.next_cursor,
        )

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    async def research_v1_document_read(
        workspace_id: str,
        document_id: str,
    ) -> ResearchDocumentContent:
        try:
            async with active_service.client() as client:
                value = await client.read_affine_global_document(
                    workspace_id,
                    document_id,
                )
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchDocumentContent(
            workspace_id=value.workspace_id,
            document_id=value.doc_id,
            title=value.title,
            content=value.content,
            content_hash=value.content_hash,
            format=value.format,
            canonical_url=value.web_url,
            document_ref=value.document_ref,
        )

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    async def research_v1_document_metadata(
        workspace_id: str,
        document_id: str,
    ) -> ResearchDocumentMetadata:
        try:
            async with active_service.client() as client:
                value = await client.read_affine_global_document_metadata(
                    workspace_id,
                    document_id,
                )
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchDocumentMetadata(
            workspace_id=value.workspace_id,
            document_id=value.doc_id,
            title=value.title,
            tags=list(value.tags),
            tags_hash=value.tags_hash,
            canonical_url=value.web_url,
            document_ref=value.document_ref,
        )

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    async def research_v1_document_search(
        query: str,
        mode: Literal["keyword", "semantic"] = "keyword",
        workspace_id: str | None = None,
        limit: int = 20,
    ) -> ResearchDocumentSearchReply:
        if not query.strip():
            raise ToolError("document search query must not be empty")
        if limit < 1 or limit > 100:
            raise ToolError("limit must be between 1 and 100")
        try:
            async with active_service.client() as client:
                value = await client.search_affine_global_documents(
                    query,
                    mode=mode,
                    workspace_id=workspace_id,
                    limit=limit,
                )
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchDocumentSearchReply(
            visibility_mode=value.visibility_mode,
            mode=value.mode,
            matches=[
                ResearchDocumentSearchMatch(
                    workspace_id=item.workspace_id,
                    document_id=item.doc_id,
                    title=item.title,
                    created_at=item.created_at,
                    content=item.content,
                    document_ref=item.document_ref,
                )
                for item in value.results
            ],
        )

    def require_explicit_target(value: str, label: str) -> str:
        target = value.strip()
        if not target:
            raise ToolError(f"{label} must not be empty")
        return target

    async def append_document(
        workspace_id: str,
        document_id: str,
        content: str,
        expected_content_hash: str,
        ctx: Context,
    ) -> ResearchDocumentMutationReply:
        active_service.require_write()
        workspace_id = require_explicit_target(workspace_id, "workspace_id")
        document_id = require_explicit_target(document_id, "document_id")
        idempotency_key = active_service.gateway_idempotency_key(ctx)
        try:
            async with active_service.client() as client:
                value = await client.append_affine_document_content(
                    document_id,
                    content,
                    expected_content_hash=expected_content_hash,
                    workspace_id=workspace_id,
                    idempotency_key=idempotency_key,
                )
        except ToolError:
            raise
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchDocumentMutationReply(
            workspace_id=workspace_id,
            document_id=value.doc_id,
            canonical_url=value.web_url,
            content_hash=value.content_hash,
            operation_id=value.operation_id,
            replayed=value.replayed,
        )

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_document_create(
        workspace_id: str,
        title: str,
        content: str,
        ctx: Context,
    ) -> ResearchDocumentMutationReply:
        active_service.require_write()
        workspace_id = require_explicit_target(workspace_id, "workspace_id")
        idempotency_key = active_service.gateway_idempotency_key(ctx)
        try:
            async with active_service.client() as client:
                value = await client.create_affine_document(
                    title=title,
                    content=content,
                    workspace_id=workspace_id,
                    idempotency_key=idempotency_key,
                )
        except ToolError:
            raise
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchDocumentMutationReply(
            workspace_id=workspace_id,
            document_id=value.doc_id,
            canonical_url=value.web_url,
            content_hash=value.content_hash,
            operation_id=value.operation_id,
            replayed=value.replayed,
        )

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_document_update_content(
        workspace_id: str,
        document_id: str,
        content: str,
        expected_content_hash: str,
        ctx: Context,
    ) -> ResearchDocumentMutationReply:
        active_service.require_write()
        workspace_id = require_explicit_target(workspace_id, "workspace_id")
        document_id = require_explicit_target(document_id, "document_id")
        idempotency_key = active_service.gateway_idempotency_key(ctx)
        try:
            async with active_service.client() as client:
                value = await client.update_affine_document_content(
                    document_id,
                    content,
                    expected_content_hash=expected_content_hash,
                    workspace_id=workspace_id,
                    idempotency_key=idempotency_key,
                )
        except ToolError:
            raise
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchDocumentMutationReply(
            workspace_id=workspace_id,
            document_id=value.doc_id,
            canonical_url=value.web_url,
            content_hash=value.content_hash,
            operation_id=value.operation_id,
            replayed=value.replayed,
        )

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_document_append(
        workspace_id: str,
        document_id: str,
        content: str,
        expected_content_hash: str,
        ctx: Context,
    ) -> ResearchDocumentMutationReply:
        if not content:
            raise ToolError("append content must not be empty")
        return await append_document(
            workspace_id,
            document_id,
            content,
            expected_content_hash,
            ctx,
        )

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_document_set_tags(
        workspace_id: str,
        document_id: str,
        tags: list[str],
        expected_tags_hash: str,
        ctx: Context,
    ) -> ResearchDocumentMutationReply:
        active_service.require_write()
        workspace_id = require_explicit_target(workspace_id, "workspace_id")
        document_id = require_explicit_target(document_id, "document_id")
        idempotency_key = active_service.gateway_idempotency_key(ctx)
        try:
            async with active_service.client() as client:
                value = await client.update_affine_document_tags(
                    document_id,
                    tags,
                    expected_tags_hash=expected_tags_hash,
                    workspace_id=workspace_id,
                    idempotency_key=idempotency_key,
                )
        except ToolError:
            raise
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchDocumentMutationReply(
            workspace_id=workspace_id,
            document_id=value.doc_id,
            canonical_url=value.web_url,
            tags=list(value.tags) if value.tags is not None else None,
            tags_hash=value.tags_hash,
            operation_id=value.operation_id,
            replayed=value.replayed,
        )

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_document_link(
        workspace_id: str,
        document_id: str,
        target_workspace_id: str,
        target_document_id: str,
        expected_content_hash: str,
        ctx: Context,
        label: str | None = None,
    ) -> ResearchDocumentMutationReply:
        active_service.require_write()
        workspace_id = require_explicit_target(workspace_id, "workspace_id")
        document_id = require_explicit_target(document_id, "document_id")
        target_workspace_id = require_explicit_target(
            target_workspace_id, "target_workspace_id"
        )
        target_document_id = require_explicit_target(
            target_document_id, "target_document_id"
        )
        try:
            async with active_service.client() as client:
                target = await client.read_affine_global_document_metadata(
                    target_workspace_id,
                    target_document_id,
                )
        except Exception as error:
            raise active_service.bridge_error(error) from error
        rendered = render_note_link(
            ResearchLink(
                target_note_id=target_document_id,
                target_url=target.web_url,
                label=label or target.title or target_document_id,
            )
        )
        return await append_document(
            workspace_id,
            document_id,
            rendered,
            expected_content_hash,
            ctx,
        )

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_document_add_source(
        workspace_id: str,
        document_id: str,
        url: str,
        title: str,
        expected_content_hash: str,
        ctx: Context,
        locator: str | None = None,
    ) -> ResearchDocumentMutationReply:
        active_service.require_write()
        workspace_id = require_explicit_target(workspace_id, "workspace_id")
        document_id = require_explicit_target(document_id, "document_id")
        try:
            rendered = render_source_reference(
                ResearchSourceReference(url=url, title=title, locator=locator)
            )
        except ValueError as error:
            raise ToolError(str(error)) from error
        return await append_document(
            workspace_id,
            document_id,
            rendered,
            expected_content_hash,
            ctx,
        )

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_document_update_title(
        workspace_id: str,
        document_id: str,
        title: str,
        expected_title: str,
        ctx: Context,
    ) -> ResearchDocumentMutationReply:
        active_service.require_write()
        workspace_id = require_explicit_target(workspace_id, "workspace_id")
        document_id = require_explicit_target(document_id, "document_id")
        idempotency_key = active_service.gateway_idempotency_key(ctx)
        try:
            async with active_service.client() as client:
                value = await client.update_affine_document_title(
                    document_id,
                    title,
                    expected_title=expected_title,
                    workspace_id=workspace_id,
                    idempotency_key=idempotency_key,
                )
        except ToolError:
            raise
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchDocumentMutationReply(
            workspace_id=workspace_id,
            document_id=value.doc_id,
            canonical_url=value.web_url,
            content_hash=value.content_hash,
            operation_id=value.operation_id,
            replayed=value.replayed,
        )

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    async def research_v1_note_read(note_id: str) -> ResearchNoteContent:
        try:
            async with active_service.client() as client:
                value = await client.read_affine_document_content(
                    note_id, workspace_id=resolved.workspace_id
                )
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchNoteContent(
            workspace_id=value.workspace_id,
            note_id=value.doc_id,
            content=value.content,
            content_hash=value.content_hash,
            format=value.format,
            canonical_url=value.web_url,
        )

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    async def research_v1_note_metadata(note_id: str) -> ResearchNoteMetadata:
        try:
            async with active_service.client() as client:
                value = await client.read_affine_document_metadata(
                    note_id, workspace_id=resolved.workspace_id
                )
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchNoteMetadata(
            workspace_id=value.workspace_id,
            note_id=value.doc_id,
            title=value.title,
            tags=list(value.tags),
            tags_hash=value.tags_hash,
            canonical_url=value.web_url,
        )

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    async def research_v1_note_search(
        query: str,
        mode: Literal["keyword", "semantic"] = "keyword",
    ) -> ResearchSearchReply:
        if not query.strip():
            raise ToolError("research query must not be empty")
        try:
            async with active_service.client() as client:
                values = await client.search_affine_documents(
                    query, mode=mode, workspace_id=resolved.workspace_id
                )
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchSearchReply(
            workspace_id=resolved.workspace_id,
            mode=mode,
            matches=[
                ResearchSearchMatch(
                    note_id=value.doc_id,
                    title=value.title,
                    created_at=value.created_at,
                    content=value.content,
                )
                for value in values
            ],
        )

    async def append_note(
        note_id: str,
        content: str,
        expected_content_hash: str,
        ctx: Context,
    ) -> ResearchMutationReply:
        active_service.require_write()
        idempotency_key = active_service.gateway_idempotency_key(ctx)
        try:
            async with active_service.client() as client:
                value = await client.append_affine_document_content(
                    note_id,
                    content,
                    expected_content_hash=expected_content_hash,
                    workspace_id=resolved.workspace_id,
                    idempotency_key=idempotency_key,
                )
        except ToolError:
            raise
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchMutationReply(
            workspace_id=resolved.workspace_id,
            note_id=value.doc_id,
            canonical_url=value.web_url,
            content_hash=value.content_hash,
            operation_id=value.operation_id,
            replayed=value.replayed,
        )

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_note_create(
        title: str,
        content: str,
        ctx: Context,
    ) -> ResearchMutationReply:
        active_service.require_write()
        idempotency_key = active_service.gateway_idempotency_key(ctx)
        try:
            async with active_service.client() as client:
                value = await client.create_affine_document(
                    title=title,
                    content=content,
                    workspace_id=resolved.workspace_id,
                    idempotency_key=idempotency_key,
                )
        except ToolError:
            raise
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchMutationReply(
            workspace_id=resolved.workspace_id,
            note_id=value.doc_id,
            canonical_url=value.web_url,
            content_hash=value.content_hash,
            operation_id=value.operation_id,
            replayed=value.replayed,
        )

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_note_update_content(
        note_id: str,
        content: str,
        expected_content_hash: str,
        ctx: Context,
    ) -> ResearchMutationReply:
        active_service.require_write()
        idempotency_key = active_service.gateway_idempotency_key(ctx)
        try:
            async with active_service.client() as client:
                value = await client.update_affine_document_content(
                    note_id,
                    content,
                    expected_content_hash=expected_content_hash,
                    workspace_id=resolved.workspace_id,
                    idempotency_key=idempotency_key,
                )
        except ToolError:
            raise
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchMutationReply(
            workspace_id=resolved.workspace_id,
            note_id=value.doc_id,
            canonical_url=value.web_url,
            content_hash=value.content_hash,
            operation_id=value.operation_id,
            replayed=value.replayed,
        )

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_note_append(
        note_id: str,
        content: str,
        expected_content_hash: str,
        ctx: Context,
    ) -> ResearchMutationReply:
        if not content:
            raise ToolError("append content must not be empty")
        return await append_note(note_id, content, expected_content_hash, ctx)

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_note_set_tags(
        note_id: str,
        tags: list[str],
        expected_tags_hash: str,
        ctx: Context,
    ) -> ResearchMutationReply:
        active_service.require_write()
        idempotency_key = active_service.gateway_idempotency_key(ctx)
        try:
            async with active_service.client() as client:
                value = await client.update_affine_document_tags(
                    note_id,
                    tags,
                    expected_tags_hash=expected_tags_hash,
                    workspace_id=resolved.workspace_id,
                    idempotency_key=idempotency_key,
                )
        except ToolError:
            raise
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchMutationReply(
            workspace_id=resolved.workspace_id,
            note_id=value.doc_id,
            canonical_url=value.web_url,
            tags=list(value.tags) if value.tags is not None else None,
            tags_hash=value.tags_hash,
            operation_id=value.operation_id,
            replayed=value.replayed,
        )

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_note_link(
        note_id: str,
        target_note_id: str,
        expected_content_hash: str,
        ctx: Context,
        label: str | None = None,
    ) -> ResearchMutationReply:
        try:
            async with active_service.client() as client:
                target = await client.read_affine_document_metadata(
                    target_note_id,
                    workspace_id=resolved.workspace_id,
                )
        except Exception as error:
            raise active_service.bridge_error(error) from error
        rendered = render_note_link(
            ResearchLink(
                target_note_id=target_note_id,
                target_url=target.web_url,
                label=label or target.title or target_note_id,
            )
        )
        return await append_note(note_id, rendered, expected_content_hash, ctx)

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_note_add_source(
        note_id: str,
        url: str,
        title: str,
        expected_content_hash: str,
        ctx: Context,
        locator: str | None = None,
    ) -> ResearchMutationReply:
        try:
            rendered = render_source_reference(
                ResearchSourceReference(url=url, title=title, locator=locator)
            )
        except ValueError as error:
            raise ToolError(str(error)) from error
        return await append_note(note_id, rendered, expected_content_hash, ctx)

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_note_update_title(
        note_id: str,
        title: str,
        expected_title: str | None,
        ctx: Context,
    ) -> ResearchMutationReply:
        active_service.require_write()
        idempotency_key = active_service.gateway_idempotency_key(ctx)
        try:
            async with active_service.client() as client:
                value = await client.update_affine_document_title(
                    note_id,
                    title,
                    expected_title=expected_title,
                    workspace_id=resolved.workspace_id,
                    idempotency_key=idempotency_key,
                )
        except ToolError:
            raise
        except Exception as error:
            raise active_service.bridge_error(error) from error
        return ResearchMutationReply(
            workspace_id=resolved.workspace_id,
            note_id=value.doc_id,
            canonical_url=value.web_url,
            content_hash=value.content_hash,
            operation_id=value.operation_id,
            replayed=value.replayed,
        )

    return mcp


def main() -> None:
    settings = AffineProviderSettings()
    mcp = build_mcp(settings)
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
