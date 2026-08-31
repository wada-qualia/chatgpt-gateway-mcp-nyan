from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import quote

from mcp.server import MCPServer
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver.context import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl, BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.requests import Request
from starlette.responses import JSONResponse

from .research_knowledge_contract import (
    ResearchLink,
    ResearchSourceReference,
    render_note_link,
    render_source_reference,
)


class ObsidianProviderSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OBSIDIAN_PROVIDER_", extra="ignore")

    vault_root: str = ""
    vault_name: str = ""
    allowed_prefixes: str = "Research"
    default_folder: str = "Research"
    access_mode: Literal["read_only", "read_write"] = "read_only"
    internal_bearer_token: SecretStr = SecretStr("")
    internal_bearer_token_file: str | None = None
    host: str = "0.0.0.0"
    port: int = Field(default=8011, ge=1, le=65535)
    auth_issuer_url: AnyHttpUrl = "http://obsidian-research-provider.internal"
    auth_resource_url: AnyHttpUrl = "http://obsidian-research-provider:8011"

    def resolved_internal_bearer_token(self) -> str:
        direct = self.internal_bearer_token.get_secret_value()
        if direct and self.internal_bearer_token_file:
            raise RuntimeError("OBSIDIAN_PROVIDER_INTERNAL_BEARER_TOKEN must use value or file")
        value = direct
        if self.internal_bearer_token_file:
            try:
                value = Path(self.internal_bearer_token_file).read_text(encoding="utf-8").strip()
            except OSError as error:
                raise RuntimeError("OBSIDIAN provider bearer file is unreadable") from error
        if not value or "\n" in value or "\r" in value or len(value) > 131072:
            raise RuntimeError("OBSIDIAN provider bearer token is not configured")
        return value

    def prefix_list(self) -> tuple[str, ...]:
        values = tuple(value.strip().strip("/") for value in self.allowed_prefixes.split(",") if value.strip())
        if not values:
            raise RuntimeError("OBSIDIAN_PROVIDER_ALLOWED_PREFIXES must not be empty")
        return values

    def validate_runtime(self) -> None:
        if not self.vault_root:
            raise RuntimeError("OBSIDIAN_PROVIDER_VAULT_ROOT is not configured")
        root = Path(self.vault_root).expanduser()
        if not root.is_dir():
            raise RuntimeError("OBSIDIAN provider vault root does not exist")
        self.prefix_list()
        self.resolved_internal_bearer_token()


class ObsidianConflictError(RuntimeError):
    def __init__(self, code: str, expected: str, current: str) -> None:
        super().__init__(code)
        self.code = code
        self.expected = expected
        self.current = current


class ObsidianNote(BaseModel):
    provider: Literal["obsidian"] = "obsidian"
    workspace_id: str
    note_id: str
    title: str
    content: str
    content_hash: str
    tags: list[str]
    tags_hash: str
    format: Literal["markdown"] = "markdown"
    canonical_url: str


class ObsidianNoteMetadata(BaseModel):
    provider: Literal["obsidian"] = "obsidian"
    workspace_id: str
    note_id: str
    title: str
    tags: list[str]
    tags_hash: str
    canonical_url: str


class ObsidianSearchMatch(BaseModel):
    note_id: str
    title: str
    canonical_url: str


class ObsidianSearchReply(BaseModel):
    provider: Literal["obsidian"] = "obsidian"
    workspace_id: str
    mode: Literal["keyword"] = "keyword"
    matches: list[ObsidianSearchMatch]


class ObsidianMutation(BaseModel):
    provider: Literal["obsidian"] = "obsidian"
    workspace_id: str
    note_id: str
    canonical_url: str
    content_hash: str | None = None
    tags: list[str] | None = None
    tags_hash: str | None = None
    replayed: bool = False


class ObsidianCapabilities(BaseModel):
    contract_version: Literal["research-knowledge/v1"] = "research-knowledge/v1"
    provider: Literal["obsidian"] = "obsidian"
    workspace_id: str
    access_mode: Literal["read_only", "read_write"]
    operations: list[str]
    conflict_detection: Literal["sha256-content-and-tags-cas"] = "sha256-content-and-tags-cas"
    idempotency: Literal["gateway-bound"] = "gateway-bound"


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _idempotency_digest(key: str) -> str:
    if not key or len(key) > 240 or "\n" in key or "\r" in key:
        raise ValueError("invalid Gateway idempotency key")
    return _hash(key)


def _append_idempotency_marker(key: str) -> str:
    return f"<!-- gateway-idempotency:v1 {_idempotency_digest(key)} -->"


def _normalize_tags(tags: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in tags:
        value = " ".join(raw.replace("\r", " ").replace("\n", " ").split())
        if not value:
            continue
        key = value.casefold()
        if key in seen:
            continue
        if len(value) > 120:
            raise ValueError("tag is too long")
        seen.add(key)
        out.append(value)
    if len(out) > 64:
        raise ValueError("too many tags")
    return out


def _tags_hash(tags: list[str]) -> str:
    return _hash(json.dumps(sorted(_normalize_tags(tags)), ensure_ascii=False, separators=(",", ":")))


def _split_frontmatter(text: str) -> tuple[list[str], str]:
    if not text.startswith("---\n"):
        return [], text
    end = text.find("\n---\n", 4)
    if end < 0:
        return [], text
    return text[4:end].splitlines(), text[end + 5 :]


def _frontmatter_scalar(lines: list[str], key: str) -> str | None:
    prefix = f"{key}:"
    for line in lines:
        if line.startswith(prefix):
            value = line[len(prefix) :].strip()
            if value.startswith('"') and value.endswith('"'):
                try:
                    parsed = json.loads(value)
                    return parsed if isinstance(parsed, str) else None
                except json.JSONDecodeError:
                    return None
            return value or None
    return None


def _frontmatter_tags(lines: list[str]) -> list[str]:
    for index, line in enumerate(lines):
        if not line.startswith("tags:"):
            continue
        inline = line[5:].strip()
        if inline:
            if inline.startswith("["):
                try:
                    values = json.loads(inline)
                    if isinstance(values, list):
                        return _normalize_tags([str(value) for value in values])
                except json.JSONDecodeError:
                    pass
            return _normalize_tags([inline.strip('"\'')])
        values: list[str] = []
        for nested in lines[index + 1 :]:
            if nested.startswith("  - "):
                raw = nested[4:].strip()
                if raw.startswith('"') and raw.endswith('"'):
                    try:
                        raw = json.loads(raw)
                    except json.JSONDecodeError:
                        pass
                values.append(str(raw))
                continue
            if nested.startswith((" ", "\t")) or not nested.strip():
                continue
            break
        return _normalize_tags(values)
    return []


def _replace_frontmatter_key(lines: list[str], key: str, replacement: list[str]) -> list[str]:
    prefix = f"{key}:"
    start: int | None = None
    end: int | None = None
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            start = index
            end = index + 1
            while end < len(lines) and (not lines[end].strip() or lines[end].startswith((" ", "\t"))):
                end += 1
            break
    if start is None:
        return [*lines, *replacement]
    return [*lines[:start], *replacement, *lines[end:]]


def _render_document(title: str, tags: list[str], body: str, original_meta: list[str] | None = None) -> str:
    meta = list(original_meta or [])
    meta = _replace_frontmatter_key(meta, "title", [f"title: {json.dumps(title, ensure_ascii=False)}"])
    tag_lines = ["tags:", *[f"  - {json.dumps(tag, ensure_ascii=False)}" for tag in _normalize_tags(tags)]]
    meta = _replace_frontmatter_key(meta, "tags", tag_lines)
    return f"---\n{'\n'.join(meta)}\n---\n{body}"


class ObsidianVaultStore:
    def __init__(self, settings: ObsidianProviderSettings) -> None:
        settings.validate_runtime()
        self.settings = settings
        self.root = Path(settings.vault_root).expanduser().resolve(strict=True)
        self.prefixes = tuple(PurePosixPath(value) for value in settings.prefix_list())
        self.default_folder = PurePosixPath(settings.default_folder.strip().strip("/"))
        if not self._allowed(self.default_folder / "probe.md"):
            raise RuntimeError("OBSIDIAN_PROVIDER_DEFAULT_FOLDER is outside allowed prefixes")
        try:
            self.default_directory = self.root.joinpath(*self.default_folder.parts).resolve(
                strict=True
            )
            self.default_directory.relative_to(self.root)
        except (OSError, ValueError) as error:
            raise RuntimeError(
                "OBSIDIAN_PROVIDER_DEFAULT_FOLDER must resolve inside the configured vault"
            ) from error
        if not self.default_directory.is_dir():
            raise RuntimeError("OBSIDIAN_PROVIDER_DEFAULT_FOLDER must be a directory")
        self.workspace_id = settings.vault_name or self.root.name
        self._lock_path = self.root / ".gateway-research.lock"

    @contextmanager
    def _write_lock(self) -> Iterator[None]:
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self._lock_path, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError("Obsidian provider vault lock is not a regular file")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _allowed(self, relative: PurePosixPath) -> bool:
        return any(relative == prefix or prefix in relative.parents for prefix in self.prefixes)

    def _resolve(self, note_id: str, *, must_exist: bool) -> tuple[PurePosixPath, Path]:
        relative = PurePosixPath(note_id)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError("note path is outside the configured vault")
        if relative.suffix.casefold() != ".md":
            raise ValueError("only Markdown notes are allowed")
        if not self._allowed(relative):
            raise ValueError("note path is outside the allowed prefixes")
        candidate = self.root.joinpath(*relative.parts)
        if must_exist:
            resolved = candidate.resolve(strict=True)
        else:
            parent = candidate.parent.resolve(strict=True)
            resolved = parent / candidate.name
        try:
            resolved.relative_to(self.root)
        except ValueError as error:
            raise ValueError("note path escapes the configured vault") from error
        if must_exist and not resolved.is_file():
            raise FileNotFoundError(note_id)
        return relative, resolved

    def canonical_url(self, note_id: str) -> str:
        path_without_suffix = str(PurePosixPath(note_id).with_suffix(""))
        return f"obsidian://open?vault={quote(self.workspace_id)}&file={quote(path_without_suffix)}"

    def read(self, note_id: str) -> ObsidianNote:
        relative, path = self._resolve(note_id, must_exist=True)
        text = path.read_text(encoding="utf-8")
        meta, body = _split_frontmatter(text)
        title = _frontmatter_scalar(meta, "title") or path.stem
        tags = _frontmatter_tags(meta)
        return ObsidianNote(
            workspace_id=self.workspace_id,
            note_id=str(relative),
            title=title,
            content=body,
            content_hash=_hash(body),
            tags=tags,
            tags_hash=_tags_hash(tags),
            canonical_url=self.canonical_url(str(relative)),
        )

    def _atomic_write(self, path: Path, value: str) -> None:
        path.parent.mkdir(parents=False, exist_ok=True)
        descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temp_path = Path(temp_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_path, path.stat().st_mode & 0o777 if path.exists() else 0o600)
            os.replace(temp_path, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def create(
        self, title: str, content: str, idempotency_key: str
    ) -> tuple[ObsidianNote, bool]:
        with self._write_lock():
            clean_title = " ".join(
                title.replace("\r", " ").replace("\n", " ").split()
            )
            if not clean_title:
                raise ValueError("title must not be empty")
            digest = _idempotency_digest(idempotency_key)
            note_id = str(self.default_folder / f"gateway-{digest[:32]}.md")
            _, path = self._resolve(note_id, must_exist=False)
            if path.exists():
                existing = self.read(note_id)
                if existing.title == clean_title and existing.content == content:
                    return existing, True
                raise ObsidianConflictError(
                    "IDEMPOTENCY_CONFLICT",
                    _hash(f"{clean_title}\0{content}"),
                    _hash(f"{existing.title}\0{existing.content}"),
                )
            self._atomic_write(path, _render_document(clean_title, [], content))
            return self.read(note_id), False

    def _update_content_locked(
        self, note_id: str, content: str, expected_hash: str
    ) -> tuple[ObsidianNote, bool]:
        relative, path = self._resolve(note_id, must_exist=True)
        text = path.read_text(encoding="utf-8")
        meta, body = _split_frontmatter(text)
        current = _hash(body)
        desired = _hash(content)
        if current == desired:
            return self.read(str(relative)), True
        if current != expected_hash:
            raise ObsidianConflictError("DOCUMENT_CONTENT_CONFLICT", expected_hash, current)
        title = _frontmatter_scalar(meta, "title") or path.stem
        tags = _frontmatter_tags(meta)
        self._atomic_write(path, _render_document(title, tags, content, meta))
        return self.read(str(relative)), False

    def update_content(
        self, note_id: str, content: str, expected_hash: str
    ) -> tuple[ObsidianNote, bool]:
        with self._write_lock():
            return self._update_content_locked(note_id, content, expected_hash)

    def append(
        self,
        note_id: str,
        content: str,
        expected_hash: str,
        idempotency_key: str,
    ) -> tuple[ObsidianNote, bool]:
        with self._write_lock():
            current = self.read(note_id)
            marker = _append_idempotency_marker(idempotency_key)
            if marker in current.content:
                return current, True
            if current.content_hash != expected_hash:
                raise ObsidianConflictError(
                    "DOCUMENT_CONTENT_CONFLICT", expected_hash, current.content_hash
                )
            separator = (
                ""
                if not current.content or current.content.endswith("\n\n")
                else "\n"
                if current.content.endswith("\n")
                else "\n\n"
            )
            next_content = f"{current.content}{separator}{marker}\n{content}"
            note, _ = self._update_content_locked(
                note_id, next_content, expected_hash
            )
            return note, False

    def set_tags(
        self, note_id: str, tags: list[str], expected_hash: str
    ) -> tuple[ObsidianNote, bool]:
        with self._write_lock():
            relative, path = self._resolve(note_id, must_exist=True)
            text = path.read_text(encoding="utf-8")
            meta, body = _split_frontmatter(text)
            current_tags = _frontmatter_tags(meta)
            next_tags = _normalize_tags(tags)
            current_hash = _tags_hash(current_tags)
            if current_tags == next_tags:
                return self.read(str(relative)), True
            if current_hash != expected_hash:
                raise ObsidianConflictError(
                    "DOCUMENT_TAGS_CONFLICT", expected_hash, current_hash
                )
            title = _frontmatter_scalar(meta, "title") or path.stem
            self._atomic_write(path, _render_document(title, next_tags, body, meta))
            return self.read(str(relative)), False

    def update_title(
        self, note_id: str, title: str, expected_title: str | None
    ) -> tuple[ObsidianNote, bool]:
        with self._write_lock():
            relative, path = self._resolve(note_id, must_exist=True)
            text = path.read_text(encoding="utf-8")
            meta, body = _split_frontmatter(text)
            current = _frontmatter_scalar(meta, "title") or path.stem
            clean = " ".join(
                title.replace("\r", " ").replace("\n", " ").split()
            )
            if not clean:
                raise ValueError("title must not be empty")
            if current == clean:
                return self.read(str(relative)), True
            if expected_title is not None and current != expected_title:
                raise ObsidianConflictError(
                    "DOCUMENT_TITLE_CONFLICT", expected_title, current
                )
            tags = _frontmatter_tags(meta)
            self._atomic_write(path, _render_document(clean, tags, body, meta))
            return self.read(str(relative)), False

    def search(self, query: str) -> list[ObsidianNote]:
        needle = query.casefold().strip()
        if not needle:
            return []
        matches: list[ObsidianNote] = []
        for prefix in self.prefixes:
            directory = self.root.joinpath(*prefix.parts)
            if not directory.is_dir():
                continue
            for path in directory.rglob("*.md"):
                try:
                    resolved = path.resolve(strict=True)
                    resolved.relative_to(self.root)
                except (OSError, ValueError):
                    continue
                note = self.read(str(resolved.relative_to(self.root).as_posix()))
                if needle in note.title.casefold() or needle in note.content.casefold() or any(needle in tag.casefold() for tag in note.tags):
                    matches.append(note)
        return matches[:50]


class _StaticBearerVerifier:
    def __init__(self, token: str) -> None:
        self._token = token

    async def verify_token(self, token: str) -> AccessToken | None:
        if not secrets.compare_digest(token, self._token):
            return None
        return AccessToken(token=token, client_id="chatgpt-mcp-gateway", scopes=["research:access"])


READ_ONLY = ToolAnnotations(title="Research knowledge read", readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
WRITE = ToolAnnotations(title="Research knowledge write", readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False)


def _gateway_idempotency_key(ctx: Context) -> str:
    meta = ctx.request_context.meta
    data = dict(meta) if isinstance(meta, dict) else (meta.model_dump(mode="python") if meta is not None else {})
    gateway = data.get("gateway") if isinstance(data, dict) else None
    value = gateway.get("idempotency_key") if isinstance(gateway, dict) else None
    if not isinstance(value, str) or not value or len(value) > 240:
        raise ToolError("GATEWAY_IDEMPOTENCY_REQUIRED")
    return value


def build_mcp(settings: ObsidianProviderSettings | None = None, *, store: ObsidianVaultStore | None = None) -> MCPServer:
    resolved = settings or ObsidianProviderSettings()
    resolved.validate_runtime()
    active = store or ObsidianVaultStore(resolved)
    bearer = resolved.resolved_internal_bearer_token()
    mcp = MCPServer(
        name="obsidian-research-knowledge-provider",
        instructions="Provider-neutral research note facade backed by a confined Obsidian vault.",
        auth=AuthSettings(
            issuer_url=resolved.auth_issuer_url,
            resource_server_url=resolved.auth_resource_url,
            required_scopes=["research:access"],
        ),
        token_verifier=_StaticBearerVerifier(bearer),
    )

    @mcp.custom_route("/ready", methods=["GET"], include_in_schema=False)
    async def provider_ready(request: Request) -> JSONResponse:
        authorization = request.headers.get("authorization", "")
        scheme, separator, presented_token = authorization.partition(" ")
        if (
            scheme.casefold() != "bearer"
            or not separator
            or not presented_token
            or not secrets.compare_digest(presented_token, bearer)
        ):
            return JSONResponse(
                {"error": {"code": "UNAUTHORIZED"}},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        ready = (
            active.root.is_dir()
            and active.default_directory.is_dir()
            and os.access(active.root, os.R_OK)
            and os.access(active.default_directory, os.R_OK)
        )
        if resolved.access_mode == "read_write":
            ready = (
                ready
                and os.access(active.root, os.W_OK)
                and os.access(active.default_directory, os.W_OK)
            )
        return JSONResponse(
            {"status": "ready" if ready else "not_ready"},
            status_code=200 if ready else 503,
        )

    def require_write(ctx: Context) -> str:
        if resolved.access_mode != "read_write":
            raise ToolError("OBSIDIAN_PROVIDER_READ_ONLY")
        return _gateway_idempotency_key(ctx)

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    async def research_v1_provider_capabilities() -> ObsidianCapabilities:
        operations = ["capabilities", "read", "metadata", "search"]
        if resolved.access_mode == "read_write":
            operations.extend(["create", "update_content", "append", "update_tags", "link", "source_reference", "update_title"])
        return ObsidianCapabilities(workspace_id=active.workspace_id, access_mode=resolved.access_mode, operations=operations)

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    async def research_v1_note_read(note_id: str) -> ObsidianNote:
        try:
            return active.read(note_id)
        except (OSError, ValueError) as error:
            raise ToolError(str(error)) from error

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    async def research_v1_note_metadata(note_id: str) -> ObsidianNoteMetadata:
        note = await research_v1_note_read(note_id)
        return ObsidianNoteMetadata(
            workspace_id=note.workspace_id,
            note_id=note.note_id,
            title=note.title,
            tags=note.tags,
            tags_hash=note.tags_hash,
            canonical_url=note.canonical_url,
        )

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    async def research_v1_note_search(
        query: str, mode: Literal["keyword"] = "keyword"
    ) -> ObsidianSearchReply:
        matches = [
            ObsidianSearchMatch(
                note_id=note.note_id,
                title=note.title,
                canonical_url=note.canonical_url,
            )
            for note in active.search(query)
        ]
        return ObsidianSearchReply(
            workspace_id=active.workspace_id,
            mode=mode,
            matches=matches,
        )

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_note_create(
        title: str, content: str, ctx: Context
    ) -> ObsidianMutation:
        idempotency_key = require_write(ctx)
        try:
            note, replayed = active.create(title, content, idempotency_key)
        except ObsidianConflictError as error:
            raise ToolError(
                json.dumps(
                    {
                        "error": {
                            "code": error.code,
                            "expected": error.expected,
                            "current": error.current,
                        }
                    },
                    sort_keys=True,
                )
            ) from error
        return ObsidianMutation(
            workspace_id=active.workspace_id,
            note_id=note.note_id,
            canonical_url=note.canonical_url,
            content_hash=note.content_hash,
            replayed=replayed,
        )

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_note_update_content(
        note_id: str,
        content: str,
        expected_content_hash: str,
        ctx: Context,
    ) -> ObsidianMutation:
        require_write(ctx)
        try:
            note, replayed = active.update_content(
                note_id, content, expected_content_hash
            )
        except ObsidianConflictError as error:
            raise ToolError(
                json.dumps(
                    {
                        "error": {
                            "code": error.code,
                            "expected": error.expected,
                            "current": error.current,
                        }
                    },
                    sort_keys=True,
                )
            ) from error
        return ObsidianMutation(
            workspace_id=active.workspace_id,
            note_id=note.note_id,
            canonical_url=note.canonical_url,
            content_hash=note.content_hash,
            replayed=replayed,
        )

    async def append_note(
        note_id: str,
        content: str,
        expected_content_hash: str,
        ctx: Context,
    ) -> ObsidianMutation:
        idempotency_key = require_write(ctx)
        try:
            note, replayed = active.append(
                note_id,
                content,
                expected_content_hash,
                idempotency_key,
            )
        except ObsidianConflictError as error:
            raise ToolError(
                json.dumps(
                    {
                        "error": {
                            "code": error.code,
                            "expected": error.expected,
                            "current": error.current,
                        }
                    },
                    sort_keys=True,
                )
            ) from error
        return ObsidianMutation(
            workspace_id=active.workspace_id,
            note_id=note.note_id,
            canonical_url=note.canonical_url,
            content_hash=note.content_hash,
            replayed=replayed,
        )

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_note_append(note_id: str, content: str, expected_content_hash: str, ctx: Context) -> ObsidianMutation:
        return await append_note(note_id, content, expected_content_hash, ctx)

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_note_set_tags(
        note_id: str,
        tags: list[str],
        expected_tags_hash: str,
        ctx: Context,
    ) -> ObsidianMutation:
        require_write(ctx)
        try:
            note, replayed = active.set_tags(note_id, tags, expected_tags_hash)
        except ObsidianConflictError as error:
            raise ToolError(
                json.dumps(
                    {
                        "error": {
                            "code": error.code,
                            "expected": error.expected,
                            "current": error.current,
                        }
                    },
                    sort_keys=True,
                )
            ) from error
        return ObsidianMutation(
            workspace_id=active.workspace_id,
            note_id=note.note_id,
            canonical_url=note.canonical_url,
            tags=note.tags,
            tags_hash=note.tags_hash,
            replayed=replayed,
        )

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_note_link(note_id: str, target_note_id: str, expected_content_hash: str, ctx: Context, label: str | None = None) -> ObsidianMutation:
        target = active.read(target_note_id)
        rendered = render_note_link(ResearchLink(target_note_id=target_note_id, target_url=target.canonical_url, label=label or target.title))
        return await append_note(note_id, rendered, expected_content_hash, ctx)

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_note_add_source(note_id: str, url: str, title: str, expected_content_hash: str, ctx: Context, locator: str | None = None) -> ObsidianMutation:
        try:
            rendered = render_source_reference(ResearchSourceReference(url=url, title=title, locator=locator))
        except ValueError as error:
            raise ToolError(str(error)) from error
        return await append_note(note_id, rendered, expected_content_hash, ctx)

    @mcp.tool(annotations=WRITE, structured_output=True)
    async def research_v1_note_update_title(
        note_id: str,
        title: str,
        expected_title: str | None,
        ctx: Context,
    ) -> ObsidianMutation:
        require_write(ctx)
        try:
            note, replayed = active.update_title(note_id, title, expected_title)
        except ObsidianConflictError as error:
            raise ToolError(
                json.dumps(
                    {
                        "error": {
                            "code": error.code,
                            "expected": error.expected,
                            "current": error.current,
                        }
                    },
                    sort_keys=True,
                )
            ) from error
        return ObsidianMutation(
            workspace_id=active.workspace_id,
            note_id=note.note_id,
            canonical_url=note.canonical_url,
            content_hash=note.content_hash,
            replayed=replayed,
        )

    return mcp


def main() -> None:
    settings = ObsidianProviderSettings()
    mcp = build_mcp(settings)
    mcp.run(
        transport="streamable-http",
        host=settings.host,
        port=settings.port,
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
    )


if __name__ == "__main__":
    main()
