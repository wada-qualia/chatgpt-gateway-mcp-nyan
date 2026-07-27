from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from .events import emit_event
from .models import (
    McpCatalogEmbedding,
    McpCatalogIndexGeneration,
    McpServer,
    McpTool,
    McpToolRevision,
    utcnow,
)

_TOKEN_PATTERN = re.compile(r"\w+", re.UNICODE)


class CatalogEmbeddingProvider(Protocol):
    model_key: str
    model_version: str
    dimensions: int

    def embed_texts(self, texts: list[str]) -> list[list[float]]: ...


class TokenHashEmbeddingProvider:
    model_key = "gateway-token-hash"
    model_version = "1"
    dimensions = 128

    def _features(self, text: str) -> list[str]:
        normalized = " ".join(text.casefold().split())
        tokens = _TOKEN_PATTERN.findall(normalized)
        features = [f"t:{token}" for token in tokens]
        for token in tokens:
            padded = f"  {token}  "
            features.extend(
                f"g:{padded[index:index + 3]}"
                for index in range(max(0, len(padded) - 2))
            )
        return features

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            vector = [0.0] * self.dimensions
            for feature in self._features(text):
                digest = hashlib.sha256(feature.encode("utf-8")).digest()
                index = int.from_bytes(digest[:4], "big") % self.dimensions
                vector[index] += 1.0 if digest[4] & 1 else -1.0
            vectors.append(_normalize_vector(vector))
        return vectors


_PROVIDERS: dict[tuple[str, str], CatalogEmbeddingProvider] = {}


def register_embedding_provider(provider: CatalogEmbeddingProvider) -> None:
    if provider.dimensions < 1 or provider.dimensions > 4096:
        raise ValueError("Embedding dimensions must be between 1 and 4096")
    _PROVIDERS[(provider.model_key, provider.model_version)] = provider


def unregister_embedding_provider(model_key: str, model_version: str) -> None:
    _PROVIDERS.pop((model_key, model_version), None)


def get_embedding_provider(
    model_key: str, model_version: str
) -> CatalogEmbeddingProvider | None:
    return _PROVIDERS.get((model_key, model_version))


def _normalize_vector(vector: list[float]) -> list[float]:
    if not vector or any(not math.isfinite(value) for value in vector):
        raise ValueError("Embedding vector must contain finite values")
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0:
        return [0.0] * len(vector)
    return [value / norm for value in vector]


def _cosine(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        return 0.0
    return max(-1.0, min(1.0, sum(a * b for a, b in zip(left, right, strict=True))))


def _document_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _catalog_hash(
    rows: list[tuple[McpToolRevision, McpTool, McpServer]],
    *,
    server_id: str | None,
) -> str:
    payload: dict[str, object] = {
        "scope_server_id": server_id,
        "documents": [
        {
            "revision_id": revision.id,
            "schema_hash": revision.schema_hash,
            "document_sha256": _document_hash(revision.search_text or ""),
            "catalog_generation": revision.catalog_generation,
        }
        for revision, _, _ in rows
        ],
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _generation(
    db: Session, *, owner_subject: str, generation_id: str
) -> McpCatalogIndexGeneration:
    generation = (
        db.query(McpCatalogIndexGeneration)
        .filter(
            McpCatalogIndexGeneration.id == generation_id,
            McpCatalogIndexGeneration.owner_subject == owner_subject,
        )
        .one_or_none()
    )
    if generation is None:
        raise HTTPException(status_code=404, detail="MCP catalog index generation not found")
    return generation


def _acquire_transaction_lock(db: Session, lock_key: str) -> None:
    if db.bind is None or db.bind.dialect.name != "postgresql":
        return
    db.execute(
        func.pg_advisory_xact_lock(func.hashtextextended(lock_key, 0)).select()
    )


def _acquire_build_lock(
    db: Session,
    *,
    owner_subject: str,
    server_id: str | None,
    model_key: str,
    model_version: str,
) -> None:
    _acquire_transaction_lock(
        db,
        "\x1f".join(
            ("mcp-catalog-build", owner_subject, server_id or "*", model_key, model_version)
        ),
    )


def _acquire_activation_lock(db: Session, *, owner_subject: str) -> None:
    _acquire_transaction_lock(
        db,
        "\x1f".join(("mcp-catalog-activate", owner_subject)),
    )


def build_index_generation(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    model_key: str,
    model_version: str,
    server_id: str | None = None,
) -> McpCatalogIndexGeneration:
    provider = get_embedding_provider(model_key, model_version)
    if provider is None:
        raise HTTPException(status_code=409, detail="Embedding provider is unavailable")
    _acquire_build_lock(
        db,
        owner_subject=owner_subject,
        server_id=server_id,
        model_key=model_key,
        model_version=model_version,
    )
    query = (
        db.query(McpToolRevision, McpTool, McpServer)
        .join(McpTool, McpTool.id == McpToolRevision.tool_id)
        .join(McpServer, McpServer.id == McpToolRevision.server_id)
        .filter(
            McpToolRevision.owner_subject == owner_subject,
            McpTool.owner_subject == owner_subject,
            McpServer.owner_subject == owner_subject,
            McpTool.lifecycle_state == "active",
            McpTool.current_revision_id == McpToolRevision.id,
        )
    )
    if server_id:
        query = query.filter(McpServer.id == server_id)
    rows = query.order_by(McpToolRevision.id.asc()).all()
    source_hash = _catalog_hash(rows, server_id=server_id)
    existing = (
        db.query(McpCatalogIndexGeneration)
        .filter(
            McpCatalogIndexGeneration.owner_subject == owner_subject,
            McpCatalogIndexGeneration.scope_server_id == server_id,
            McpCatalogIndexGeneration.model_key == model_key,
            McpCatalogIndexGeneration.model_version == model_version,
            McpCatalogIndexGeneration.source_catalog_sha256 == source_hash,
            McpCatalogIndexGeneration.status.in_(["ready", "active"]),
        )
        .order_by(McpCatalogIndexGeneration.generation.desc())
        .first()
    )
    if existing is not None:
        return existing
    next_generation = (
        db.query(func.max(McpCatalogIndexGeneration.generation))
        .filter(
            McpCatalogIndexGeneration.owner_subject == owner_subject,
            McpCatalogIndexGeneration.scope_server_id == server_id,
            McpCatalogIndexGeneration.model_key == model_key,
            McpCatalogIndexGeneration.model_version == model_version,
        )
        .scalar()
        or 0
    ) + 1
    generation = McpCatalogIndexGeneration(
        id=str(uuid.uuid4()),
        owner_subject=owner_subject,
        scope_server_id=server_id,
        model_key=model_key,
        model_version=model_version,
        dimensions=provider.dimensions,
        generation=next_generation,
        status="building",
        source_catalog_sha256=source_hash,
        document_count=0,
        created_by_subject=actor_subject,
        version=1,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(generation)
    db.flush()
    try:
        texts = [revision.search_text or "" for revision, _, _ in rows]
        vectors = provider.embed_texts(texts)
        if len(vectors) != len(rows):
            raise HTTPException(
                status_code=409, detail="Embedding provider returned wrong count"
            )
        for (revision, _, _), vector in zip(rows, vectors, strict=True):
            normalized = _normalize_vector([float(value) for value in vector])
            if len(normalized) != provider.dimensions:
                raise HTTPException(
                    status_code=409,
                    detail="Embedding provider returned wrong dimensions",
                )
            db.add(
                McpCatalogEmbedding(
                    id=str(uuid.uuid4()),
                    owner_subject=owner_subject,
                    generation_id=generation.id,
                    revision_id=revision.id,
                    schema_hash=revision.schema_hash,
                    document_sha256=_document_hash(revision.search_text or ""),
                    dimensions=provider.dimensions,
                    vector=normalized,
                    created_at=utcnow(),
                )
            )
    except Exception:
        db.rollback()
        raise
    generation.status = "ready"
    generation.document_count = len(rows)
    generation.updated_at = utcnow()
    emit_event(
        db,
        event_type="gateway.mcp.catalog.index_built.v1",
        actor_subject=actor_subject,
        action="build",
        resource_type="mcp_catalog_index_generation",
        resource_id=generation.id,
        payload={
            "scope_server_id": server_id,
            "model_key": model_key,
            "model_version": model_version,
            "generation": next_generation,
            "document_count": len(rows),
            "source_catalog_sha256": source_hash,
        },
        owner_subject=owner_subject,
        commit=False,
    )
    db.commit()
    db.refresh(generation)
    return generation


class _QueryEmbeddingCache:
    def __init__(
        self,
        max_entries: int = 256,
        ttl_seconds: int = 60,
        max_tenants: int = 256,
    ) -> None:
        self.max_entries = max_entries
        self.max_tenants = max_tenants
        self.ttl = timedelta(seconds=ttl_seconds)
        self._entries: OrderedDict[
            str,
            OrderedDict[tuple[str, str], tuple[datetime, list[float]]],
        ] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: tuple[str, str, str]) -> list[float] | None:
        owner_subject, generation_id, query_sha = key
        now = datetime.now(timezone.utc)
        with self._lock:
            partition = self._entries.get(owner_subject)
            if partition is None:
                return None
            partition_key = (generation_id, query_sha)
            item = partition.get(partition_key)
            if item is None:
                return None
            created_at, vector = item
            if now - created_at > self.ttl:
                partition.pop(partition_key, None)
                if not partition:
                    self._entries.pop(owner_subject, None)
                return None
            partition.move_to_end(partition_key)
            self._entries.move_to_end(owner_subject)
            return list(vector)

    def put(self, key: tuple[str, str, str], vector: list[float]) -> None:
        owner_subject, generation_id, query_sha = key
        with self._lock:
            partition = self._entries.setdefault(owner_subject, OrderedDict())
            partition_key = (generation_id, query_sha)
            partition[partition_key] = (
                datetime.now(timezone.utc),
                list(vector),
            )
            partition.move_to_end(partition_key)
            self._entries.move_to_end(owner_subject)
            while len(partition) > self.max_entries:
                partition.popitem(last=False)
            while len(self._entries) > self.max_tenants:
                self._entries.popitem(last=False)

    def clear(self, owner_subject: str | None = None) -> None:
        with self._lock:
            if owner_subject is None:
                self._entries.clear()
                return
            self._entries.pop(owner_subject, None)


_QUERY_CACHE = _QueryEmbeddingCache()


def activate_index_generation(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    generation_id: str,
    expected_version: int,
    action: str = "activate",
) -> McpCatalogIndexGeneration:
    _acquire_activation_lock(db, owner_subject=owner_subject)
    target = _generation(db, owner_subject=owner_subject, generation_id=generation_id)
    if target.version != expected_version:
        raise HTTPException(status_code=409, detail="Optimistic version conflict")
    if target.status not in {"ready", "retired", "active"}:
        raise HTTPException(status_code=409, detail="Index generation is not activatable")
    current = (
        db.query(McpCatalogIndexGeneration)
        .filter(
            McpCatalogIndexGeneration.owner_subject == owner_subject,
            McpCatalogIndexGeneration.status == "active",
        )
        .one_or_none()
    )
    if current is not None and current.id == target.id:
        return target
    if current is not None:
        current.status = "retired"
        current.retired_at = utcnow()
        current.updated_at = utcnow()
        current.version += 1
        db.flush()
        target.supersedes_generation_id = current.id
    target.status = "active"
    target.activated_at = utcnow()
    target.retired_at = None
    target.updated_at = utcnow()
    target.version += 1
    emit_event(
        db,
        event_type="gateway.mcp.catalog.index_activated.v1",
        actor_subject=actor_subject,
        action=action,
        resource_type="mcp_catalog_index_generation",
        resource_id=target.id,
        payload={
            "scope_server_id": target.scope_server_id,
            "model_key": target.model_key,
            "model_version": target.model_version,
            "generation": target.generation,
            "supersedes_generation_id": target.supersedes_generation_id,
            "transition": action,
        },
        owner_subject=owner_subject,
        commit=False,
    )
    db.commit()
    _QUERY_CACHE.clear(owner_subject)
    db.refresh(target)
    return target


def rollback_index_generation(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    generation_id: str,
    expected_version: int,
) -> McpCatalogIndexGeneration:
    return activate_index_generation(
        db,
        owner_subject=owner_subject,
        actor_subject=actor_subject,
        generation_id=generation_id,
        expected_version=expected_version,
        action="rollback",
    )


def list_index_generations(
    db: Session, *, owner_subject: str
) -> list[McpCatalogIndexGeneration]:
    return (
        db.query(McpCatalogIndexGeneration)
        .filter(McpCatalogIndexGeneration.owner_subject == owner_subject)
        .order_by(
            McpCatalogIndexGeneration.created_at.desc(),
            McpCatalogIndexGeneration.id.desc(),
        )
        .all()
    )


def get_index_generation(
    db: Session, *, owner_subject: str, generation_id: str
) -> McpCatalogIndexGeneration:
    return _generation(db, owner_subject=owner_subject, generation_id=generation_id)


def active_index_generation(
    db: Session, *, owner_subject: str
) -> McpCatalogIndexGeneration | None:
    return (
        db.query(McpCatalogIndexGeneration)
        .filter(
            McpCatalogIndexGeneration.owner_subject == owner_subject,
            McpCatalogIndexGeneration.status == "active",
        )
        .one_or_none()
    )


def semantic_scores(
    db: Session,
    *,
    owner_subject: str,
    query: str,
    server_id: str | None,
    revision_bindings: dict[str, str],
) -> tuple[dict[str, float], dict[str, object]]:
    generation = active_index_generation(db, owner_subject=owner_subject)
    if generation is None:
        return {}, {"available": False, "reason": "no_active_index"}
    if (
        generation.scope_server_id is not None
        and generation.scope_server_id != server_id
    ):
        return {}, {
            "available": False,
            "reason": "index_scope_mismatch",
            "generation_id": generation.id,
            "scope_server_id": generation.scope_server_id,
        }
    provider = get_embedding_provider(generation.model_key, generation.model_version)
    if provider is None:
        return {}, {
            "available": False,
            "reason": "provider_unavailable",
            "generation_id": generation.id,
            "model_key": generation.model_key,
            "model_version": generation.model_version,
        }
    query_sha = hashlib.sha256(query.encode("utf-8")).hexdigest()
    cache_key = (owner_subject, generation.id, query_sha)
    query_vector = _QUERY_CACHE.get(cache_key)
    if query_vector is None:
        try:
            generated = provider.embed_texts([query])
            if len(generated) != 1:
                return {}, {"available": False, "reason": "provider_error"}
            query_vector = _normalize_vector(
                [float(value) for value in generated[0]]
            )
        except Exception:
            return {}, {
                "available": False,
                "reason": "provider_error",
                "generation_id": generation.id,
                "model_key": generation.model_key,
                "model_version": generation.model_version,
            }
        if len(query_vector) != generation.dimensions:
            return {}, {"available": False, "reason": "dimension_mismatch"}
        _QUERY_CACHE.put(cache_key, query_vector)
    revision_ids = sorted(revision_bindings)
    if not revision_ids:
        rows: list[McpCatalogEmbedding] = []
    else:
        rows = (
            db.query(McpCatalogEmbedding)
            .filter(
                McpCatalogEmbedding.owner_subject == owner_subject,
                McpCatalogEmbedding.generation_id == generation.id,
                McpCatalogEmbedding.revision_id.in_(revision_ids),
            )
            .all()
        )
    scores: dict[str, float] = {}
    for row in rows:
        if (
            row.dimensions != generation.dimensions
            or revision_bindings.get(row.revision_id) != row.schema_hash
        ):
            continue
        try:
            score = _cosine(
                query_vector,
                [float(value) for value in row.vector],
            )
        except (TypeError, ValueError):
            continue
        if score > 0:
            scores[row.revision_id] = score
    return scores, {
        "available": True,
        "generation_id": generation.id,
        "generation": generation.generation,
        "model_key": generation.model_key,
        "model_version": generation.model_version,
        "dimensions": generation.dimensions,
        "indexed_documents": generation.document_count,
        "matched_documents": len(scores),
    }


@dataclass(frozen=True, slots=True)
class CatalogRankCandidate:
    revision_id: str
    normalized_name: str
    title: str
    server_name: str
    lexical_score: float
    semantic_score: float | None


def lexical_fallback_score(query: str, document: str) -> float:
    normalized_query = " ".join(query.casefold().split())
    normalized_document = " ".join(document.casefold().split())
    tokens = _TOKEN_PATTERN.findall(normalized_query)
    if not tokens:
        return 0.0
    matched = sum(1 for token in tokens if token in normalized_document)
    if matched == 0:
        return 0.0
    coverage = matched / len(tokens)
    phrase = 1.0 if normalized_query in normalized_document else 0.0
    return coverage + phrase


def rank_candidates(
    candidates: list[CatalogRankCandidate], *, query: str, limit: int
) -> list[dict[str, float | str | None]]:
    lexical_order = sorted(
        (candidate for candidate in candidates if candidate.lexical_score > 0),
        key=lambda candidate: (
            -candidate.lexical_score,
            candidate.normalized_name,
            candidate.revision_id,
        ),
    )
    semantic_order = sorted(
        (
            candidate
            for candidate in candidates
            if candidate.semantic_score is not None and candidate.semantic_score > 0
        ),
        key=lambda candidate: (
            -float(candidate.semantic_score or 0.0),
            candidate.normalized_name,
            candidate.revision_id,
        ),
    )
    lexical_ranks = {
        candidate.revision_id: rank for rank, candidate in enumerate(lexical_order, 1)
    }
    semantic_ranks = {
        candidate.revision_id: rank for rank, candidate in enumerate(semantic_order, 1)
    }
    normalized_query = " ".join(query.casefold().split())
    ranked: list[dict[str, float | str | None]] = []
    for candidate in candidates:
        lexical_rank = lexical_ranks.get(candidate.revision_id)
        semantic_rank = semantic_ranks.get(candidate.revision_id)
        if lexical_rank is None and semantic_rank is None:
            continue
        score = 0.0
        if lexical_rank is not None:
            score += 0.65 / (60 + lexical_rank)
        if semantic_rank is not None:
            score += 0.35 / (60 + semantic_rank)
        if normalized_query == candidate.normalized_name.casefold():
            score += 0.05
        elif normalized_query in candidate.normalized_name.casefold():
            score += 0.02
        elif normalized_query and normalized_query in candidate.title.casefold():
            score += 0.01
        ranked.append(
            {
                "revision_id": candidate.revision_id,
                "score": score,
                "lexical_score": candidate.lexical_score,
                "semantic_score": candidate.semantic_score,
            }
        )
    ranked.sort(key=lambda item: (-float(item["score"]), str(item["revision_id"])))
    return ranked[:limit]


register_embedding_provider(TokenHashEmbeddingProvider())
