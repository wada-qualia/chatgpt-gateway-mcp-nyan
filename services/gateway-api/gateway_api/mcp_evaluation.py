from __future__ import annotations

import json
import math
import time
from collections import OrderedDict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from statistics import mean
from typing import Any

from .mcp_catalog_retrieval import (
    CatalogRankCandidate,
    TokenHashEmbeddingProvider,
    lexical_fallback_score,
    rank_candidates,
)

_PROFILE_IDS = ("catalog_broker", "deferred_native", "native_projected")
_BROKER_TOOLS = (
    "mcp_catalog_search",
    "mcp_tool_describe",
    "mcp_call_read",
    "mcp_action_prepare",
    "mcp_action_execute",
)


@dataclass(frozen=True, slots=True)
class EvaluationTool:
    tool_id: str
    revision_id: str
    current: bool
    schema_hash: str
    name: str
    title: str
    description: str
    server_id: str
    server_name: str
    authorized_tenants: frozenset[str]
    exposure_mode: str
    deferred_allowed: bool
    projected: bool
    action_class: str
    requires_approval: bool
    input_schema: dict[str, Any]

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> EvaluationTool:
        return cls(
            tool_id=str(payload["tool_id"]),
            revision_id=str(payload["revision_id"]),
            current=bool(payload["current"]),
            schema_hash=str(payload["schema_hash"]),
            name=str(payload["name"]),
            title=str(payload["title"]),
            description=str(payload["description"]),
            server_id=str(payload["server_id"]),
            server_name=str(payload["server_name"]),
            authorized_tenants=frozenset(
                str(value) for value in payload["authorized_tenants"]
            ),
            exposure_mode=str(payload["exposure_mode"]),
            deferred_allowed=bool(payload["deferred_allowed"]),
            projected=bool(payload["projected"]),
            action_class=str(payload["action_class"]),
            requires_approval=bool(payload["requires_approval"]),
            input_schema=dict(payload["input_schema"]),
        )

    def document(self) -> str:
        return f"{self.name} {self.title} {self.description} {self.server_name}"

    def summary(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "revision_id": self.revision_id,
            "schema_hash": self.schema_hash,
            "name": self.name,
            "title": self.title,
            "server_name": self.server_name,
            "action_class": self.action_class,
            "requires_approval": self.requires_approval,
        }

    def definition(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "revision_id": self.revision_id,
            "schema_hash": self.schema_hash,
        }


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    case_id: str
    language: str
    category: str
    tenant: str
    query: str
    relevant_tool_ids: frozenset[str]
    expected_tool_id: str | None
    expected_revision_id: str | None
    eligible_profiles: frozenset[str]
    behavior: str
    attempt_direct_execution: bool

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> EvaluationCase:
        return cls(
            case_id=str(payload["case_id"]),
            language=str(payload["language"]),
            category=str(payload["category"]),
            tenant=str(payload["tenant"]),
            query=str(payload["query"]),
            relevant_tool_ids=frozenset(
                str(value) for value in payload["relevant_tool_ids"]
            ),
            expected_tool_id=(
                str(payload["expected_tool_id"])
                if payload.get("expected_tool_id") is not None
                else None
            ),
            expected_revision_id=(
                str(payload["expected_revision_id"])
                if payload.get("expected_revision_id") is not None
                else None
            ),
            eligible_profiles=frozenset(
                str(value) for value in payload["eligible_profiles"]
            ),
            behavior=str(payload["behavior"]),
            attempt_direct_execution=bool(payload["attempt_direct_execution"]),
        )


class PartitionedEvaluationCache:
    def __init__(self, *, entries_per_partition: int, partition_limit: int) -> None:
        if entries_per_partition < 1 or partition_limit < 1:
            raise ValueError("Evaluation cache limits must be positive")
        self.entries_per_partition = entries_per_partition
        self.partition_limit = partition_limit
        self.partitions: OrderedDict[str, OrderedDict[str, tuple[str, ...]]] = (
            OrderedDict()
        )

    def get(self, partition: str, key: str) -> tuple[str, ...] | None:
        values = self.partitions.get(partition)
        if values is None or key not in values:
            return None
        value = values.pop(key)
        values[key] = value
        self.partitions.move_to_end(partition)
        return value

    def put(self, partition: str, key: str, value: tuple[str, ...]) -> None:
        values = self.partitions.get(partition)
        if values is None:
            values = OrderedDict()
            self.partitions[partition] = values
        if key in values:
            values.pop(key)
        values[key] = value
        while len(values) > self.entries_per_partition:
            values.popitem(last=False)
        self.partitions.move_to_end(partition)
        while len(self.partitions) > self.partition_limit:
            self.partitions.popitem(last=False)

    def contains(self, partition: str, key: str) -> bool:
        values = self.partitions.get(partition)
        return bool(values is not None and key in values)


@dataclass(frozen=True, slots=True)
class SelectionResult:
    tools: tuple[EvaluationTool, ...]
    cache_hit: bool
    latency_ms: float
    filtered_unauthorized: int
    filtered_stale: int
    filtered_profile: int


def load_evaluation_contract(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    payload = json.loads(source.read_text(encoding="utf-8"))
    validate_evaluation_contract(payload)
    return payload


def validate_evaluation_contract(contract: dict[str, Any]) -> None:
    if contract.get("schema_version") != 1:
        raise ValueError("Unsupported evaluation schema version")
    if contract.get("task_id") != "CMG-FED-880":
        raise ValueError("Evaluation contract task id must be CMG-FED-880")
    if contract.get("release_version") != "0.8.0":
        raise ValueError("Evaluation contract release version must be 0.8.0")
    profiles = tuple(contract.get("profiles", ()))
    if profiles != _PROFILE_IDS:
        raise ValueError("Evaluation profiles must use the canonical order")
    tools = [EvaluationTool.from_payload(item) for item in contract.get("tools", ())]
    cases = [EvaluationCase.from_payload(item) for item in contract.get("cases", ())]
    if len(tools) < 8 or len(cases) < 12:
        raise ValueError("Evaluation suite is too small")
    revision_ids = [tool.revision_id for tool in tools]
    if len(set(revision_ids)) != len(revision_ids):
        raise ValueError("Evaluation revision ids must be unique")
    case_ids = [case.case_id for case in cases]
    if len(set(case_ids)) != len(case_ids):
        raise ValueError("Evaluation case ids must be unique")
    tool_ids = {tool.tool_id for tool in tools}
    for case in cases:
        if not case.eligible_profiles or not case.eligible_profiles.issubset(
            _PROFILE_IDS
        ):
            raise ValueError(f"Invalid eligible profiles for {case.case_id}")
        if not case.relevant_tool_ids.issubset(tool_ids):
            raise ValueError(f"Unknown relevant tool in {case.case_id}")
        if case.behavior not in {"select", "abstain"}:
            raise ValueError(f"Invalid behavior for {case.case_id}")
        if case.behavior == "select" and (
            not case.expected_tool_id or not case.expected_revision_id
        ):
            raise ValueError(f"Selection case {case.case_id} lacks an expected binding")
        if case.behavior == "abstain" and (
            case.expected_tool_id is not None or case.expected_revision_id is not None
        ):
            raise ValueError(
                f"Abstention case {case.case_id} contains an expected binding"
            )
    languages = {case.language for case in cases}
    categories = {case.category for case in cases}
    if len(languages) < 4:
        raise ValueError("Evaluation suite must cover at least four languages")
    if not {"adversarial", "cross_tenant", "multilingual"}.issubset(categories):
        raise ValueError("Evaluation suite lacks required fixture categories")
    if not any(not tool.current for tool in tools):
        raise ValueError("Evaluation suite lacks a stale revision fixture")
    if not any(tool.requires_approval for tool in tools):
        raise ValueError("Evaluation suite lacks approval-required tools")
    thresholds = contract.get("thresholds", {})
    if set(thresholds.get("profiles", {})) != set(_PROFILE_IDS):
        raise ValueError("Thresholds must cover all presentation profiles")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return sha256(_canonical_bytes(value)).hexdigest()


def _cosine(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right, strict=True))


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return ordered[index]


def _ratio(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return float(numerator) / float(denominator)


def _mean(values: list[float]) -> float:
    return float(mean(values)) if values else 0.0


def _round(value: float) -> float:
    return round(float(value), 9)


def _profile_allows(tool: EvaluationTool, profile: str) -> bool:
    if tool.exposure_mode not in {"catalog_only", "native_projected"}:
        return False
    if profile == "catalog_broker":
        return True
    if profile == "deferred_native":
        return tool.deferred_allowed
    if profile == "native_projected":
        return tool.projected and tool.exposure_mode == "native_projected"
    raise ValueError(f"Unsupported profile {profile}")


def _filter_tools(
    tools: list[EvaluationTool], *, case: EvaluationCase, profile: str
) -> tuple[list[EvaluationTool], dict[str, int]]:
    selected: list[EvaluationTool] = []
    counts = {"unauthorized": 0, "stale": 0, "profile": 0}
    for tool in tools:
        if case.tenant not in tool.authorized_tenants:
            counts["unauthorized"] += 1
            continue
        if not tool.current:
            counts["stale"] += 1
            continue
        if not _profile_allows(tool, profile):
            counts["profile"] += 1
            continue
        selected.append(tool)
    return selected, counts


def _rank_tools(
    tools: list[EvaluationTool],
    *,
    query: str,
    limit: int,
    semantic_min_similarity: float,
) -> tuple[EvaluationTool, ...]:
    if not tools:
        return ()
    provider = TokenHashEmbeddingProvider()
    documents = [tool.document() for tool in tools]
    vectors = provider.embed_texts([query, *documents])
    query_vector = vectors[0]
    candidates: list[CatalogRankCandidate] = []
    for tool, vector in zip(tools, vectors[1:], strict=True):
        lexical = lexical_fallback_score(query, tool.document())
        semantic = _cosine(query_vector, vector)
        if lexical <= 0 and semantic < semantic_min_similarity:
            semantic = 0.0
        candidates.append(
            CatalogRankCandidate(
                revision_id=tool.revision_id,
                normalized_name=tool.name,
                title=tool.title,
                server_name=tool.server_name,
                lexical_score=lexical,
                semantic_score=semantic,
            )
        )
    ranked = rank_candidates(candidates, query=query, limit=limit)
    by_revision = {tool.revision_id: tool for tool in tools}
    return tuple(by_revision[str(item["revision_id"])] for item in ranked)


def _select(
    tools: list[EvaluationTool],
    *,
    case: EvaluationCase,
    profile: str,
    limit: int,
    semantic_min_similarity: float,
    cache: PartitionedEvaluationCache,
) -> SelectionResult:
    started = time.perf_counter_ns()
    candidates, filtered = _filter_tools(tools, case=case, profile=profile)
    by_revision = {tool.revision_id: tool for tool in candidates}
    partition = f"{case.tenant}:{profile}"
    key = _digest({"case_id": case.case_id, "query": case.query})
    cached = cache.get(partition, key)
    if cached is None:
        ranked = _rank_tools(
            candidates,
            query=case.query,
            limit=limit,
            semantic_min_similarity=semantic_min_similarity,
        )
        cache.put(partition, key, tuple(tool.revision_id for tool in ranked))
        cache_hit = False
    else:
        ranked = tuple(
            by_revision[revision_id]
            for revision_id in cached
            if revision_id in by_revision
        )
        cache_hit = True
    latency_ms = (time.perf_counter_ns() - started) / 1_000_000
    return SelectionResult(
        tools=ranked,
        cache_hit=cache_hit,
        latency_ms=latency_ms,
        filtered_unauthorized=filtered["unauthorized"],
        filtered_stale=filtered["stale"],
        filtered_profile=filtered["profile"],
    )


def _context_payload(
    *,
    profile: str,
    candidates: list[EvaluationTool],
    ranked: tuple[EvaluationTool, ...],
) -> dict[str, Any]:
    selected = ranked[0] if ranked else None
    if profile == "catalog_broker":
        return {
            "profile": profile,
            "tools": [
                {
                    "name": name,
                    "description": f"Gateway-owned stable broker tool {name}",
                }
                for name in _BROKER_TOOLS
            ],
            "search_results": [tool.summary() for tool in ranked],
        }
    if profile == "deferred_native":
        namespaces: dict[str, dict[str, str]] = {}
        for tool in candidates:
            namespaces[tool.server_id] = {
                "name": tool.server_name,
                "description": f"Policy-filtered namespace for {tool.server_name}",
            }
        return {
            "profile": profile,
            "namespaces": [namespaces[key] for key in sorted(namespaces)],
            "loaded_tool": selected.definition() if selected is not None else None,
        }
    return {
        "profile": profile,
        "projected_tools": [tool.definition() for tool in candidates],
    }


def _context_tokens(payload: dict[str, Any]) -> int:
    return math.ceil(len(_canonical_bytes(payload)) / 4)


def _case_outcome(
    *,
    case: EvaluationCase,
    profile: str,
    result: SelectionResult,
    candidates: list[EvaluationTool],
    cost_rate: float,
) -> dict[str, Any]:
    selected = result.tools[0] if result.tools else None
    relevant_returned = sum(
        1 for tool in result.tools if tool.tool_id in case.relevant_tool_ids
    )
    recall = (
        _ratio(relevant_returned, len(case.relevant_tool_ids))
        if case.relevant_tool_ids
        else None
    )
    precision = (
        _ratio(relevant_returned, len(result.tools)) if case.relevant_tool_ids else None
    )
    unauthorized_results = sum(
        1 for tool in result.tools if case.tenant not in tool.authorized_tenants
    )
    expected_selection = case.behavior == "select"
    wrong_tool = bool(
        expected_selection
        and (selected is None or selected.tool_id != case.expected_tool_id)
    )
    wrong_revision = bool(
        expected_selection
        and selected is not None
        and selected.tool_id == case.expected_tool_id
        and selected.revision_id != case.expected_revision_id
    )
    approval_required = bool(selected is not None and selected.requires_approval)
    approval_bypass_attempted = bool(case.attempt_direct_execution)
    execution_surface = "none"
    if selected is not None:
        execution_surface = "broker_approval" if approval_required else "direct_read"
    approval_bypass_succeeded = bool(
        approval_bypass_attempted
        and approval_required
        and execution_surface != "broker_approval"
    )
    if case.behavior == "abstain":
        task_success = selected is None
    else:
        task_success = bool(
            selected is not None
            and selected.tool_id == case.expected_tool_id
            and selected.revision_id == case.expected_revision_id
            and not approval_bypass_succeeded
        )
    context = _context_payload(
        profile=profile, candidates=candidates, ranked=result.tools
    )
    tokens = _context_tokens(context)
    return {
        "case_id": case.case_id,
        "language": case.language,
        "category": case.category,
        "tenant": case.tenant,
        "eligible": profile in case.eligible_profiles,
        "behavior": case.behavior,
        "returned_tool_ids": [tool.tool_id for tool in result.tools],
        "returned_revision_ids": [tool.revision_id for tool in result.tools],
        "selected_tool_id": selected.tool_id if selected is not None else None,
        "selected_revision_id": selected.revision_id if selected is not None else None,
        "recall_at_k": _round(recall) if recall is not None else None,
        "precision_at_k": _round(precision) if precision is not None else None,
        "unauthorized_results": unauthorized_results,
        "wrong_tool": wrong_tool,
        "wrong_revision": wrong_revision,
        "approval_bypass_attempted": approval_bypass_attempted,
        "approval_bypass_succeeded": approval_bypass_succeeded,
        "execution_surface": execution_surface,
        "task_success": task_success,
        "context_tokens": tokens,
        "estimated_input_cost_usd": _round(tokens * cost_rate / 1_000_000),
        "first_pass_latency_ms": _round(result.latency_ms),
        "filtered": {
            "unauthorized": result.filtered_unauthorized,
            "stale": result.filtered_stale,
            "profile": result.filtered_profile,
        },
    }


def _profile_metrics(
    outcomes: list[dict[str, Any]],
    second_pass_latencies: list[float],
    second_pass_hits: list[bool],
) -> dict[str, Any]:
    eligible = [item for item in outcomes if item["eligible"]]
    quality = [item for item in eligible if item["behavior"] == "select"]
    returned_count = sum(len(item["returned_revision_ids"]) for item in outcomes)
    unauthorized_count = sum(int(item["unauthorized_results"]) for item in outcomes)
    expected_count = len(quality)
    wrong_tool_count = sum(bool(item["wrong_tool"]) for item in quality)
    wrong_revision_count = sum(bool(item["wrong_revision"]) for item in quality)
    approval_attempts = sum(
        bool(item["approval_bypass_attempted"]) for item in outcomes
    )
    approval_successes = sum(
        bool(item["approval_bypass_succeeded"]) for item in outcomes
    )
    task_successes = sum(bool(item["task_success"]) for item in eligible)
    context_values = [float(item["context_tokens"]) for item in eligible]
    cost_values = [float(item["estimated_input_cost_usd"]) for item in eligible]
    first_latencies = [float(item["first_pass_latency_ms"]) for item in outcomes]
    all_latencies = [*first_latencies, *second_pass_latencies]
    return {
        "case_count": len(outcomes),
        "eligible_case_count": len(eligible),
        "quality_case_count": len(quality),
        "recall_at_k": _round(_mean([float(item["recall_at_k"]) for item in quality])),
        "precision_at_k": _round(
            _mean([float(item["precision_at_k"]) for item in quality])
        ),
        "unauthorized_result_rate": _round(_ratio(unauthorized_count, returned_count)),
        "wrong_tool_rate": _round(_ratio(wrong_tool_count, expected_count)),
        "wrong_revision_rate": _round(_ratio(wrong_revision_count, expected_count)),
        "approval_bypass_attempt_rate": _round(
            _ratio(approval_attempts, len(outcomes))
        ),
        "approval_bypass_success_rate": _round(
            _ratio(approval_successes, approval_attempts)
        ),
        "task_success_rate": _round(_ratio(task_successes, len(eligible))),
        "context_tokens_mean": _round(_mean(context_values)),
        "context_tokens_p95": _round(_percentile(context_values, 0.95)),
        "estimated_input_cost_usd_mean": _round(_mean(cost_values)),
        "estimated_input_cost_usd_max": _round(max(cost_values, default=0.0)),
        "latency_ms_mean": _round(_mean(all_latencies)),
        "latency_ms_p95": _round(_percentile(all_latencies, 0.95)),
        "first_pass_cache_hit_rate": 0.0,
        "second_pass_cache_hit_rate": _round(
            _ratio(sum(second_pass_hits), len(second_pass_hits))
        ),
        "filtered_unauthorized_count": sum(
            int(item["filtered"]["unauthorized"]) for item in outcomes
        ),
        "filtered_stale_count": sum(
            int(item["filtered"]["stale"]) for item in outcomes
        ),
        "filtered_profile_count": sum(
            int(item["filtered"]["profile"]) for item in outcomes
        ),
    }


def evaluate_thresholds(
    report: dict[str, Any], thresholds: dict[str, Any]
) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []

    def check(
        scope: str, metric: str, actual: float, comparator: str, expected: float
    ) -> None:
        passed = actual <= expected if comparator == "max" else actual >= expected
        if not passed:
            violations.append(
                {
                    "scope": scope,
                    "metric": metric,
                    "actual": actual,
                    "comparator": comparator,
                    "threshold": expected,
                }
            )

    global_metrics = report["global_metrics"]
    global_thresholds = thresholds["global"]
    mapping = {
        "unauthorized_result_rate_max": ("unauthorized_result_rate", "max"),
        "wrong_revision_rate_max": ("wrong_revision_rate", "max"),
        "approval_bypass_success_rate_max": ("approval_bypass_success_rate", "max"),
        "cross_tenant_cache_leak_rate_max": ("cross_tenant_cache_leak_rate", "max"),
        "second_pass_cache_hit_rate_min": ("second_pass_cache_hit_rate", "min"),
    }
    for threshold_name, (metric, comparator) in mapping.items():
        check(
            "global",
            metric,
            float(global_metrics[metric]),
            comparator,
            float(global_thresholds[threshold_name]),
        )

    profile_mapping = {
        "eligible_case_count_min": ("eligible_case_count", "min"),
        "recall_at_k_min": ("recall_at_k", "min"),
        "precision_at_k_min": ("precision_at_k", "min"),
        "wrong_tool_rate_max": ("wrong_tool_rate", "max"),
        "task_success_rate_min": ("task_success_rate", "min"),
        "context_tokens_p95_max": ("context_tokens_p95", "max"),
        "latency_ms_p95_max": ("latency_ms_p95", "max"),
        "cost_usd_per_case_max": ("estimated_input_cost_usd_max", "max"),
    }
    for profile, configured in thresholds["profiles"].items():
        metrics = report["profiles"][profile]["metrics"]
        for threshold_name, (metric, comparator) in profile_mapping.items():
            check(
                profile,
                metric,
                float(metrics[metric]),
                comparator,
                float(configured[threshold_name]),
            )
    return violations


def run_evaluation(contract: dict[str, Any]) -> dict[str, Any]:
    validate_evaluation_contract(contract)
    tools = [EvaluationTool.from_payload(item) for item in contract["tools"]]
    cases = [EvaluationCase.from_payload(item) for item in contract["cases"]]
    cache = PartitionedEvaluationCache(
        entries_per_partition=int(contract["cache"]["entries_per_tenant_profile"]),
        partition_limit=int(contract["cache"]["tenant_partitions"]),
    )
    limit = int(contract["ranking"]["limit"])
    semantic_min_similarity = float(contract["ranking"]["semantic_min_similarity"])
    cost_rate = float(contract["cost_model"]["input_usd_per_million_tokens"])
    profiles: dict[str, dict[str, Any]] = {}
    cache_keys: list[tuple[str, str, str]] = []
    for profile in _PROFILE_IDS:
        outcomes: list[dict[str, Any]] = []
        second_latencies: list[float] = []
        second_hits: list[bool] = []
        for case in cases:
            candidates, _ = _filter_tools(tools, case=case, profile=profile)
            first = _select(
                tools,
                case=case,
                profile=profile,
                limit=limit,
                semantic_min_similarity=semantic_min_similarity,
                cache=cache,
            )
            outcomes.append(
                _case_outcome(
                    case=case,
                    profile=profile,
                    result=first,
                    candidates=candidates,
                    cost_rate=cost_rate,
                )
            )
            second = _select(
                tools,
                case=case,
                profile=profile,
                limit=limit,
                semantic_min_similarity=semantic_min_similarity,
                cache=cache,
            )
            second_latencies.append(second.latency_ms)
            second_hits.append(second.cache_hit)
            cache_keys.append(
                (
                    case.tenant,
                    profile,
                    _digest({"case_id": case.case_id, "query": case.query}),
                )
            )
        profiles[profile] = {
            "metrics": _profile_metrics(outcomes, second_latencies, second_hits),
            "cases": outcomes,
        }
    tenants = sorted({case.tenant for case in cases})
    probes = 0
    leaks = 0
    for tenant, profile, key in cache_keys:
        for other_tenant in tenants:
            if other_tenant == tenant:
                continue
            probes += 1
            if cache.contains(f"{other_tenant}:{profile}", key):
                leaks += 1
    all_metrics = [profiles[profile]["metrics"] for profile in _PROFILE_IDS]
    returned = sum(
        len(item["returned_revision_ids"])
        for profile in _PROFILE_IDS
        for item in profiles[profile]["cases"]
    )
    unauthorized = sum(
        int(item["unauthorized_results"])
        for profile in _PROFILE_IDS
        for item in profiles[profile]["cases"]
    )
    expected = sum(int(metrics["quality_case_count"]) for metrics in all_metrics)
    wrong_revisions = sum(
        bool(item["wrong_revision"])
        for profile in _PROFILE_IDS
        for item in profiles[profile]["cases"]
        if item["eligible"] and item["behavior"] == "select"
    )
    approval_attempts = sum(
        bool(item["approval_bypass_attempted"])
        for profile in _PROFILE_IDS
        for item in profiles[profile]["cases"]
    )
    approval_successes = sum(
        bool(item["approval_bypass_succeeded"])
        for profile in _PROFILE_IDS
        for item in profiles[profile]["cases"]
    )
    global_metrics = {
        "unauthorized_result_rate": _round(_ratio(unauthorized, returned)),
        "wrong_revision_rate": _round(_ratio(wrong_revisions, expected)),
        "approval_bypass_success_rate": _round(
            _ratio(approval_successes, approval_attempts)
        ),
        "cross_tenant_cache_probe_count": probes,
        "cross_tenant_cache_leak_rate": _round(_ratio(leaks, probes)),
        "second_pass_cache_hit_rate": _round(
            _mean(
                [
                    float(metrics["second_pass_cache_hit_rate"])
                    for metrics in all_metrics
                ]
            )
        ),
    }
    report = {
        "schema_version": 1,
        "task_id": contract["task_id"],
        "suite_id": contract["suite_id"],
        "status": "pending",
        "contract_sha256": _digest(contract),
        "fixture_counts": {
            "tools": len(tools),
            "cases": len(cases),
            "languages": len({case.language for case in cases}),
            "categories": len({case.category for case in cases}),
        },
        "ranking": dict(contract["ranking"]),
        "global_metrics": global_metrics,
        "profiles": profiles,
        "comparisons": {
            "context_tokens_p95": {
                profile: profiles[profile]["metrics"]["context_tokens_p95"]
                for profile in _PROFILE_IDS
            },
            "task_success_rate": {
                profile: profiles[profile]["metrics"]["task_success_rate"]
                for profile in _PROFILE_IDS
            },
            "recall_at_k": {
                profile: profiles[profile]["metrics"]["recall_at_k"]
                for profile in _PROFILE_IDS
            },
            "estimated_input_cost_usd_mean": {
                profile: profiles[profile]["metrics"]["estimated_input_cost_usd_mean"]
                for profile in _PROFILE_IDS
            },
        },
        "thresholds": contract["thresholds"],
        "violations": [],
    }
    violations = evaluate_thresholds(report, contract["thresholds"])
    report["violations"] = violations
    report["status"] = "passed" if not violations else "failed"
    return report
