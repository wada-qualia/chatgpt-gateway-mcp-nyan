from __future__ import annotations

import asyncio
import ipaddress
import re
import secrets
import socket
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlparse

import httpx

_TRACEPARENT = re.compile(r"^[\da-f]{2}-([\da-f]{32})-([\da-f]{16})-([\da-f]{2})$", re.I)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


class FederationBoundaryError(RuntimeError):
    def __init__(self, code: str, message: str, *, http_status: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


@dataclass(frozen=True, slots=True)
class EndpointResolution:
    endpoint: str
    scheme: str
    hostname: str
    port: int
    addresses: frozenset[str]


@dataclass(frozen=True, slots=True)
class RecursionContext:
    hop: int
    visited: tuple[str, ...]

    def outbound_headers(self, instance_id: str, traceparent: str) -> dict[str, str]:
        visited = tuple(dict.fromkeys((*self.visited, instance_id)))
        return {
            "traceparent": traceparent,
            "X-Gateway-MCP-Instance": instance_id,
            "X-Gateway-MCP-Hop": str(self.hop + 1),
            "X-Gateway-MCP-Visited": ",".join(visited),
        }


def default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def normalize_instance_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._:-]", "", value.strip())[:120]
    return cleaned or "gateway-local"


def new_traceparent(parent: str | None = None) -> str:
    match = _TRACEPARENT.fullmatch((parent or "").strip())
    trace_id = match.group(1).lower() if match and int(match.group(1), 16) else secrets.token_hex(16)
    span_id = secrets.token_hex(8)
    flags = match.group(3).lower() if match else "01"
    return f"00-{trace_id}-{span_id}-{flags}"


def parse_recursion_context(
    headers: Mapping[str, str], *, instance_id: str, max_hops: int
) -> RecursionContext:
    normalized = {str(key).lower(): str(value) for key, value in headers.items()}
    try:
        hop = int(normalized.get("x-gateway-mcp-hop", "0") or 0)
    except ValueError as exc:
        raise FederationBoundaryError(
            "MCP_RECURSION_DETECTED", "Invalid federation hop header", http_status=409
        ) from exc
    if hop < 0 or hop >= max(1, max_hops):
        raise FederationBoundaryError(
            "MCP_RECURSION_DETECTED", "Federation hop limit exceeded", http_status=409
        )
    visited = tuple(
        item.strip()[:120]
        for item in normalized.get("x-gateway-mcp-visited", "").split(",")
        if item.strip()
    )
    current = normalize_instance_id(instance_id)
    sender = normalize_instance_id(normalized.get("x-gateway-mcp-instance", ""))
    if current in visited or sender == current:
        raise FederationBoundaryError(
            "MCP_RECURSION_DETECTED",
            "The federation request already visited this Gateway instance",
            http_status=409,
        )
    if len(visited) != len(set(visited)):
        raise FederationBoundaryError(
            "MCP_RECURSION_DETECTED",
            "The federation request contains a repeated Gateway instance",
            http_status=409,
        )
    return RecursionContext(hop=hop, visited=visited)


async def resolve_endpoint(
    endpoint: str,
    *,
    public_base_url: str,
    allow_private_networks: bool,
    allow_insecure_http: bool,
) -> EndpointResolution:
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise FederationBoundaryError(
            "MCP_PROTOCOL_MISMATCH", "Upstream endpoint must be an absolute HTTP URL"
        )
    if parsed.username or parsed.password or parsed.fragment:
        raise FederationBoundaryError(
            "MCP_PROTOCOL_MISMATCH",
            "Upstream endpoint must not contain credentials or fragments",
        )
    if parsed.scheme != "https" and not allow_insecure_http:
        raise FederationBoundaryError(
            "MCP_PROTOCOL_MISMATCH", "Insecure upstream HTTP is disabled"
        )
    own = urlparse(public_base_url)
    port = parsed.port or default_port(parsed.scheme)
    if (
        parsed.hostname.lower() == (own.hostname or "").lower()
        and port == (own.port or default_port(own.scheme))
    ):
        raise FederationBoundaryError(
            "MCP_RECURSION_DETECTED",
            "The Gateway cannot federate its own public endpoint",
            http_status=409,
        )
    try:
        infos = await asyncio.to_thread(
            socket.getaddrinfo,
            parsed.hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise FederationBoundaryError(
            "MCP_SERVER_OFFLINE", "Upstream endpoint DNS resolution failed", http_status=503
        ) from exc
    addresses = frozenset(str(item[4][0]).split("%", 1)[0] for item in infos)
    if not addresses:
        raise FederationBoundaryError(
            "MCP_SERVER_OFFLINE", "Upstream endpoint DNS returned no addresses", http_status=503
        )
    if not allow_private_networks and any(
        not ipaddress.ip_address(address).is_global for address in addresses
    ):
        raise FederationBoundaryError(
            "MCP_SERVER_QUARANTINED",
            "Upstream endpoint resolves to a non-public network",
        )
    return EndpointResolution(
        endpoint=endpoint,
        scheme=parsed.scheme,
        hostname=parsed.hostname.lower(),
        port=port,
        addresses=addresses,
    )


def peer_address(response: httpx.Response) -> str | None:
    stream = response.extensions.get("network_stream")
    if stream is None or not hasattr(stream, "get_extra_info"):
        return None
    value = stream.get_extra_info("server_addr")
    if isinstance(value, tuple) and value:
        return str(value[0]).split("%", 1)[0]
    if isinstance(value, str):
        return value.split("%", 1)[0]
    return None


def assert_pinned_peer(response: httpx.Response, resolution: EndpointResolution) -> None:
    address = peer_address(response)
    if address is None:
        raise FederationBoundaryError(
            "MCP_DNS_REBINDING_DETECTED",
            "Connected peer address is unavailable for DNS pin verification",
            http_status=502,
        )
    if address not in resolution.addresses:
        raise FederationBoundaryError(
            "MCP_DNS_REBINDING_DETECTED",
            "Connected peer is outside the prevalidated DNS answer set",
            http_status=409,
        )


def sanitize_untrusted(value: Any, *, max_string: int = 2000, depth: int = 0) -> Any:
    if depth > 8:
        return "[depth-limited]"
    if isinstance(value, str):
        return _CONTROL.sub(" ", value).strip()[:max_string]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 100:
                result["_gateway_truncated"] = True
                break
            clean_key = _CONTROL.sub("", str(key)).strip()[:160]
            result[clean_key] = sanitize_untrusted(
                item, max_string=max_string, depth=depth + 1
            )
        return result
    if isinstance(value, (list, tuple)):
        return [
            sanitize_untrusted(item, max_string=max_string, depth=depth + 1)
            for item in value[:100]
        ]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return sanitize_untrusted(str(value), max_string=max_string, depth=depth + 1)


class SlidingWindowLimiter:
    def __init__(self, *, window_seconds: float = 60.0) -> None:
        self.window_seconds = max(1.0, float(window_seconds))
        self._entries: dict[str, deque[float]] = defaultdict(deque)

    def acquire(self, key: str, limit: int, *, now: float | None = None) -> bool:
        if limit <= 0:
            return True
        current = time.monotonic() if now is None else now
        queue = self._entries[key]
        threshold = current - self.window_seconds
        while queue and queue[0] <= threshold:
            queue.popleft()
        if len(queue) >= limit:
            return False
        queue.append(current)
        return True


class FederationTelemetry:
    def __init__(self) -> None:
        self.counters: Counter[tuple[str, tuple[tuple[str, str], ...]]] = Counter()
        self.latency_sum: Counter[tuple[str, str]] = Counter()
        self.latency_count: Counter[tuple[str, str]] = Counter()
        self.active_connections = 0
        self.active_calls = 0

    def increment(self, name: str, **labels: str) -> None:
        safe = tuple(sorted((key, str(value)[:80]) for key, value in labels.items()))
        self.counters[(name, safe)] += 1

    def observe_latency(self, operation: str, outcome: str, seconds: float) -> None:
        key = (operation[:40], outcome[:40])
        self.latency_sum[key] += max(0.0, float(seconds))
        self.latency_count[key] += 1

    def prometheus_lines(self) -> list[str]:
        lines = [
            "# TYPE gateway_mcp_events_total counter",
            "# TYPE gateway_mcp_operation_duration_seconds summary",
            "# TYPE gateway_mcp_active_connections gauge",
            f"gateway_mcp_active_connections {self.active_connections}",
            "# TYPE gateway_mcp_active_calls gauge",
            f"gateway_mcp_active_calls {self.active_calls}",
        ]
        for (name, labels), value in sorted(self.counters.items()):
            label_map = (("event", name), *labels)
            rendered = ",".join(
                f'{key}="{str(item).replace(chr(34), "")}"' for key, item in label_map
            )
            lines.append(f"gateway_mcp_events_total{{{rendered}}} {value}")
        for (operation, outcome), value in sorted(self.latency_count.items()):
            labels = f'operation="{operation}",outcome="{outcome}"'
            lines.append(
                f"gateway_mcp_operation_duration_seconds_count{{{labels}}} {value}"
            )
            lines.append(
                f"gateway_mcp_operation_duration_seconds_sum{{{labels}}} "
                f"{self.latency_sum[(operation, outcome)]:.9f}"
            )
        return lines
