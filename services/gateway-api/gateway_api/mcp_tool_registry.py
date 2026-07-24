from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


class ToolRegistryCollision(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ToolDispatchTarget:
    provider: str
    public_name: str
    revision_id: str | None = None
    generation_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ToolRegistryEntry:
    tool: dict[str, Any]
    target: ToolDispatchTarget
    order: int


class ToolRegistry:
    """Deterministic public tool registry with fail-closed collision handling."""

    def __init__(self) -> None:
        self._entries: dict[str, ToolRegistryEntry] = {}

    def register(
        self,
        provider: str,
        tools: Iterable[dict[str, Any]],
        *,
        order_by_name: dict[str, int] | None = None,
        start_order: int = 0,
        targets: dict[str, ToolDispatchTarget] | None = None,
    ) -> None:
        for offset, raw_tool in enumerate(tools):
            tool = dict(raw_tool)
            name = str(tool.get("name") or "").strip()
            if not name:
                raise ValueError(f"{provider} registry returned a tool without a name")
            if name in self._entries:
                existing = self._entries[name].target.provider
                raise ToolRegistryCollision(
                    f"Public tool name collision: {name} ({existing} vs {provider})"
                )
            target = (targets or {}).get(name) or ToolDispatchTarget(
                provider=provider,
                public_name=name,
            )
            order = (order_by_name or {}).get(name, start_order + offset)
            self._entries[name] = ToolRegistryEntry(tool=tool, target=target, order=order)

    def filtered(self, allowed_names: set[str] | None) -> "ToolRegistry":
        if allowed_names is None:
            return self
        filtered = ToolRegistry()
        for entry in self.entries():
            name = entry.target.public_name
            if name in allowed_names:
                filtered._entries[name] = entry
        return filtered

    def entries(self) -> list[ToolRegistryEntry]:
        return sorted(
            self._entries.values(),
            key=lambda entry: (entry.order, entry.target.public_name),
        )

    def tools(self) -> list[dict[str, Any]]:
        return [dict(entry.tool) for entry in self.entries()]

    def target(self, name: str) -> ToolDispatchTarget | None:
        entry = self._entries.get(name)
        return entry.target if entry else None

    def tool(self, name: str) -> dict[str, Any] | None:
        entry = self._entries.get(name)
        return dict(entry.tool) if entry else None

    def names(self) -> tuple[str, ...]:
        return tuple(entry.target.public_name for entry in self.entries())
