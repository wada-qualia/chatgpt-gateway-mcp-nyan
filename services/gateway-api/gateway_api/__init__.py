"""FastAPI backend for the ChatGPT MCP SSH Gateway."""

from __future__ import annotations

from typing import Any

__all__ = ["create_app"]


def __getattr__(name: str) -> Any:
    if name == "create_app":
        from .main import create_app

        return create_app
    raise AttributeError(name)
