from __future__ import annotations

from pathlib import PurePosixPath

from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.types import Scope


class SPAStaticFiles(StaticFiles):
    backend_prefixes = {
        "api",
        "assets",
        "auth",
        "docs",
        "health",
        "mcp",
        "oauth",
        "openapi.json",
        "ready",
        "redoc",
    }

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            response = await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code != 404 or not self._is_spa_navigation(path, scope):
                raise
            return await super().get_response("index.html", scope)

        if response.status_code == 404 and self._is_spa_navigation(path, scope):
            return await super().get_response("index.html", scope)
        return response

    def _is_spa_navigation(self, path: str, scope: Scope) -> bool:
        if scope.get("method") not in {"GET", "HEAD"}:
            return False

        normalized = path.strip("/")
        if not normalized:
            return False

        first_segment = normalized.split("/", 1)[0]
        if first_segment in self.backend_prefixes or first_segment.startswith("."):
            return False

        return PurePosixPath(normalized).suffix == ""
