#!/usr/bin/env python3
"""Standalone, local-only synthetic chat-context isolation demo.

This example intentionally does not import or start the Gateway application. It
models three public resource families with deterministic in-memory state so the
ownership boundary can be inspected without credentials or external services.
It is an illustration, not production evidence.
"""

from __future__ import annotations

import argparse
import html
import json
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlparse


RESOURCE_FAMILIES = ("CommandSession", "Monitoring", "FileChange")
CONTEXTS = ("context-a", "context-b")


@dataclass(frozen=True)
class SyntheticResource:
    family: str
    resource_id: str
    owner_context: str
    state: str

    def public_dict(self) -> dict[str, str]:
        return {
            "family": self.family,
            "id": self.resource_id,
            "state": self.state,
        }


class SyntheticControlPlane:
    """Deterministic context-scoped state on one shared synthetic backend."""

    principal = "demo-principal"
    client = "demo-client"
    backend = "synthetic-backend"

    def __init__(self) -> None:
        self._resources = (
            SyntheticResource("CommandSession", "session-a", "context-a", "running"),
            SyntheticResource("Monitoring", "monitor-a", "context-a", "running"),
            SyntheticResource("FileChange", "change-a", "context-a", "recorded"),
            SyntheticResource("CommandSession", "session-b", "context-b", "running"),
            SyntheticResource("Monitoring", "monitor-b", "context-b", "running"),
            SyntheticResource("FileChange", "change-b", "context-b", "recorded"),
        )

    @staticmethod
    def _require_context(context: str) -> None:
        if context not in CONTEXTS:
            raise KeyError("Chat context not found")

    def resources_for(self, context: str) -> dict[str, list[dict[str, str]]]:
        self._require_context(context)
        grouped = {family: [] for family in RESOURCE_FAMILIES}
        for resource in self._resources:
            if resource.owner_context == context:
                grouped[resource.family].append(resource.public_dict())
        return grouped

    def get_command_session(self, context: str, session_id: str) -> dict[str, str]:
        self._require_context(context)
        for resource in self._resources:
            if resource.family != "CommandSession" or resource.resource_id != session_id:
                continue
            if resource.owner_context != context:
                raise KeyError("Command session not found")
            return resource.public_dict()
        raise KeyError("Command session not found")

    def snapshot(self) -> dict[str, Any]:
        contexts: dict[str, Any] = {}
        for context in CONTEXTS:
            own_session = "session-a" if context == "context-a" else "session-b"
            other_session = "session-b" if context == "context-a" else "session-a"
            try:
                self.get_command_session(context, other_session)
            except KeyError as exc:
                cross_lookup = {
                    "target": other_session,
                    "status": HTTPStatus.NOT_FOUND,
                    "detail": str(exc.args[0]),
                }
            else:  # pragma: no cover - fail-closed invariant
                raise AssertionError("cross-context session lookup unexpectedly succeeded")
            contexts[context] = {
                "own_session": own_session,
                "resources": self.resources_for(context),
                "cross_lookup": cross_lookup,
            }
        return {
            "demo": "synthetic",
            "production_evidence": False,
            "shared_infrastructure": {
                "principal": self.principal,
                "client": self.client,
                "backend": self.backend,
            },
            "resource_families": list(RESOURCE_FAMILIES),
            "contexts": contexts,
        }


def render_page(model: SyntheticControlPlane) -> bytes:
    snapshot = model.snapshot()

    def context_card(context: str) -> str:
        item = snapshot["contexts"][context]
        resources = item["resources"]
        rows = "".join(
            f"<li><b>{html.escape(family)}</b><code>{html.escape(entries[0]['id'])}</code>"
            f"<span>{html.escape(entries[0]['state'])}</span></li>"
            for family, entries in resources.items()
        )
        lookup = item["cross_lookup"]
        return f"""
        <section class="context-card" aria-label="{html.escape(context)} resources">
          <header><span class="context-name">{html.escape(context)}</span><span class="owned">OWN STATE ONLY</span></header>
          <ul>{rows}</ul>
          <div class="blocked"><b>cross lookup</b><code>GET {html.escape(lookup['target'])}</code><strong>{lookup['status']} · {html.escape(lookup['detail'])}</strong></div>
        </section>
        """

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nyan · Synthetic chat-context isolation demo</title>
<style>
:root {{ color-scheme: dark; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background:#081018; color:#e8f0f7; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; min-height:100vh; background:radial-gradient(circle at 50% 0,#14283a 0,#081018 48rem); }}
main {{ width:min(1080px,100%); margin:auto; padding:20px; }}
.banner {{ display:flex; align-items:center; gap:10px; color:#081018; background:#f9d66d; border-radius:999px; width:max-content; max-width:100%; padding:7px 12px; font-weight:800; font-size:12px; letter-spacing:.04em; }}
h1 {{ font-family:ui-sans-serif,system-ui,sans-serif; font-size:clamp(27px,5vw,54px); line-height:.98; margin:20px 0 12px; max-width:850px; }}
.lede {{ color:#a9bbca; max-width:780px; font-family:ui-sans-serif,system-ui,sans-serif; font-size:15px; line-height:1.45; margin:0 0 16px; }}
.result {{ border:1px solid #34536d; background:#0c1721e8; border-radius:18px; padding:14px; box-shadow:0 24px 70px #0008; }}
.result-head {{ display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:11px; }}
.result-head strong {{ font-family:ui-sans-serif,system-ui,sans-serif; font-size:15px; margin-right:auto; }}
.pill {{ border:1px solid #34536d; border-radius:999px; padding:5px 8px; color:#b8c8d5; font-size:11px; }}
.proof-grid {{ display:grid; grid-template-columns:1fr 52px 1fr; gap:8px; align-items:stretch; }}
.proof {{ border:1px solid #284358; border-radius:13px; padding:10px; background:#09131b; min-width:0; }}
.proof b {{ display:block; color:#7dd3fc; margin-bottom:6px; font-size:13px; }}
.proof span {{ display:block; color:#9fb2c0; font-size:11px; line-height:1.55; }}
.proof strong {{ display:block; margin-top:8px; color:#fb7185; font-size:11px; line-height:1.35; }}
.shared {{ display:grid; place-items:center; text-align:center; color:#85a2b8; font-size:10px; line-height:1.35; }}
.scope {{ margin-top:10px; border-top:1px solid #203544; padding-top:9px; color:#91a7b8; font-size:11px; display:flex; gap:8px; flex-wrap:wrap; }}
.details {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:14px; }}
.context-card {{ border:1px solid #203b50; background:#09131bc7; border-radius:16px; padding:13px; }}
.context-card header {{ display:flex; justify-content:space-between; gap:8px; align-items:center; margin-bottom:9px; }}
.context-name {{ color:#7dd3fc; font-weight:800; }}
.owned {{ font-size:9px; color:#86efac; border:1px solid #285443; padding:4px 6px; border-radius:999px; }}
ul {{ list-style:none; padding:0; margin:0; display:grid; gap:6px; }}
li {{ display:grid; grid-template-columns:110px 1fr auto; gap:8px; align-items:center; border:1px solid #172b39; border-radius:9px; padding:7px; font-size:10px; }}
li b {{ color:#9fb2c0; }} code {{ overflow-wrap:anywhere; color:#e8f0f7; }} li span {{ color:#86efac; }}
.blocked {{ display:grid; grid-template-columns:auto 1fr; gap:5px 8px; margin-top:9px; padding:8px; border-radius:9px; background:#251017; font-size:10px; }}
.blocked b {{ color:#fb7185; text-transform:uppercase; }} .blocked strong {{ grid-column:1/-1; color:#fb7185; }}
footer {{ color:#698296; font-size:10px; line-height:1.5; margin-top:14px; }}
@media (max-width:620px) {{
 main {{ padding:14px; }} h1 {{ margin-top:15px; }} .lede {{ font-size:13px; margin-bottom:12px; }}
 .result {{ padding:10px; }} .result-head {{ margin-bottom:8px; }}
 .proof-grid {{ grid-template-columns:1fr 34px 1fr; gap:5px; }} .proof {{ padding:8px; }} .proof span {{ font-size:9px; }} .proof strong {{ font-size:9px; }}
 .shared {{ font-size:8px; }} .details {{ grid-template-columns:1fr; }}
}}
</style>
</head>
<body><main>
<div class="banner">SYNTHETIC DEMO · NOT PRODUCTION EVIDENCE</div>
<h1>Two chats. One infrastructure. Separate mutable state.</h1>
<p class="lede">A dependency-free illustration of context-bound <b>CommandSession</b>, <b>Monitoring</b> and <b>FileChange</b> state. It makes no claim about arbitrary Gateway resource families.</p>
<section class="result" aria-label="Isolation result">
  <div class="result-head"><strong>Result visible before any interaction</strong><span class="pill">same demo principal</span><span class="pill">same demo client</span><span class="pill">same synthetic backend</span></div>
  <div class="proof-grid">
    <div class="proof"><b>context-a</b><span>session-a · monitor-a · change-a</span><strong>GET session-b → 404<br>Command session not found</strong></div>
    <div class="shared">ONE<br>SHARED<br>BACKEND</div>
    <div class="proof"><b>context-b</b><span>session-b · monitor-b · change-b</span><strong>GET session-a → 404<br>Command session not found</strong></div>
  </div>
  <div class="scope"><b>Illustrated scope:</b><span>CommandSession</span><span>Monitoring</span><span>FileChange</span></div>
</section>
<div class="details">{context_card('context-a')}{context_card('context-b')}</div>
<footer>This server binds to loopback only, stores deterministic data in memory, performs no shell/device/container/MCP calls, and uses no credentials or external services.</footer>
</main></body></html>"""
    return page.encode("utf-8")


class DemoServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], model: SyntheticControlPlane | None = None) -> None:
        self.model = model or SyntheticControlPlane()
        super().__init__(address, DemoHandler)


class DemoHandler(BaseHTTPRequestHandler):
    server: DemoServer

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: HTTPStatus, payload: Any) -> None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        path = unquote(urlparse(self.path).path)
        if path == "/":
            self._send(HTTPStatus.OK, render_page(self.server.model), "text/html; charset=utf-8")
            return
        if path == "/api/demo":
            self._json(HTTPStatus.OK, self.server.model.snapshot())
            return

        parts = [part for part in path.split("/") if part]
        if len(parts) == 4 and parts[:2] == ["api", "contexts"] and parts[3] == "resources":
            context = parts[2]
            try:
                payload = self.server.model.resources_for(context)
            except KeyError as exc:
                self._json(HTTPStatus.NOT_FOUND, {"detail": str(exc.args[0])})
            else:
                self._json(HTTPStatus.OK, payload)
            return
        if len(parts) == 5 and parts[:2] == ["api", "contexts"] and parts[3] == "sessions":
            context, session_id = parts[2], parts[4]
            try:
                payload = self.server.model.get_command_session(context, session_id)
            except KeyError as exc:
                self._json(HTTPStatus.NOT_FOUND, {"detail": str(exc.args[0])})
            else:
                self._json(HTTPStatus.OK, payload)
            return

        self._json(HTTPStatus.NOT_FOUND, {"detail": "Not found"})


def run_self_test() -> None:
    model = SyntheticControlPlane()
    snapshot = model.snapshot()
    assert snapshot["production_evidence"] is False
    assert tuple(snapshot["resource_families"]) == RESOURCE_FAMILIES
    for context in CONTEXTS:
        resources = model.resources_for(context)
        assert tuple(resources) == RESOURCE_FAMILIES
        assert all(len(resources[family]) == 1 for family in RESOURCE_FAMILIES)
        expected_suffix = "a" if context == "context-a" else "b"
        assert resources["CommandSession"][0]["id"] == f"session-{expected_suffix}"
        other = "session-b" if context == "context-a" else "session-a"
        try:
            model.get_command_session(context, other)
        except KeyError as exc:
            assert exc.args[0] == "Command session not found"
        else:  # pragma: no cover - invariant guard
            raise AssertionError("cross-context lookup must fail closed")
    print("synthetic isolation self-test: PASS")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765, help="loopback TCP port (default: 8765)")
    parser.add_argument("--self-test", action="store_true", help="run deterministic invariants and exit")
    args = parser.parse_args()
    if args.self_test:
        run_self_test()
        return 0
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")

    server = DemoServer(("127.0.0.1", args.port))
    host, port = server.server_address
    print(f"Synthetic isolation demo: http://{host}:{port}")
    print("Synthetic illustration only; not production evidence.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
