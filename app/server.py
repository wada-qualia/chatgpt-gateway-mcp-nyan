from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import shutil
import signal
import subprocess
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import jwt
from fastmcp import FastMCP
from fastmcp.dependencies import CurrentAccessToken
from fastmcp.server.auth import AccessToken
from fastmcp.server.auth.providers.jwt import JWTVerifier
from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("chatgpt_mcp_docker_app")

WORKSPACE_ROOT = Path(os.environ.get("WORKSPACE_ROOT", "/workspace")).resolve()
AUTH_USERS_PATH = Path(os.environ.get("AUTH_USERS_PATH", "/auth/users.json")).resolve()
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
AUTH_ISSUER = (os.environ.get("AUTH_ISSUER") or PUBLIC_BASE_URL or "http://localhost:8000").rstrip("/")
AUTH_AUDIENCE = (os.environ.get("AUTH_AUDIENCE") or PUBLIC_BASE_URL or "docker-workspace-mcp").rstrip("/")
AUTH_JWT_SECRET = os.environ.get("AUTH_JWT_SECRET", "")
AUTH_ACCESS_TOKEN_TTL_SECONDS = int(os.environ.get("AUTH_ACCESS_TOKEN_TTL_SECONDS", "28800"))
AUTH_CODE_TTL_SECONDS = int(os.environ.get("AUTH_CODE_TTL_SECONDS", "600"))
AUTH_DEFAULT_SCOPES = [scope for scope in os.environ.get("AUTH_DEFAULT_SCOPES", "workspace:read workspace:write workspace:exec").split() if scope]
AUTH_SUPPORTED_SCOPES = [scope for scope in os.environ.get("AUTH_SUPPORTED_SCOPES", "workspace:read workspace:write workspace:exec").split() if scope]
MCP_HOST = os.environ.get("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.environ.get("MCP_PORT", "8000"))
MAX_COMMAND_TIMEOUT_SECONDS = int(os.environ.get("MAX_COMMAND_TIMEOUT_SECONDS", "120"))
MAX_COMMAND_CHARS = int(os.environ.get("MAX_COMMAND_CHARS", "10000"))
MAX_FILE_READ_BYTES = int(os.environ.get("MAX_FILE_READ_BYTES", "200000"))
MAX_FILE_WRITE_BYTES = int(os.environ.get("MAX_FILE_WRITE_BYTES", "1000000"))
MAX_OUTPUT_CHARS = int(os.environ.get("MAX_OUTPUT_CHARS", "30000"))

if not AUTH_JWT_SECRET:
    AUTH_JWT_SECRET = base64.urlsafe_b64encode(os.urandom(48)).decode("ascii")
    logger.warning("AUTH_JWT_SECRET was not set. A temporary secret was generated and tokens will be invalid after restart.")

jwt_verifier = JWTVerifier(
    public_key=AUTH_JWT_SECRET,
    issuer=AUTH_ISSUER,
    audience=AUTH_AUDIENCE,
    algorithm="HS256",
)

server_instructions = """
This MCP server is a Docker-contained multi-user development workspace. It requires OAuth authentication. Every authenticated user receives an isolated workspace under /workspace/users/<username>. It can list files, read files, create files, edit files, delete files, create directories, and run CLI commands inside the authenticated user's workspace only. Use destructive tools carefully and prefer reading before overwriting. Shell commands run in the user's workspace or a validated subdirectory.
""".strip()

mcp = FastMCP(
    name="Docker Workspace MCP",
    instructions=server_instructions,
    auth=jwt_verifier,
)

OAUTH_CLIENTS: dict[str, dict[str, Any]] = {}
OAUTH_CODES: dict[str, dict[str, Any]] = {}


class OperationResult(BaseModel):
    ok: bool
    message: str
    data: dict[str, Any] = Field(default_factory=dict)


class FileEntry(BaseModel):
    path: str
    kind: str
    size_bytes: int | None = None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def now_ts() -> int:
    return int(time.time())


def log_event(event: str, **fields: Any) -> None:
    payload = {"event": event, "ts": now_iso(), **fields}
    logger.info(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def truncate_text(value: str, limit: int) -> tuple[str, bool]:
    if len(value) <= limit:
        return value, False
    return value[:limit], True


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_raw, salt_raw, digest_raw = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_raw)
        salt = b64url_decode(salt_raw)
        expected = b64url_decode(digest_raw)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def load_users() -> list[dict[str, Any]]:
    if not AUTH_USERS_PATH.exists():
        return []
    with AUTH_USERS_PATH.open("r", encoding="utf-8") as file:
        data = json.load(file)
    users = data.get("users", [])
    if not isinstance(users, list):
        return []
    return [user for user in users if isinstance(user, dict)]


def find_user(username: str) -> dict[str, Any] | None:
    for user in load_users():
        if user.get("username") == username:
            return user
    return None


def authenticate_user(username: str, password: str) -> dict[str, Any] | None:
    user = find_user(username)
    if user is None or user.get("disabled"):
        return None
    password_hash = str(user.get("password_hash", ""))
    if not verify_password(password, password_hash):
        return None
    return user


def normalize_scopes(scope_value: str | list[str] | None) -> list[str]:
    if scope_value is None:
        return []
    if isinstance(scope_value, str):
        raw = scope_value.replace(",", " ").split()
    else:
        raw = [str(item) for item in scope_value]
    result: list[str] = []
    for scope in raw:
        if scope and scope not in result:
            result.append(scope)
    return result


def external_base_url(request: Request) -> str:
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    forwarded_proto = request.headers.get("x-forwarded-proto")
    forwarded_host = request.headers.get("x-forwarded-host")
    if forwarded_proto and forwarded_host:
        return f"{forwarded_proto}://{forwarded_host}".rstrip("/")
    return str(request.base_url).rstrip("/")


def oauth_metadata(base_url: str) -> dict[str, Any]:
    return {
        "issuer": AUTH_ISSUER,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "registration_endpoint": f"{base_url}/oauth/register",
        "revocation_endpoint": f"{base_url}/oauth/revoke",
        "userinfo_endpoint": f"{base_url}/oauth/userinfo",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": AUTH_SUPPORTED_SCOPES,
    }


def protected_resource_metadata(base_url: str) -> dict[str, Any]:
    return {
        "resource": AUTH_AUDIENCE,
        "authorization_servers": [base_url],
        "scopes_supported": AUTH_SUPPORTED_SCOPES,
        "resource_documentation": f"{base_url}/health",
    }


def parse_form_body_sync(raw: bytes) -> dict[str, str]:
    from urllib.parse import parse_qs

    parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
    result: dict[str, str] = {}
    for key, values in parsed.items():
        result[key] = values[-1] if values else ""
    return result


def is_allowed_redirect_uri(uri: str) -> bool:
    if uri.startswith("https://chatgpt.com/connector/oauth/"):
        return True
    if uri == "https://chatgpt.com/connector_platform_oauth_redirect":
        return True
    if uri.startswith("http://localhost:") or uri.startswith("http://127.0.0.1:"):
        return True
    return False


def get_client(client_id: str) -> dict[str, Any] | None:
    return OAUTH_CLIENTS.get(client_id)


def auto_register_client(client_id: str, redirect_uri: str) -> dict[str, Any]:
    client = {
        "client_id": client_id,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "client_name": "Auto-registered MCP client",
        "scope": " ".join(AUTH_SUPPORTED_SCOPES),
        "client_id_issued_at": now_ts(),
    }
    OAUTH_CLIENTS[client_id] = client
    return client


def client_allows_redirect(client: dict[str, Any], redirect_uri: str) -> bool:
    redirect_uris = client.get("redirect_uris") or []
    return redirect_uri in redirect_uris and is_allowed_redirect_uri(redirect_uri)


def html_login_form(base_url: str, params: dict[str, str], error: str | None = None) -> str:
    hidden_inputs = "\n".join(
        f'<input type="hidden" name="{html.escape(key)}" value="{html.escape(value)}">'
        for key, value in params.items()
    )
    error_block = f'<div class="error">{html.escape(error)}</div>' if error else ""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCP Login</title>
<style>
body {{ font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #101214; color: #f5f5f5; margin: 0; padding: 32px; }}
main {{ max-width: 460px; margin: 48px auto; background: #181b1f; border: 1px solid #30343a; border-radius: 16px; padding: 28px; }}
label {{ display: block; margin: 16px 0 6px; color: #cbd5e1; }}
input {{ width: 100%; box-sizing: border-box; padding: 12px; border-radius: 10px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; }}
button {{ width: 100%; margin-top: 22px; padding: 12px 16px; border: 0; border-radius: 10px; background: #38bdf8; color: #020617; font-weight: 700; cursor: pointer; }}
.error {{ background: #7f1d1d; border: 1px solid #ef4444; padding: 10px 12px; border-radius: 10px; margin-bottom: 12px; }}
small {{ color: #94a3b8; }}
</style>
</head>
<body>
<main>
<h1>Docker Workspace MCP</h1>
<p>Sign in to authorize ChatGPT access to your isolated Docker workspace.</p>
{error_block}
<form method="post" action="{html.escape(base_url)}/oauth/authorize">
{hidden_inputs}
<label for="username">Username</label>
<input id="username" name="username" autocomplete="username" required>
<label for="password">Password</label>
<input id="password" type="password" name="password" autocomplete="current-password" required>
<button type="submit">Authorize</button>
</form>
<p><small>Only local users from auth/users.json can sign in.</small></p>
</main>
</body>
</html>"""


def json_error(message: str, status_code: int = 400, **fields: Any) -> JSONResponse:
    return JSONResponse({"error": message, **fields}, status_code=status_code)


def oauth_error_redirect(redirect_uri: str, state: str | None, error: str, description: str) -> RedirectResponse:
    params = {"error": error, "error_description": description}
    if state:
        params["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{separator}{urlencode(params)}", status_code=302)


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return hmac.compare_digest(b64url_encode(digest), code_challenge)


def issue_access_token(user: dict[str, Any], client_id: str, scopes: list[str], resource: str | None) -> str:
    issued_at = now_ts()
    expires_at = issued_at + AUTH_ACCESS_TOKEN_TTL_SECONDS
    username = str(user["username"])
    payload = {
        "iss": AUTH_ISSUER,
        "aud": AUTH_AUDIENCE,
        "sub": username,
        "preferred_username": username,
        "name": str(user.get("display_name") or username),
        "client_id": client_id,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": expires_at,
        "jti": uuid.uuid4().hex,
        "scope": " ".join(scopes),
        "scopes": scopes,
    }
    if resource:
        payload["resource"] = resource
    return jwt.encode(payload, AUTH_JWT_SECRET, algorithm="HS256")


def verify_bearer_token_for_http(request: Request) -> dict[str, Any] | None:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    token = header.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, AUTH_JWT_SECRET, algorithms=["HS256"], issuer=AUTH_ISSUER, audience=AUTH_AUDIENCE)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def access_identity(access_token: AccessToken) -> dict[str, Any]:
    claims = access_token.claims or {}
    username = str(claims.get("sub") or access_token.client_id or "unknown")
    scopes = list(access_token.scopes or normalize_scopes(claims.get("scope")))
    return {
        "username": username,
        "display_name": str(claims.get("name") or claims.get("preferred_username") or username),
        "client_id": access_token.client_id,
        "scopes": scopes,
    }


def require_scope(access_token: AccessToken, required_scope: str) -> OperationResult | None:
    identity = access_identity(access_token)
    if required_scope not in identity["scopes"]:
        return OperationResult(
            ok=False,
            message="Authenticated user does not have the required scope.",
            data={"required_scope": required_scope, "user_id": identity["username"], "scopes": identity["scopes"]},
        )
    return None


def safe_user_slug(username: str) -> str:
    result = []
    for ch in username.lower():
        if ch.isalnum() or ch in ["-", "_", "."]:
            result.append(ch)
        else:
            result.append("_")
    slug = "".join(result).strip("._-")
    return slug or "user"


def user_workspace_root(access_token: AccessToken) -> Path:
    identity = access_identity(access_token)
    root = (WORKSPACE_ROOT / "users" / safe_user_slug(identity["username"])).resolve()
    if root != WORKSPACE_ROOT and WORKSPACE_ROOT not in root.parents:
        raise ValueError("Resolved user workspace escapes workspace root.")
    root.mkdir(parents=True, exist_ok=True)
    return root


def relative_to_workspace(path: Path, root: Path) -> str:
    if path == root:
        return "."
    return str(path.relative_to(root))


def resolve_workspace_path(raw_path: str | None, root: Path) -> Path:
    value = "." if raw_path is None or raw_path.strip() == "" else raw_path.strip()
    candidate = Path(value)
    if candidate.is_absolute():
        raise ValueError("Use relative paths inside your workspace, not absolute paths.")
    resolved = (root / candidate).resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError("Path escapes your workspace root.")
    return resolved


def ensure_workspace_exists() -> None:
    WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
    (WORKSPACE_ROOT / "users").mkdir(parents=True, exist_ok=True)


def ensure_file_write_size(content: str) -> None:
    size = len(content.encode("utf-8"))
    if size > MAX_FILE_WRITE_BYTES:
        raise ValueError(f"Content is too large: {size} bytes > {MAX_FILE_WRITE_BYTES} bytes.")


def atomic_write_text(target: Path, content: str) -> None:
    tmp = target.with_name(f".{target.name}.tmp-{uuid.uuid4().hex}")
    tmp.write_text(content, encoding="utf-8", newline="")
    os.replace(tmp, target)


def make_entry(path: Path, root: Path) -> FileEntry:
    stat = path.stat()
    if path.is_dir():
        kind = "directory"
        size = None
    elif path.is_file():
        kind = "file"
        size = stat.st_size
    elif path.is_symlink():
        kind = "symlink"
        size = None
    else:
        kind = "other"
        size = None
    return FileEntry(path=relative_to_workspace(path, root), kind=kind, size_bytes=size)


def deny_obviously_dangerous_command(command: str) -> None:
    normalized = " ".join(command.lower().split())
    denied_fragments = [
        "rm -rf /",
        "rm -fr /",
        "mkfs",
        "dd if=",
        "shutdown",
        "reboot",
        "poweroff",
        ":(){",
        "docker ",
        "podman ",
        "mount ",
        "umount ",
        "sudo ",
        "su ",
    ]
    for fragment in denied_fragments:
        if fragment in normalized:
            raise ValueError(f"Command rejected by sandbox guard: {fragment.strip()}")


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "ok": True,
            "service": "docker-workspace-mcp",
            "workspace_root": str(WORKSPACE_ROOT),
            "users_file": str(AUTH_USERS_PATH),
            "public_base_url": PUBLIC_BASE_URL,
            "auth_issuer": AUTH_ISSUER,
            "auth_audience": AUTH_AUDIENCE,
            "mcp_endpoint": "/mcp",
            "oauth_authorization_endpoint": "/oauth/authorize",
            "oauth_token_endpoint": "/oauth/token",
        }
    )


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def protected_resource(request: Request) -> JSONResponse:
    return JSONResponse(protected_resource_metadata(external_base_url(request)))


@mcp.custom_route("/.well-known/oauth-protected-resource/mcp", methods=["GET"])
async def protected_resource_mcp(request: Request) -> JSONResponse:
    return JSONResponse(protected_resource_metadata(external_base_url(request)))


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_authorization_server(request: Request) -> JSONResponse:
    return JSONResponse(oauth_metadata(external_base_url(request)))


@mcp.custom_route("/.well-known/openid-configuration", methods=["GET"])
async def openid_configuration(request: Request) -> JSONResponse:
    return JSONResponse(oauth_metadata(external_base_url(request)))


@mcp.custom_route("/oauth/register", methods=["POST"])
async def oauth_register(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    redirect_uris = payload.get("redirect_uris") or []
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return json_error("redirect_uris must be a non-empty list", 400)
    redirect_uris = [str(uri) for uri in redirect_uris]
    invalid = [uri for uri in redirect_uris if not is_allowed_redirect_uri(uri)]
    if invalid:
        return json_error("unsupported redirect_uri", 400, invalid_redirect_uris=invalid)
    client_id = secrets.token_urlsafe(32)
    client = {
        "client_id": client_id,
        "redirect_uris": redirect_uris,
        "grant_types": payload.get("grant_types") or ["authorization_code"],
        "response_types": payload.get("response_types") or ["code"],
        "token_endpoint_auth_method": "none",
        "client_name": str(payload.get("client_name") or "ChatGPT MCP client"),
        "scope": str(payload.get("scope") or " ".join(AUTH_SUPPORTED_SCOPES)),
        "client_id_issued_at": now_ts(),
    }
    OAUTH_CLIENTS[client_id] = client
    log_event("oauth_client_registered", client_id=client_id, redirect_uris=redirect_uris)
    return JSONResponse(client, status_code=201)


@mcp.custom_route("/oauth/authorize", methods=["GET", "POST"])
async def oauth_authorize(request: Request) -> HTMLResponse | RedirectResponse | JSONResponse:
    base_url = external_base_url(request)
    if request.method == "GET":
        params = dict(request.query_params)
        return HTMLResponse(html_login_form(base_url, params))

    params = parse_form_body_sync(await request.body())
    username = params.pop("username", "")
    password = params.pop("password", "")
    client_id = params.get("client_id", "")
    redirect_uri = params.get("redirect_uri", "")
    response_type = params.get("response_type", "")
    state = params.get("state")
    code_challenge = params.get("code_challenge", "")
    code_challenge_method = params.get("code_challenge_method", "")
    resource = params.get("resource")

    if response_type != "code":
        return JSONResponse({"error": "unsupported_response_type"}, status_code=400)
    if not client_id or not redirect_uri:
        return HTMLResponse(html_login_form(base_url, params, "Missing client_id or redirect_uri."), status_code=400)
    if not code_challenge or code_challenge_method != "S256":
        return HTMLResponse(html_login_form(base_url, params, "PKCE S256 is required."), status_code=400)

    client = get_client(client_id)
    if client is None and is_allowed_redirect_uri(redirect_uri):
        client = auto_register_client(client_id, redirect_uri)
    if client is None or not client_allows_redirect(client, redirect_uri):
        return HTMLResponse(html_login_form(base_url, params, "Unknown client or redirect URI is not allowed."), status_code=400)

    user = authenticate_user(username, password)
    if user is None:
        log_event("oauth_login_failed", username=username, client_id=client_id)
        return HTMLResponse(html_login_form(base_url, params, "Invalid username or password."), status_code=401)

    user_scopes = normalize_scopes(user.get("scopes"))
    requested_scopes = normalize_scopes(params.get("scope")) or AUTH_DEFAULT_SCOPES
    unsupported_scopes = [scope for scope in requested_scopes if scope not in user_scopes]
    if unsupported_scopes:
        return oauth_error_redirect(redirect_uri, state, "access_denied", f"User is missing scopes: {' '.join(unsupported_scopes)}")

    code = secrets.token_urlsafe(32)
    OAUTH_CODES[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "scopes": requested_scopes,
        "username": str(user["username"]),
        "resource": resource,
        "expires_at": now_ts() + AUTH_CODE_TTL_SECONDS,
    }
    query = {"code": code}
    if state:
        query["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    log_event("oauth_login_success", username=user["username"], client_id=client_id, scopes=requested_scopes)
    return RedirectResponse(f"{redirect_uri}{separator}{urlencode(query)}", status_code=302)


@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request: Request) -> JSONResponse:
    params = parse_form_body_sync(await request.body())
    grant_type = params.get("grant_type", "")
    code = params.get("code", "")
    redirect_uri = params.get("redirect_uri", "")
    client_id = params.get("client_id", "")
    code_verifier = params.get("code_verifier", "")
    resource = params.get("resource")

    if grant_type != "authorization_code":
        return json_error("unsupported_grant_type", 400)
    code_record = OAUTH_CODES.pop(code, None)
    if code_record is None:
        return json_error("invalid_grant", 400, error_description="Authorization code is invalid or was already used.")
    if now_ts() > int(code_record["expires_at"]):
        return json_error("invalid_grant", 400, error_description="Authorization code has expired.")
    if client_id != code_record["client_id"] or redirect_uri != code_record["redirect_uri"]:
        return json_error("invalid_grant", 400, error_description="client_id or redirect_uri mismatch.")
    if not verify_pkce(code_verifier, str(code_record["code_challenge"])):
        return json_error("invalid_grant", 400, error_description="PKCE verification failed.")

    user = find_user(str(code_record["username"]))
    if user is None or user.get("disabled"):
        return json_error("access_denied", 403)
    scopes = list(code_record["scopes"])
    access_token = issue_access_token(user, client_id, scopes, resource or code_record.get("resource"))
    log_event("oauth_token_issued", username=user["username"], client_id=client_id, scopes=scopes)
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": AUTH_ACCESS_TOKEN_TTL_SECONDS,
            "scope": " ".join(scopes),
        }
    )


@mcp.custom_route("/oauth/revoke", methods=["POST"])
async def oauth_revoke(request: Request) -> JSONResponse:
    return JSONResponse({"ok": True})


@mcp.custom_route("/oauth/userinfo", methods=["GET"])
async def oauth_userinfo(request: Request) -> JSONResponse:
    payload = verify_bearer_token_for_http(request)
    if payload is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse(
        {
            "sub": payload.get("sub"),
            "preferred_username": payload.get("preferred_username"),
            "name": payload.get("name"),
            "scope": payload.get("scope"),
        }
    )


@mcp.tool(
    name="workspace_info",
    description="Return information about the authenticated user's Docker-contained workspace and runtime limits.",
)
def workspace_info(access_token: AccessToken = CurrentAccessToken()) -> OperationResult:
    deny = require_scope(access_token, "workspace:read")
    if deny:
        return deny
    ensure_workspace_exists()
    root = user_workspace_root(access_token)
    identity = access_identity(access_token)
    log_event("tool_call", tool="workspace_info", user_id=identity["username"], client_id=identity["client_id"])
    return OperationResult(
        ok=True,
        message="Workspace info returned.",
        data={
            "user_id": identity["username"],
            "display_name": identity["display_name"],
            "workspace_root": str(root),
            "workspace_path_policy": "All tool paths are relative to this authenticated user's workspace.",
            "scopes": identity["scopes"],
            "max_command_timeout_seconds": MAX_COMMAND_TIMEOUT_SECONDS,
            "max_command_chars": MAX_COMMAND_CHARS,
            "max_file_read_bytes": MAX_FILE_READ_BYTES,
            "max_file_write_bytes": MAX_FILE_WRITE_BYTES,
            "max_output_chars": MAX_OUTPUT_CHARS,
        },
    )


@mcp.tool(
    name="list_files",
    description="List files and directories inside the authenticated user's workspace. The path must be relative to that workspace.",
)
def list_files(path: str = ".", recursive: bool = False, max_entries: int = 200, access_token: AccessToken = CurrentAccessToken()) -> OperationResult:
    deny = require_scope(access_token, "workspace:read")
    if deny:
        return deny
    ensure_workspace_exists()
    root = user_workspace_root(access_token)
    identity = access_identity(access_token)
    target = resolve_workspace_path(path, root)
    max_entries = max(1, min(max_entries, 2000))
    log_event("tool_call", tool="list_files", user_id=identity["username"], path=path, resolved_path=str(target), recursive=recursive, max_entries=max_entries)
    if not target.exists():
        return OperationResult(ok=False, message="Path does not exist.", data={"path": path})
    if target.is_file():
        entry = make_entry(target, root)
        return OperationResult(ok=True, message="Single file returned.", data={"entries": [entry.model_dump()]})
    iterator = target.rglob("*") if recursive else target.iterdir()
    entries: list[FileEntry] = []
    truncated = False
    for item in sorted(iterator, key=lambda p: str(p).lower()):
        if len(entries) >= max_entries:
            truncated = True
            break
        try:
            resolved_item = item.resolve()
            if resolved_item != root and root not in resolved_item.parents:
                continue
            entries.append(make_entry(resolved_item, root))
        except OSError as exc:
            entries.append(FileEntry(path=str(item), kind=f"error:{exc.__class__.__name__}", size_bytes=None))
    return OperationResult(
        ok=True,
        message=f"Returned {len(entries)} entries.",
        data={"path": relative_to_workspace(target, root), "recursive": recursive, "truncated": truncated, "entries": [entry.model_dump() for entry in entries]},
    )


@mcp.tool(
    name="read_file",
    description="Read a UTF-8 text file from the authenticated user's workspace with line and byte limits.",
)
def read_file(path: str, start_line: int = 1, max_lines: int = 400, max_bytes: int = MAX_FILE_READ_BYTES, access_token: AccessToken = CurrentAccessToken()) -> OperationResult:
    deny = require_scope(access_token, "workspace:read")
    if deny:
        return deny
    ensure_workspace_exists()
    root = user_workspace_root(access_token)
    identity = access_identity(access_token)
    target = resolve_workspace_path(path, root)
    start_line = max(1, start_line)
    max_lines = max(1, min(max_lines, 5000))
    max_bytes = max(1, min(max_bytes, MAX_FILE_READ_BYTES))
    log_event("tool_call", tool="read_file", user_id=identity["username"], path=path, resolved_path=str(target), start_line=start_line, max_lines=max_lines, max_bytes=max_bytes)
    if not target.exists():
        return OperationResult(ok=False, message="File does not exist.", data={"path": path})
    if not target.is_file():
        return OperationResult(ok=False, message="Path is not a file.", data={"path": path})
    raw = target.read_bytes()
    truncated_by_bytes = len(raw) > max_bytes
    raw = raw[:max_bytes]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return OperationResult(ok=False, message="File is not valid UTF-8 text within the requested byte range.", data={"path": path, "error": str(exc)})
    lines = text.splitlines(keepends=True)
    selected = lines[start_line - 1 : start_line - 1 + max_lines]
    content = "".join(selected)
    truncated_by_lines = start_line - 1 + max_lines < len(lines)
    return OperationResult(
        ok=True,
        message="File content returned.",
        data={
            "path": relative_to_workspace(target, root),
            "size_bytes": target.stat().st_size,
            "start_line": start_line,
            "returned_lines": len(selected),
            "truncated_by_bytes": truncated_by_bytes,
            "truncated_by_lines": truncated_by_lines,
            "content": content,
        },
    )


@mcp.tool(
    name="write_file",
    description="Create or overwrite a UTF-8 text file inside the authenticated user's workspace. Parent directories are created automatically.",
)
def write_file(path: str, content: str, overwrite: bool = True, access_token: AccessToken = CurrentAccessToken()) -> OperationResult:
    deny = require_scope(access_token, "workspace:write")
    if deny:
        return deny
    ensure_workspace_exists()
    root = user_workspace_root(access_token)
    identity = access_identity(access_token)
    target = resolve_workspace_path(path, root)
    ensure_file_write_size(content)
    log_event("tool_call", tool="write_file", user_id=identity["username"], path=path, resolved_path=str(target), overwrite=overwrite, content_chars=len(content), content_bytes=len(content.encode("utf-8")))
    if target.exists() and target.is_dir():
        return OperationResult(ok=False, message="Path is a directory.", data={"path": path})
    if target.exists() and not overwrite:
        return OperationResult(ok=False, message="File already exists and overwrite=false.", data={"path": path})
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(target, content)
    return OperationResult(ok=True, message="File written.", data={"path": relative_to_workspace(target, root), "size_bytes": target.stat().st_size})


@mcp.tool(
    name="replace_in_file",
    description="Replace exact text inside a UTF-8 file in the authenticated user's workspace. Set expected_replacements to -1 to allow any positive number of replacements.",
)
def replace_in_file(path: str, old_text: str, new_text: str, expected_replacements: int = 1, access_token: AccessToken = CurrentAccessToken()) -> OperationResult:
    deny = require_scope(access_token, "workspace:write")
    if deny:
        return deny
    ensure_workspace_exists()
    root = user_workspace_root(access_token)
    identity = access_identity(access_token)
    target = resolve_workspace_path(path, root)
    log_event("tool_call", tool="replace_in_file", user_id=identity["username"], path=path, resolved_path=str(target), old_text_chars=len(old_text), new_text_chars=len(new_text), expected_replacements=expected_replacements)
    if old_text == "":
        return OperationResult(ok=False, message="old_text must not be empty.", data={"path": path})
    if not target.exists():
        return OperationResult(ok=False, message="File does not exist.", data={"path": path})
    if not target.is_file():
        return OperationResult(ok=False, message="Path is not a file.", data={"path": path})
    text = target.read_text(encoding="utf-8")
    actual = text.count(old_text)
    if expected_replacements >= 0 and actual != expected_replacements:
        return OperationResult(ok=False, message="Replacement count mismatch. File was not changed.", data={"path": path, "actual_replacements": actual, "expected_replacements": expected_replacements})
    if expected_replacements < 0 and actual == 0:
        return OperationResult(ok=False, message="old_text was not found. File was not changed.", data={"path": path})
    updated = text.replace(old_text, new_text)
    ensure_file_write_size(updated)
    atomic_write_text(target, updated)
    return OperationResult(ok=True, message="File updated.", data={"path": relative_to_workspace(target, root), "replacements": actual, "size_bytes": target.stat().st_size})


@mcp.tool(
    name="make_directory",
    description="Create a directory inside the authenticated user's workspace.",
)
def make_directory(path: str, access_token: AccessToken = CurrentAccessToken()) -> OperationResult:
    deny = require_scope(access_token, "workspace:write")
    if deny:
        return deny
    ensure_workspace_exists()
    root = user_workspace_root(access_token)
    identity = access_identity(access_token)
    target = resolve_workspace_path(path, root)
    log_event("tool_call", tool="make_directory", user_id=identity["username"], path=path, resolved_path=str(target))
    target.mkdir(parents=True, exist_ok=True)
    return OperationResult(ok=True, message="Directory exists.", data={"path": relative_to_workspace(target, root)})


@mcp.tool(
    name="delete_path",
    description="Delete a file or directory inside the authenticated user's workspace. Directories require recursive=true.",
)
def delete_path(path: str, recursive: bool = False, access_token: AccessToken = CurrentAccessToken()) -> OperationResult:
    deny = require_scope(access_token, "workspace:write")
    if deny:
        return deny
    ensure_workspace_exists()
    root = user_workspace_root(access_token)
    identity = access_identity(access_token)
    target = resolve_workspace_path(path, root)
    log_event("tool_call", tool="delete_path", user_id=identity["username"], path=path, resolved_path=str(target), recursive=recursive)
    if target == root:
        return OperationResult(ok=False, message="Refusing to delete user workspace root.", data={"path": path})
    if not target.exists():
        return OperationResult(ok=False, message="Path does not exist.", data={"path": path})
    if target.is_dir():
        if not recursive:
            return OperationResult(ok=False, message="Path is a directory. Set recursive=true to delete it.", data={"path": path})
        shutil.rmtree(target)
        return OperationResult(ok=True, message="Directory deleted.", data={"path": path})
    target.unlink()
    return OperationResult(ok=True, message="File deleted.", data={"path": path})


@mcp.tool(
    name="run_cli_command",
    description="Run a CLI command inside the authenticated user's Docker workspace using bash. The command runs as a non-root user with a timeout.",
)
def run_cli_command(command: str, working_dir: str = ".", timeout_seconds: int = 30, max_output_chars: int = MAX_OUTPUT_CHARS, access_token: AccessToken = CurrentAccessToken()) -> OperationResult:
    deny = require_scope(access_token, "workspace:exec")
    if deny:
        return deny
    ensure_workspace_exists()
    root = user_workspace_root(access_token)
    identity = access_identity(access_token)
    cwd = resolve_workspace_path(working_dir, root)
    if not cwd.exists():
        return OperationResult(ok=False, message="working_dir does not exist.", data={"working_dir": working_dir})
    if not cwd.is_dir():
        return OperationResult(ok=False, message="working_dir is not a directory.", data={"working_dir": working_dir})
    if len(command) > MAX_COMMAND_CHARS:
        return OperationResult(ok=False, message="Command is too long.", data={"command_chars": len(command), "max_command_chars": MAX_COMMAND_CHARS})
    timeout_seconds = max(1, min(timeout_seconds, MAX_COMMAND_TIMEOUT_SECONDS))
    max_output_chars = max(1000, min(max_output_chars, MAX_OUTPUT_CHARS))
    deny_obviously_dangerous_command(command)
    log_event("tool_call", tool="run_cli_command", user_id=identity["username"], command=command, working_dir=working_dir, resolved_working_dir=str(cwd), timeout_seconds=timeout_seconds, max_output_chars=max_output_chars)
    env = os.environ.copy()
    env["HOME"] = str(root)
    env["PWD"] = str(cwd)
    started_at = now_iso()
    proc = subprocess.Popen(["/bin/bash", "-lc", command], cwd=str(cwd), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(proc.pid, signal.SIGKILL)
        stdout, stderr = proc.communicate()
    finished_at = now_iso()
    stdout, stdout_truncated = truncate_text(stdout or "", max_output_chars)
    stderr, stderr_truncated = truncate_text(stderr or "", max_output_chars)
    return_code = proc.returncode
    log_event("tool_result", tool="run_cli_command", user_id=identity["username"], return_code=return_code, timed_out=timed_out, stdout_chars=len(stdout), stderr_chars=len(stderr), stdout_truncated=stdout_truncated, stderr_truncated=stderr_truncated)
    return OperationResult(
        ok=(return_code == 0 and not timed_out),
        message="Command finished." if not timed_out else "Command timed out and was killed.",
        data={
            "command": command,
            "working_dir": relative_to_workspace(cwd, root),
            "return_code": return_code,
            "timed_out": timed_out,
            "started_at": started_at,
            "finished_at": finished_at,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
        },
    )


if __name__ == "__main__":
    ensure_workspace_exists()
    log_event("server_start", host=MCP_HOST, port=MCP_PORT, workspace_root=str(WORKSPACE_ROOT), users_file=str(AUTH_USERS_PATH), public_base_url=PUBLIC_BASE_URL, auth_issuer=AUTH_ISSUER, auth_audience=AUTH_AUDIENCE, mcp_endpoint="/mcp", health_endpoint="/health")
    mcp.run(transport="http", host=MCP_HOST, port=MCP_PORT)
