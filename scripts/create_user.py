from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any

DEFAULT_SCOPES = ["workspace:read", "workspace:write", "workspace:exec"]


def hash_password(password: str, iterations: int = 390000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    digest_b64 = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"pbkdf2_sha256${iterations}${salt_b64}${digest_b64}"


def load_users(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"users": []}
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict) or not isinstance(data.get("users"), list):
        raise ValueError("users file must contain an object with a users list")
    return data


def save_users(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    with tmp.open("w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2, sort_keys=True)
        file.write("\n")
    os.replace(tmp, path)


def normalize_scopes(raw: str | None) -> list[str]:
    if raw is None or raw.strip() == "":
        return DEFAULT_SCOPES
    result = []
    for item in raw.replace(",", " ").split():
        item = item.strip()
        if item and item not in result:
            result.append(item)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Create or update a local MCP OAuth user.")
    parser.add_argument("--users-path", default=os.environ.get("AUTH_USERS_PATH", "auth/users.json"))
    parser.add_argument("--username", required=True)
    parser.add_argument("--display-name", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--scopes", default=None)
    parser.add_argument("--disabled", action="store_true")
    args = parser.parse_args()

    username = args.username.strip()
    if not username:
        raise SystemExit("username must not be empty")
    if any(ch in username for ch in ["/", "\\", "..", "\x00"]):
        raise SystemExit("username must not contain path separators, '..', or NUL")

    password = args.password
    if password is None:
        password = getpass.getpass("Password: ")
        password2 = getpass.getpass("Repeat password: ")
        if not hmac.compare_digest(password, password2):
            raise SystemExit("passwords do not match")
    if len(password) < 12:
        raise SystemExit("password must be at least 12 characters long")

    path = Path(args.users_path)
    data = load_users(path)
    users = data["users"]
    existing = None
    for user in users:
        if user.get("username") == username:
            existing = user
            break

    record = {
        "username": username,
        "display_name": args.display_name or username,
        "password_hash": hash_password(password),
        "scopes": normalize_scopes(args.scopes),
        "disabled": bool(args.disabled),
    }

    if existing is None:
        users.append(record)
        action = "created"
    else:
        existing.update(record)
        action = "updated"

    save_users(path, data)
    print(f"User {username!r} {action} in {path}")
    print(f"Scopes: {' '.join(record['scopes'])}")


if __name__ == "__main__":
    main()
