#!/usr/bin/env bash
set -euo pipefail

health_timeout_seconds="${HEALTH_TIMEOUT_SECONDS:-120}"
url_timeout_seconds="${URL_TIMEOUT_SECONDS:-90}"

read_env_value() {
  local key="$1"
  if [ -n "${!key:-}" ]; then
    printf '%s' "${!key}"
    return 0
  fi
  if [ -f .env ]; then
    grep -E "^${key}=" .env | tail -n 1 | sed -E "s/^${key}=//" | sed -E 's/^"(.*)"$/\1/' | sed -E "s/^'(.*)'$/\1/"
  fi
}

set_env_value() {
  local key="$1"
  local value="$2"
  touch .env
  if grep -qE "^${key}=" .env; then
    python3 - "$key" "$value" <<'PY'
from pathlib import Path
import sys
key = sys.argv[1]
value = sys.argv[2]
path = Path('.env')
lines = path.read_text(encoding='utf-8').splitlines()
out = []
written = False
for line in lines:
    if line.startswith(f'{key}='):
        out.append(f'{key}={value}')
        written = True
    else:
        out.append(line)
if not written:
    out.append(f'{key}={value}')
path.write_text('\n'.join(out) + '\n', encoding='utf-8')
PY
  else
    printf '%s=%s\n' "$key" "$value" >> .env
  fi
}

if [ -z "$(read_env_value NGROK_AUTHTOKEN || true)" ]; then
  echo "NGROK_AUTHTOKEN is required."
  echo "zsh/Linux/macOS: export NGROK_AUTHTOKEN='your-ngrok-token' && ./scripts/start.sh"
  echo "Alternative: put NGROK_AUTHTOKEN=your-ngrok-token into .env"
  exit 1
fi

mkdir -p auth workspace
if [ ! -f auth/users.json ]; then
  printf '{\n  "users": []\n}\n' > auth/users.json
fi

if [ -z "$(read_env_value AUTH_JWT_SECRET || true)" ]; then
  secret="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(64))
PY
)"
  set_env_value AUTH_JWT_SECRET "$secret"
fi

user_count="$(python3 - <<'PY'
import json
from pathlib import Path
path = Path('auth/users.json')
try:
    data = json.loads(path.read_text(encoding='utf-8'))
    print(len(data.get('users', [])))
except Exception:
    print(0)
PY
)"

if [ "${user_count}" = "0" ]; then
  echo "No users found in auth/users.json. Create one before connecting ChatGPT:"
  echo "zsh/Linux/macOS: python3 scripts/create_user.py --username darius"
fi

docker compose up --build -d mcp-app ngrok

echo "Waiting for ngrok public HTTPS URL..."

url=""
for _ in $(seq 1 "${url_timeout_seconds}"); do
  api_json="$(curl -fsS --max-time 3 http://localhost:4040/api/tunnels 2>/dev/null || true)"
  if [ -n "${api_json}" ]; then
    url="$(printf '%s' "${api_json}" | tr -d '\n' | grep -Eo '"public_url"[[:space:]]*:[[:space:]]*"https://[^"]+"' | head -n 1 | sed -E 's/^"public_url"[[:space:]]*:[[:space:]]*"//; s/"$//' || true)"
  fi

  if [ -z "${url}" ]; then
    url="$(docker compose logs ngrok 2>&1 | grep -Eo 'https://[-a-zA-Z0-9.]+\.ngrok(-free)?\.app' | tail -n 1 || true)"
  fi

  if [ -n "${url}" ]; then
    break
  fi

  sleep 1
done

if [ -z "${url}" ]; then
  echo "ngrok public URL was not found. Current ngrok logs:"
  docker compose logs ngrok
  exit 1
fi

echo "Public URL candidate: ${url}"
echo "Writing OAuth public URL into .env and recreating mcp-app..."
set_env_value PUBLIC_BASE_URL "$url"
set_env_value AUTH_ISSUER "$url"
set_env_value AUTH_AUDIENCE "$url"

docker compose up --build -d --force-recreate mcp-app

echo "Checking public health endpoint before printing ChatGPT Connector URL..."

for _ in $(seq 1 "${health_timeout_seconds}"); do
  if curl -fsS --max-time 5 "${url}/health" >/dev/null 2>&1; then
    echo "Public URL: ${url}"
    echo "ChatGPT Connector URL: ${url}/mcp"
    echo "OAuth Protected Resource Metadata: ${url}/.well-known/oauth-protected-resource"
    echo "OAuth Authorization Server Metadata: ${url}/.well-known/oauth-authorization-server"
    echo "Health URL: ${url}/health"
    echo "Logs: docker compose logs -f mcp-app ngrok"
    exit 0
  fi
  sleep 1
done

echo "The ngrok URL appeared, but ${url}/health did not become reachable."
echo "MCP app local health check:"
curl -fsS http://localhost:8000/health || true
echo
echo "ngrok API tunnels:"
curl -fsS http://localhost:4040/api/tunnels || true
echo
echo "mcp-app logs:"
docker compose logs mcp-app
echo
echo "ngrok logs:"
docker compose logs ngrok
exit 1
