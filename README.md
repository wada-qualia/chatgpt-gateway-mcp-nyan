# ChatGPT Gateway MCP Nyan

ChatGPT Gateway MCP Nyan is an open-source control plane for connecting agent clients to tools and execution resources through MCP without treating every tool call as an unrestricted remote shell.

It provides a FastAPI gateway, a web operator UI, MCP federation, authorization and policy boundaries, audit records, chat-context isolation, long-running command sessions, SSH device access, Docker workspace access, approvals and controlled autonomy primitives.

> Agents can call tools. Production systems need a control plane.

## Why this exists

MCP makes tool integration straightforward. Operating tool access for real users and real infrastructure adds a different set of problems:

- who is allowed to invoke a tool;
- which chat or execution context owns the action;
- which resource the action is bound to;
- how long a capability remains valid;
- what happens when a request times out after a side effect may already have started;
- how operators inspect sessions, approvals and audit history;
- how multiple MCP servers can be federated without silently widening trust boundaries.

Nyan treats these as control-plane concerns rather than leaving them to individual tools.

## Core capabilities

- **MCP endpoint and federation** — expose local capabilities and federate independently operated MCP servers behind one policy boundary.
- **Chat-context isolation** — bind execution records and selected resources to an internal conversation context instead of sharing implicit state across chats.
- **SSH devices** — register SSH targets and expose bounded allowlisted actions; raw command execution is not the public default.
- **Docker workspaces** — register and operate controlled container workspaces.
- **Command sessions** — track long-running commands independently from transport timeouts and reconnects.
- **Authorization and scopes** — OAuth-oriented client access and resource-level authorization boundaries.
- **Auditability** — persistent tool, file-change and execution evidence.
- **Approvals and autonomy primitives** — explicit approval, permit and receipt concepts for higher-risk actions.
- **Operator UI** — React/Vite interface for Gateway resources and operations.
- **PostgreSQL + SQLite development mode** — production-oriented persistence with a low-friction local path.
- **NATS event plane** — optional multi-replica/event-driven coordination.

## Repository boundaries

This repository contains the public Gateway server, web UI, schemas, contracts, migrations and generic local-development configuration.

Production-specific infrastructure is intentionally not part of the public source tree. In particular, the public repository does not contain private deployment manifests, private CI/CD topology, internal host inventories, production acceptance receipts, credentials, private signing material or internal-only SDK artifacts.

Some integrations present in the private production environment depend on separately operated software and are disabled by default here. The public core does not require those integrations to start.

## Ecosystem

The user-facing clients are maintained as separate source repositories so that each component can evolve and release independently:

- **Gateway CLI / Thin Client:** https://github.com/wada-qualia/chatgpt-gateway-mcp-nyan-cli
- **ChatGPT Browser Extension:** https://github.com/wada-qualia/chatgpt-gateway-mcp-nyan-browser-extension

The CLI repository contains the source for `gateway-cli`, including local MCP bridging, browser-assisted authorization, sandboxing and update/rollback support.

The browser-extension repository contains the Manifest V3 ChatGPT integration. The extension is a client of the Gateway; it does not own Gateway authorization or server-side resource state.

## Architecture

A simplified request path is:

```text
ChatGPT / MCP client / CLI / browser extension
                    |
                    v
             Gateway OAuth/MCP
                    |
        +-----------+------------+
        |           |            |
        v           v            v
    policy       context       audit
        |           |            |
        +-----------+------------+
                    |
          capability/resource bind
                    |
        +-----------+------------+
        |                        |
        v                        v
 local execution           MCP federation
 SSH / Docker              upstream servers
```

The authority model is intentionally explicit:

```text
principal -> chat context -> capability -> resource -> action
```

A transport connection by itself is not authority.

## Quick start

### Requirements

- Docker with Compose support, or Python 3.12+ and Node.js 22
- Git

### Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

The API is then available at `http://localhost:8000` and the development web UI at `http://localhost:5173`.

Local development authentication is enabled by the example configuration. Do not expose that configuration to an untrusted network.

### Native backend

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=services/gateway-api uvicorn gateway_api.main:app --reload
```

For PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PYTHONPATH = "services/gateway-api"
uvicorn gateway_api.main:app --reload
```

### Frontend

```bash
cd frontend
npm ci
npm test
npm run dev
```

## Safe defaults

The public configuration intentionally starts conservatively:

- SSH command profile: `restricted`;
- Docker execution: disabled;
- private-network MCP upstreams: disabled;
- insecure HTTP MCP upstreams: disabled;
- chat-context HMAC mode: disabled until a key is supplied;
- controlled autonomy worker: disabled;
- external prompt registry: disabled;
- optional internal/provider integrations: disabled.

`accept-new` SSH host-key behavior is convenient for an isolated local test environment. A real deployment should pre-provision and protect its known-hosts file and use the strictest host-key lifecycle appropriate for the environment.

## Production checklist

Before exposing a Gateway outside a development machine:

1. Disable development authentication.
2. Configure an external identity provider and verify issuer/audience/scopes.
3. Replace every example secret and development database credential.
4. Use PostgreSQL and apply migrations through a controlled deployment process.
5. Pin SSH host keys and restrict device actions.
6. Keep raw command execution disabled unless the operator explicitly needs it and has an appropriate policy boundary.
7. Keep Docker disabled unless the daemon/socket boundary is intentionally delegated to Gateway.
8. Configure TLS at the ingress.
9. Restrict MCP upstream networks and validate each upstream identity/contract.
10. Configure audit retention and observability.
11. Run the security and test gates described below.

## Development gates

Backend:

```bash
python -m pytest -q services/gateway-api/tests
ruff check services/gateway-api
```

Frontend:

```bash
npm --prefix frontend ci
npm --prefix frontend test
npm --prefix frontend run build
```

Secret scan:

```bash
gitleaks git .
```

Container build:

```bash
docker build -t chatgpt-gateway-mcp-nyan:local .
```

## MCP compatibility

The codebase contains compatibility and negotiation support for multiple MCP protocol eras. Capability negotiation is preferred over hard-coding behavior to a client product name. Unsupported extensions should fail closed rather than being advertised merely because an upstream dependency recognizes their names.

## Security model

Nyan is security-sensitive infrastructure. A registered tool, SSH host, container or upstream MCP server is not automatically trusted merely because it is reachable.

Important design expectations include:

- credentials stay server-side;
- browser code never receives service credentials for server-to-server integrations;
- private-network upstream access is opt-in;
- write-capable operations can be separated from read-only discovery;
- unknown outcomes after timeouts are reconciled rather than blindly retried;
- chat/context metadata is treated as an authorization and attribution dimension, not as a cosmetic tag;
- approval records are distinct from execution receipts.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and deployment guidance.

## Public-source lineage

This repository is a sanitized public-source lineage derived from the production Gateway codebase. The public history intentionally excludes private operational boundaries and replaces historical test fixture strings that trigger secret scanners. It is not a byte-for-byte mirror of the private production repository.

That separation is deliberate: application source belongs here; private infrastructure, credentials, production topology and internal acceptance evidence do not.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security-sensitive changes should include tests for both the allowed path and the fail-closed path.
