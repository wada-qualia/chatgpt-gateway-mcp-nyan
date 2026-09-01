# Contributing

Contributions are welcome, especially around MCP interoperability, authorization boundaries, operator UX, observability and reproducible local deployment.

## Development setup

Backend:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

Frontend:

```bash
npm --prefix frontend ci
```

## Required checks

Before opening a pull request, run the checks that cover your change. For changes touching shared contracts or security boundaries, run all of them:

```bash
PYTHONPATH=services/gateway-api pytest -q services/gateway-api/tests
npm --prefix frontend test
npm --prefix frontend run build
git diff --check
```

If Gitleaks is installed:

```bash
gitleaks git .
```

## Security-sensitive changes

For authorization, OAuth, MCP federation, SSH, Docker, approvals, chat-context isolation, credential handling or command lifecycle changes:

- include a positive test for the intended behavior;
- include a negative/fail-closed test;
- preserve explicit resource ownership and authorization checks;
- do not weaken host-key, TLS or credential handling to make a test pass;
- treat timeout after a potentially side-effecting request as an unknown outcome until reconciled;
- never add real credentials, production topology or private host inventories to fixtures.

## Public repository boundary

Do not add private production deployment manifests, private CI/CD credentials/topology, internal-only dependency artifacts or production acceptance records to this repository.

The CLI and ChatGPT browser extension are separate repositories. Changes that only affect one of those clients should normally be made in that repository rather than copied into Gateway core.
