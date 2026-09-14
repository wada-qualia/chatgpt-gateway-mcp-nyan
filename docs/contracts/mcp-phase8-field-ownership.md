# MCP Phase 8 field ownership and security contract

## Immutable Gateway-owned records

| Record | Owner | Mutability | Sensitive-field rule |
|---|---|---|---|
| Capability snapshot | Gateway backend | Append-only | Raw credentials, tokens, headers and local environment are forbidden. |
| Resource/template/prompt revision | Gateway backend | Append-only | Descriptors are sanitized before persistence; content bodies are not stored by this schema. |
| Capability event | Gateway backend | Append-only | Only bounded redacted payload plus SHA-256 is stored. |

## Mutable policy records

| Record | Owner | Allowed transitions |
|---|---|---|
| Subscription | Gateway operator/policy | active → paused/revoked |
| Root grant | Exact tenant owner/operator | pending → approved/revoked/expired |
| Sampling/elicitation consent | Exact tenant owner/operator | pending → approved/denied/expired/revoked |
| Federated task | Gateway runtime | working/input_required → completed/failed/cancelled |

## Boundaries

- `owner_subject` is mandatory on every record and is never accepted from an upstream payload.
- Root URIs and subscription URIs are represented by SHA-256 plus an optional bounded hint; raw local paths are not stored in these tables.
- Thin-client command, arguments, working directory, environment and secrets remain client-owned and are absent from capability snapshots.
- Upstream capability advertisements are observations, not authorization and not proof of Gateway support.
- Phase 8 creates no public execution route for resources, prompts, roots, sampling, elicitation, logging, completions or Tasks.
