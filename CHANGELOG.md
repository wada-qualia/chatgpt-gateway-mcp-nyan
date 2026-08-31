# Changelog

All notable Gateway releases are recorded here. Detailed release-specific design,
qualification, deployment and rollback evidence remains under `docs/releases/`.

## [Unreleased]

No unreleased changes are recorded at this time.

## [0.13.8] - 2026-08-31

### Added

- Production ChatGPT chat-context isolation with a durable internal context UUID
  and a four-character model-visible alias used on normal ATLAS tool calls.
- Gateway-owned `chat_context_start` and `chat_context_refresh` recovery tools,
  plus `off|optional|required` MCP presentation modes.
- Browser Extension provisional context creation, conversation binding and
  owner-scoped resolution without persisting raw ChatGPT conversation identifiers.
- Context attribution for `AgentToolCall`, `CommandSession` and `FileChangeSet`,
  with fail-closed cross-chat monitoring and file-change isolation.
- Privacy-safe chat-context Prometheus metrics and owner-scoped
  `gatewaychatcontextid` correlation for supported LUP/Langfuse flows.

### Changed

- ChatGPT Dynamic Client Registration replacement clients can inherit the
  predecessor chat-context presentation policy only after a successful same-user
  PKCE authorization-code exchange with an unambiguous connector lineage.
- A stale default replacement bearer can receive
  `MCP_PRESENTATION_REAUTH_REQUIRED`; policy inheritance remains transactional and
  occurs only during the subsequent successful OAuth token exchange.
- The MCP Connections Web UI exposes chat-context mode configuration for OAuth
  clients.

### Security

- OAuth `owner_subject` remains the authentication and authorization principal;
  the short chat-context alias is routing metadata and never an authentication
  credential.
- Raw ChatGPT conversation references are HMAC-bound at the Gateway boundary and
  are excluded from generic logs, metrics and durable lifecycle metadata.
- Short aliases, owner subjects and durable context UUIDs are excluded from
  high-cardinality Prometheus labels.
- Ambiguous DCR lineage fails closed without consuming the authorization code or
  mutating predecessor policy state.

### Operations

- Production acceptance proved real ChatGPT reauthorization, policy inheritance,
  fresh `openai-mcp/1.0.0` traffic, context bootstrap and context-bound tool calls.
- The production drift guard accepts a protected-source/runtime gap only when all
  intervening paths are documentation-only; release-impact and non-linear drift
  remain fail-closed.
- The initial `0.13.8` Jenkins deployment `#270` failed closed on a Docker test-fixture
  mismatch before candidate publication; MR `!114` corrected only the test target.
- Jenkins `#271` then released protected source `1ab1c9e9fea08bca6a41f847eafdc575ffc8a138`
  with candidate `12/12`, production `30/30`, public smoke PASS, active slot `green`,
  and immutable image id `sha256:a6543765cae546d47eddf9daa69cf4ab16bb4a2abe3c2541aea4b780c92e49a9`.

### Known limitations

- 0.13.8 does not add an operator `Chats` page, per-chat usage/statistics, or a
  chat/context column and filter to the Monitoring Web UI.
- Existing Web UI command-session, tool-call and file-change DTOs do not project
  `chat_context_id`; operator chat drill-down requires a separate reviewed API/UI
  change.
- Shared resources such as registered devices, thin clients, Docker workspaces
  and collaboration control-plane entities intentionally retain their existing
  owner/resource/room authority rather than becoming conversation-local.

Detailed release notes: `docs/releases/0.13.8/README.md`.

## [0.13.7] - 2026-08-29

Blue-green deployment and PostgreSQL migration hardening after the 2026-08-29
production API outage, including bounded migration lock behavior, candidate
settlement semantics and explicit NATS approval-network allocation.

Detailed release notes: `docs/releases/0.13.7/README.md`.

## [0.13.6] - 2026-08-26

Static-NKey NATS server-authentication contract and guarded production cutover for
the AFFiNE approval transport.

Detailed release notes: `docs/releases/0.13.6/README.md`.

Earlier detailed release records remain under `docs/releases/`.
