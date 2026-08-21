# AFFiNE approval notification contract v1

This contract is the versioned Gateway -> AFFiNE projection boundary for automated research-document approvals. Gateway remains authoritative for approval eligibility, quorum, permits and receipts; AFFiNE owns document ACL/data and the reviewer notification UI.

Transport: existing Gateway transactional outbox and NATS JetStream. The event is at-least-once; consumers MUST deduplicate by event_id and MUST NOT interpret notification state as authorization. Gateway additionally projects a bounded `eligible_reviewer_subjects` list computed from the same canonical vote policy; consumers may use it only for notification routing and Gateway MUST re-authorize every vote.

Canonical event: gateway.affine.approval.projected.v1

Canonical payload schema: ../../../../schemas/gateway.affine.approval.projected.v1.schema.json

Gateway additionally projects optional `eligible_reviewer_bindings` derived from an explicit one-to-one control-plane mapping of Gateway reviewer subject to native AFFiNE user id. Bindings are presentation/routing metadata only; missing mappings are reported by `unmapped_reviewer_count`, and AFFiNE MUST NOT infer authority from the mapping. Gateway re-authorizes every vote against current roles, access grants, proposer exclusion and quorum state.

Commands travel in the opposite direction through the versioned AFFiNE vote bridge at `POST /api/agent-autonomy/affine/v1/approvals/{request_id}/votes`. The REST contract is `openapi.yaml`; the signed payload contract is `affine-approval-vote-assertion.schema.json`. AFFiNE signs a short-lived method/path/request/decision/reason-bound assertion with its existing asymmetric server key; Gateway pins only the AFFiNE public key, maps `affine_user_id` back to exactly one Gateway subject, and then calls the canonical Gateway `cast_vote`. The bridge is default-OFF and does not accept a voter subject in the request body.

Gateway configuration is fail-closed. `gateway_affine_approval_reviewer_map_json` must be an explicit one-to-one subject/user mapping, `gateway_affine_approval_public_key_files` accepts at most two pinned public keys for bounded rotation, and `gateway_affine_approval_vote_bridge_enabled` must be true before assertions are accepted. The verifier accepts only P-256 ECDSA/SHA-256 or Ed25519 keys, enforces the configured assertion TTL and clock skew, checks the exact HTTP method/path/request/decision/reason binding, and rejects unmapped native identities before the canonical vote path is entered.

The AFFiNE caller is expected to target the Gateway origin directly. Its local client rejects endpoint path prefixes, query strings, fragments, embedded credentials, redirects, and implicit private-network/plain-HTTP access so that the HTTP target path remains byte-for-byte consistent with the signed assertion path.

Local Phase 6 verification on 2026-08-20 includes the contract/schema suite, one-to-one/rotation checks, cryptographic payload tamper/expiry/wrong-key tests, canonical vote-route tests, and the full Gateway backend regression. Exact-SHA CI remains the acceptance boundary for closing Phase 6; the rollout flags stay disabled until the later native review UI, reconciliation, browser/security, protected-delivery, and production configuration phases are complete.

Raw tool arguments, credentials, unrestricted document bodies, private signing keys, session secrets and execution permits are outside this contract.
