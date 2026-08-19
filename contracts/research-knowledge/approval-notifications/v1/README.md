# AFFiNE approval notification contract v1

This contract is the versioned Gateway -> AFFiNE projection boundary for automated research-document approvals. Gateway remains authoritative for approval eligibility, quorum, permits and receipts; AFFiNE owns document ACL/data and the reviewer notification UI.

Transport: existing Gateway transactional outbox and NATS JetStream. The event is at-least-once; consumers MUST deduplicate by event_id and MUST NOT interpret notification state as authorization.

Canonical event: gateway.affine.approval.projected.v1

Canonical payload schema: ../../../../schemas/gateway.affine.approval.projected.v1.schema.json

Commands travel in the opposite direction through the canonical Gateway REST vote API, not through this event stream. Raw tool arguments, credentials and unrestricted document bodies are outside this contract.
