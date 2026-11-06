# Implementation status

Public experimental core. Production/beta: NO-GO.

- IMPLEMENTED: synthetic CLI/fake model/closed operation catalog/fixed-fixture worker, local ledger and optional caller-supplied Temporal adapter.
- IMPLEMENTED: strict receipt JSON contract and permanent wire/schema regressions; unkeyed hashes still do not authenticate producers.
- IMPLEMENTED: local audit finalization of a pinned expected plan, caller observations and bounded artifact integrity.
- IMPLEMENTED: separate datalab-sdk-unit/v1 profile for one reviewed public SDK commit and 33 unit test identities, with automatic audit.md. This is local client/mock/file-I/O testing, not DataLab service/ML/userspace E2E.
- BLOCKED: authenticated worker/artifact provenance, arbitrary or hostile projects, multi-tenant isolation, distributed fencing/reconciliation, durable recovery and host-wide quotas.
- NOT_RUN / NOT_IMPLEMENTED: live Ollama, network SDK/MCP/Cloud services, hosted provider admission/compatibility, DataLab service E2E, production and general model/hardware compatibility.
- REPOSITORY BOUNDARIES: private optional modules do not supply missing core permissions; the pinned SDK PR18 candidate remains explicitly unmerged/unreleased.

Clean-source tests and exact source hashes belong to their PR evidence. Local profile PASS is scoped to the reviewed unit suite. See [implementation plan](IMPLEMENTATION-PLAN.md), [audit contract](AUDIT-CONTRACT.md) and [SDK unit profile](SDK-UNIT-PROFILE.md).
