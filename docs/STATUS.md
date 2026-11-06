# Implementation status

Public experimental core, after the initial repository bootstrap. Source: committed synthetic R&D candidate a540846331c2dedf0124c0c9d94d246dd5440d6c, exported without its Git history and with the public Go module path.

- IMPLEMENTED: synthetic CLI, fake model, closed operation catalog, fixed-fixture Linux worker, local ledger, hash-bound receipt, optional caller-supplied Temporal adapter.
- IMPLEMENTED IN THIS CHANGE: independently written strict receipt JSON handling and permanent regression corpus; offline audit finalizer for a pinned plan and caller-collected observations. Clean-SHA test results belong to the PR evidence, not this status list.
- BLOCKED: authenticated worker/artifact provenance, arbitrary projects, tenant/hostile-code isolation, distributed fencing, reconciliation and host-wide quota guarantees.
- NOT_RUN: live Ollama, MCP/Cloud services, full project execution/authenticated audit collection, provider runner allocation, DataLab service E2E, production and general model/hardware compatibility.
- NEW REPOSITORIES: structure and boundaries only; not a release, deployment or commercial-service availability claim.

Actual public-head checks and source hashes belong in the bootstrap evidence. Historical private R&D checks are not evidence for the renamed public module.

Research and ordered acceptance criteria: [implementation plan](IMPLEMENTATION-PLAN.md). Local audit trust boundary: [audit contract](AUDIT-CONTRACT.md). The audit finalizer does not expand the fixed-fixture worker.
