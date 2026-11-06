# Implementation status

Initial public repository bootstrap. Source: committed synthetic R&D candidate a540846331c2dedf0124c0c9d94d246dd5440d6c, exported without its Git history and with the public Go module path.

- IMPLEMENTED: synthetic CLI, fake model, closed operation catalog, fixed-fixture Linux worker, local ledger, hash-bound receipt, optional caller-supplied Temporal adapter.
- OPEN / FAIL: strict receipt JSON contract, including null normalization. No unpublished foreign-owner receipt diff was copied.
- BLOCKED: authenticated worker/artifact provenance, arbitrary projects, tenant/hostile-code isolation, distributed fencing, reconciliation and host-wide quota guarantees.
- NOT_RUN: live Ollama, MCP/Cloud services, full project audit, provider runner allocation, DataLab service E2E, production and general model/hardware compatibility.
- NEW REPOSITORIES: structure and boundaries only; not a release, deployment or commercial-service availability claim.

Actual public-head checks and source hashes belong in the bootstrap evidence. Historical private R&D checks are not evidence for the renamed public module.
