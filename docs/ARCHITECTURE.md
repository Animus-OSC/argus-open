# Architecture

The implemented synthetic slice separates event verification, project registry, model provider, strict operation planning, source preparation, worker execution, local task store and receipt integrity. Go contracts live in api/v1 and schemas/. The core has no hard dependency on a CI provider or private module.

The target architecture adds independent control, reasoning, execution and integration planes. Ollama proposes; policy authorizes; workers execute; verified execution records determine scoped outcomes. MCP/CLI/provider adapters share one versioned task contract.

A separate local audit finalizer now checks a pinned expected plan, caller-collected observations and local artifact hashes, then emits Markdown. Full project execution, authenticated observation collection, real model integration and production promotion remain design work. A report must distinguish required stages, actual evidence, hypotheses, skipped checks and uncertainty.

The separate internal/profile path snapshots the reviewed public SDK python subtree with the existing isolated Git reader, verifies a SHA-256 catalog, runs a fixed driver in a bounded Linux sandbox, and feeds typed observations to the audit finalizer. It does not expand the synthetic operation catalog or create a general execution API.
