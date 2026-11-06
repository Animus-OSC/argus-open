# Architecture

The implemented synthetic slice separates event verification, project registry, model provider, strict operation planning, source preparation, worker execution, local task store and receipt integrity. Go contracts live in api/v1 and schemas/. The core has no hard dependency on a CI provider or private module.

The target architecture adds independent control, reasoning, execution and integration planes. Ollama proposes; policy authorizes; workers execute; verified execution records determine scoped outcomes. MCP/CLI/provider adapters share one versioned task contract.

Full project pipelines, final Markdown audit generation, real model integration and production promotion remain design work. A report must distinguish required stages, actual evidence, hypotheses, skipped checks and uncertainty.
