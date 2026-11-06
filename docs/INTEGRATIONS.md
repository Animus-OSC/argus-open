# Integrations

Implemented: public Go interfaces, synthetic adapters, optional caller-supplied Temporal adapter, a separate external-adapter example module and provider-neutral offline audit finalization. See [audit CLI](AUDIT-CONTRACT.md).

Design: GitHub Actions, GitLab CI, Jenkins and Zuul adapters over a shared task/evidence contract. Kubernetes is an execution backend; Helm packages deployment. None is mandatory for the OSS core.

The public SDK is a client/contracts boundary. A future MCP server exposes bounded planning/start/status/report operations through authorized APIs; no model-selected arbitrary shell or deployment authority is implied.

DataLab is an optional private testbed. Its free SDK does not embed Control Plane, Data Plane, database migrations or platform deployment source.

The [pinned SDK profile](SDK-UNIT-PROFILE.md) is a provider-neutral local/CI entrypoint producing its own audit inputs and Markdown. Actual hosted provider adapters and their failure-recovery behavior are not certified by that local command.
