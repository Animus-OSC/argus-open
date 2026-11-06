# Integrations

Implemented: public Go interfaces, synthetic adapters, optional caller-supplied Temporal adapter and a separate external-adapter example module.

Design: GitHub Actions, GitLab CI, Jenkins and Zuul adapters over a shared task/evidence contract. Kubernetes is an execution backend; Helm packages deployment. None is mandatory for the OSS core.

The public SDK is a client/contracts boundary. A future MCP server exposes bounded planning/start/status/report operations through authorized APIs; no model-selected arbitrary shell or deployment authority is implied.

DataLab is an optional private testbed. Its free SDK does not embed Control Plane, Data Plane, database migrations or platform deployment source.
