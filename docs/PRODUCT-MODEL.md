# Product model and current truth boundary

This document records the approved direction, not implemented services.

| Repository/product | Visibility | Boundary |
| --- | --- | --- |
| argus-open | public, Apache-2.0 | standalone OSS policy/execution/evidence core |
| argus-sdk | public, Apache-2.0 | versioned contracts, client libraries and integration surface; MCP is an AI-facing adapter |
| argus-cloud | private | planned managed compute, scheduling and team operations |
| argus-enterprise | private | planned enterprise deployment/integration, support and contractual operations |
| animus-datalab-sdk | public, Apache-2.0 | free typed client/demo for DataLab; no private server implementation |
| animus-ml-datalab | private | Enterprise ML/data platform and authorized Argus development testbed |
| argus | private | preserved R&D source, active PRs and claims |

Argus MCP is a planned interface to Cloud or self-hosted Argus, not the entire SDK and not an authorization authority. Existing public schemas do not imply an available Cloud endpoint.

Enterprise targets a governed lifecycle: inventory -> test plan -> bounded test generation/debugging -> unit/integration/ML/security/E2E/userspace -> evidence -> authorized production promotion -> observation/rollback. Required stages are explicit; missing execution blocks acceptance. Production authorization remains separate.

The DataLab SDK is free client software. A managed training pilot may require a separate service agreement, capacity and explicit budget approval. No billing, public endpoint or SLA is enabled by this split.

A local synthetic/CPU smoke and paid managed training are different profiles. Model selection, revision, license, compression method, quality floor and hardware/runtime support must be measured. No universal-device training or 'maximum compression with no loss' guarantee is made.
