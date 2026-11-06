# Argus implementation research — 2026-11-06

Status: research and engineering decisions, not product certification. The requested DeepSearch integration was not available in the connected tool catalogue. This research used primary documentation and research papers, plus inspection of the current public source. No separate hosted DeepSearch job is claimed.

## Decisions supported by the research

### 1. Stabilize evidence before adding autonomous execution

[SLSA v1.2 verification](https://slsa.dev/spec/v1.2/verifying-artifacts) checks artifact binding, trusted builder identity, signatures and expected build parameters. A content hash alone cannot identify who executed a test. Argus must distinguish integrity, execution authenticity and authorization. The current receipts and new local audit finalizer only establish scoped consistency/integrity against independently retained inputs. Authenticated worker records and production admission remain open.

[Bubblewrap's security description](https://github.com/containers/bubblewrap#sandbox-security) makes the caller responsible for the chosen sandbox policy. Extending the fixed-fixture worker to arbitrary repository commands would change the threat model. Before doing that, Argus needs reviewed filesystem/egress/secret/process/resource boundaries, trusted immutable inputs, admission, cancellation and reconciliation. A Docker socket or privileged Kubernetes job is not a shortcut to that boundary.

**Implementation decision:** first deliver strict receipt parsing and a bounded offline finalizer. It must not run commands from a manifest or let a model determine success. The caller approves the complete expected stage list and independently pins its exact bytes.

### 2. Make the result contract independent of CI providers

GitHub's [cancellation procedure](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-cancellation) can terminate job processes. GitLab's [artifact and after_script semantics](https://docs.gitlab.com/ci/yaml/) include timeout exceptions; an after_script failure does not automatically fail a successful script. Jenkins [post conditions](https://www.jenkins.io/doc/book/pipeline/syntax/#post) provide finalization hooks. Zuul's [job cleanup configuration](https://zuul-ci.org/docs/zuul/latest/config/job.html#attr-job.post-run.cleanup) is version-sensitive and best effort during cancellation. These are adapter hooks, not a guarantee of report delivery after runner loss.

[Kubernetes Jobs](https://kubernetes.io/docs/concepts/workloads/controllers/job/) may start the same program more than once even with single completion and no Pod restart. Helm should package a backend, not define Argus semantics. [Temporal Activities](https://docs.temporal.io/activity-definition#idempotency) also require idempotency; [cancellation and execution](https://docs.temporal.io/activity-execution#cancellation) depend on worker communication and timeouts.

**Implementation decision:** manifest → scoped observations → evidence verification → Markdown. Missing required stage means incomplete/BLOCKED. Unknown side effects mean UNCERTAIN. Conflicting observations are rejected. Later adapters must preserve run/stage/attempt/fencing identity and separately report test verdict and report-delivery verdict. A durable collector/reconciler is required before promising an audit after every infrastructure failure. CI green status is not a substitute for this contract.

### 3. Keep SDK, MCP and Cloud distinct

The [MCP architecture](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture) defines context exchange, clients, servers and transports; it does not define Argus workflow or policy. MCP is one adapter to the same versioned Argus operations used by CLI and SDK. The [MCP security guidance](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) requires explicit authorization boundaries and rejects token passthrough. Session/task handles are not permission grants.

**Implementation decision:** keep public contracts and local operation usable without Cloud. Introduce read-only status/report MCP operations before task submission. Submission later needs tenant/project/resource scope, token audience validation, idempotency, budgets and authorization at execution time. Never forward a local administrator bearer to a model-selected endpoint. Cloud provides managed resources; Enterprise adds governed deployment/operations. Neither repository existence nor a submodule proves a service exists.

### 4. Use model assistance behind deterministic gates

[Ollama's API](https://docs.ollama.com/api/introduction) supports local and cloud endpoints. Local-first does not imply that every configured endpoint is local. Its [structured output documentation](https://docs.ollama.com/capabilities/structured-outputs) supports constrained JSON; valid JSON still needs independent semantic/policy validation.

[CodaMOSA (ICSE 2023)](https://www.microsoft.com/en-us/research/publication/codamosa-escaping-coverage-plateaus-in-test-generation-with-pre-trained-large-language-models/) uses LLM-generated test seeds when search-based testing stalls. [EvoSuite](https://github.com/EvoSuite/evosuite/wiki) uses evolutionary search for coverage and regression assertions. These support a measured hybrid experiment, not an assumption that adding more agents proves correctness.

**Implementation decision:** compare existing tests, random/search-based generation, LLM-only and a hybrid under equal compute/time budgets and multiple seeds. Preserve generated tests, oracle, minimized reproducer and provenance. Use requirement/invariant/reference/metamorphic oracles; regression assertions may merely preserve a bug. Measure confirmed seeded bugs, mutation score with stated limits, coverage, flaky rate and cost. Agents can propose and criticize; observed checks and reviewed policy decide the gate.

### 5. Treat ML quality, reproducibility and device support as separate claims

[PyTorch 2.8 reproducibility](https://docs.pytorch.org/docs/2.8/notes/randomness.html) does not guarantee identical results across versions, platforms or CPU/GPU. [Scikit-learn's leakage guidance](https://scikit-learn.org/stable/common_pitfalls.html) separates test data before fitting preprocessing. [TFX Evaluator](https://www.tensorflow.org/tfx/guide/evaluator) supports predefined quality and baseline comparisons; [TFDV](https://www.tensorflow.org/tfx/data_validation/get_started#checking_data_skew_and_drift) treats skew/drift as statistical checks.

[TorchAO workflow support](https://docs.pytorch.org/ao/stable/workflows/index.html) and [ExecuTorch export paths](https://docs.pytorch.org/executorch/stable/llm/export-llm.html) vary by workflow, hardware and backend. These moving documents must be pinned to the selected implementation version before adopting an export recipe. The current CPU pilot's PyTorch 2.8 runtime must not silently follow a later library's example.

**Implementation decision:** retain source/data/split/config/model/runtime identities, seeds and deterministic settings. Freeze baseline/evaluation data and thresholds before candidate evaluation; record slices/sample sizes. Verify contaminated-data negative controls. Compression creates a separately identified derived artifact, with measured size, quality change, memory and latency on each supported device/runtime pair. Local inference and local training are separate capabilities. Choose a pilot model using recorded popularity metrics, license, resource envelope and task quality at selection time; no model or universal-device claim is approved here.

[Linux powercap/RAPL](https://docs.kernel.org/power/powercap/powercap.html) counters have hardware scopes. Missing/reset/unavailable counters mean measured=false and joules=null, not zero. Likewise an uninstrumented egress field is not a measured privacy guarantee.

### 6. Use DataLab as the acceptance workload, while preserving product boundaries

Public DataLab SDK remains a free client/demo; managed training may be paid and private platform source stays private. A local CPU model smoke test is useful but does not prove the SDK → Control Plane → Data Plane → database/object-store → model artifact → userspace path. No private source or operational evidence is published with this research.

**Acceptance profile:** one licensed small CPU workload, immutable dataset/split, actual executor, training metrics and artifact, reproducible inference, negative policy/data/artifact cases, API and userspace E2E. Exercise independent PostgreSQL/object-store services in a disposable environment. Disabled executors, synthetic heartbeats, skipped E2E and unavailable measurement must remain visible. Extend to other model families, data types and devices only after separate profiles pass.

## Alternatives and limits

A single full-privilege multi-agent executor would create the broadest trust and debugging surface before the result contract is stable; defer it. Provider-specific workflows without a shared contract would fragment semantics; use adapters. Making SDK equal to a hosted MCP endpoint would unnecessarily require Cloud; retain offline contracts and local CLI. Automatic production promotion requires separate artifact/identity/policy and rollback evidence; a local audit PASS cannot grant it.

This is a focused design investigation, not an exhaustive market survey or an independent cryptographic audit. Documentation was retrieved on 2026-11-06. Current library/provider behavior must be checked again when implementing each adapter. The implementation and acceptance sequence is in [the plan](../IMPLEMENTATION-PLAN.md).