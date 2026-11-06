# Argus implementation plan

Evidence-gated sequence based on [the 2026-11-06 research](research/2026-11-06-deep-search.md). Public OSS core and SDK are Apache-2.0. Cloud/Enterprise and the DataLab platform remain private; the free DataLab SDK contains client/demo source only. All stages below require review and clean-commit evidence; a repository or plan is not a completed capability.

| Milestone | Deliverable and acceptance | Current position |
| --- | --- | --- |
| M0 — trustworthy wire contracts | Strict receipt types/required fields; valid PASS and FAIL roundtrip; null/duplicates/aliases/unknowns rejected by CLI; permanent actual-schema regression and date-time checking. Worker identity/provenance remains a separate gate. | Public fix and tests in this change; final clean-SHA verification required. |
| M1a — local final audit | Versioned expected plan, independently pinned digest, exact source/run binding, mandatory stage completeness, bounded local evidence hashes, escaped Markdown; positive/negative offline tests and exit codes. No project command execution. | Implemented in this change; see audit contract. |
| M1b — one real project/CI profile | Reviewed allowlisted commands in disposable worker; typed observations from actual tool parsers, no exit-only/no-test PASS. Real failure, skip, cancellation, timeout and missing artifacts produce honest report. Use Argus self-checks then the DataLab CPU workload. | Initial pinned SDK unit profile implemented separately; hosted CI and general project profiles remain open. |
| M2 — execution and delivery trust | Authenticated event/worker/artifact identity; immutable snapshot; admission and quotas; attempt/fencing ownership; cancellation/worker-loss reconciliation; durable finalization and upload recovery. Fault-injection tests prove no false PASS or duplicate side effects. | OPEN; prerequisite for hostile projects and unattended retries. |
| M3 — measured model assistance | Explicit local Ollama endpoint/model digest, resource/egress limits, structured proposals validated by policy; search/LLM/hybrid regression experiment with fixed budget, seeds and independent oracles. Offline core still works without a model. | NOT_RUN. |
| M4 — DataLab complete CPU vertical slice | SDK/API submission → real CP/DP execution → dataset/split → trained artifact/metrics → inference → userspace; disposable DB/object store; leakage/quality/corruption/auth negatives; measured runtime envelope. | Local CPU smoke exists separately; service/userspace E2E NOT_RUN. |
| M5 — SDK/MCP/provider compatibility | Publish reviewed task/run/report contracts in SDK; local/remote auth boundaries; initially read-only MCP status/report, then authorized idempotent submission. Adapter conformance for GitHub Actions, GitLab CI, Jenkins, Zuul and K8s Jobs/Helm. Each has failure/cancel/runner-loss tests. | Schema-bundle SDK exists; network/MCP/providers NOT_IMPLEMENTED. |
| M6 — managed Cloud/Enterprise | Capacity and isolation tests, tenant controls, cost/budget limits, secrets, backup/restore, audit retention, rollout/rollback and operational ownership. Production promotion binds approved artifact/source, policy and authorized identity. | Design only. No deployment/SLA claim. |
| M7 — model/data/device expansion | Per-profile license/data rights, baseline quality, reproducibility, compression/latency/memory/energy methodology and supported device matrix. No hidden CPU/cloud fallback. | Target; no all-model/all-device guarantee. |

## Immediate acceptance for this change

1. Strict receipt regression runs through public Decode+Verify, the CLI and the actual published JSON Schema. Keep runtime dependencies unchanged; schema checker dependencies are explicit test-only pins.
2. `argus audit` returns 0 only for a complete locally consistent PASS, 1 for complete known FAIL, 2 for blocked/invalid input and 4 for UNCERTAIN. Missing and untrusted evidence never becomes PASS.
3. Report source, expected plan digest, results digest, per-stage reported/assessed state, check count and evidence references. Do not embed artifact bodies or grant production permission.
4. Full offline entrypoint (tests/race/vet/isolation probes), schema check, fixture CLI smoke, changed-source scan and independent review run on a clean final commit. Historical and candidate results are labelled separately.
5. Publish a narrow Draft PR. Keep old private R&D claims and existing DataLab PRs untouched; no automatic merge, rollout, runner registration or paid inference.

## Follow-on design work

M1b starts with one profile, not an arbitrary shell API. The trusted controller must approve source and mandatory stages before execution. Record actual tool versions, parser results and counts; no findings is distinct from no scanner run. Persist one terminal result per accepted attempt. Any later retry requires scoped ownership and reconciliation of prior unknown effects. A finalizer outside the failed runner can synthesize missing-stage evidence from a retained plan; that durable supervisor is not part of M1a.

M4 is the first cross-product acceptance workload. Public SDK changes and private platform implementation use separate PRs and releases. Public module pins may reference explicitly documented unmerged candidates, but are not evidence of production availability. Advance them deliberately after review.