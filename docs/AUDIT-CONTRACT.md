# Offline audit finalizer v1

`argus audit` consumes caller-collected observations and writes a new Markdown report. It neither runs project commands nor parses scanner/test logs to establish that they really ran. Use only observations collected by a trusted caller. SHA-256 checks local integrity/consistency, not worker identity, authenticity, completeness of a test suite or production readiness.

## Inputs and trust

Approve the expected plan independently of repository/model proposals. Retain its digest in the trusted caller's run record. Pass it through `--plan-sha256`; taking this value from an untrusted results file only checks self-consistency. The raw plan bytes, including whitespace, are hashed. The pinned plan binds version, run/project, repository/source commit and the complete ordered set of mandatory stages.

[Plan schema](../schemas/audit-plan-v1.schema.json) and [results schema](../schemas/audit-results-v1.schema.json) describe structure. Runtime checks also reject duplicate JSON keys, case aliases, repeated/unknown stage IDs, invalid scope, unsafe paths, control/bidi text and incomplete artifacts. Schemas alone cannot enforce these runtime rules or digest checks. Fields are exact; no extensions or retry replacement are accepted in v1. Stages use stable IDs and kinds build/static/unit/integration/security/ml/e2e/userspace/custom; kinds label observations and do not select executable commands. Existing synthetic receipts are a different contract and are not silently accepted as stage observations.

All plan stages are required. Completed PASS/FAIL records require an integer exit code, at least one executed check and at least one evidence reference. PASS requires exit 0; FAIL requires exit 1–255. For scanner profiles, checks_run counts performed checks, not findings. NOT_RUN requires checks_run=0. BLOCKED/UNCERTAIN can retain partial counts. Non-completed states require an explicit null exit code. A skipped test is not an executed check. These fields are declarations by the trusted collector; v1 does not authenticate them or infer an oracle from their names.

An absent stage appears as NOT_RUN and blocks the aggregate. A missing/changed artifact makes its stage BLOCKED, except an existing UNCERTAIN remains UNCERTAIN. The report preserves both reported and assessed state. Aggregate precedence is UNCERTAIN, then BLOCKED/NOT_RUN, then FAIL, then PASS. Thus a known FAIL is still visible when another stage prevents a complete assessment. Every aggregate other than PASS has a nonzero exit.

Evidence must reside in an explicitly supplied, trusted and quiescent local directory with trusted parents. Paths must be relative, slash-separated and clean, without dot segments, backslash, colon or symlinks (including intermediate components). The opened file must be regular. Concurrent hostile changes to that store, hostile same-user races and crash consistency are outside this contract. No archive extraction, URLs, sockets or filesystem discovery is performed.

Limits: 64 KiB plan, 1 MiB results, JSON nesting 32, 64 stages, 8 evidence references per observation, 8 MiB per artifact and 64 MiB total verified bytes per invocation. Repeated references count again. IDs are bounded ASCII; repository/summary/path strings are bounded UTF-8 without control/format characters. Runtime string limits are bytes, while JSON Schema maxLength counts characters. Invalid contract, scope or unavailable artifact root returns 2 without claiming a completed report.

## Command

Build with the pinned Go toolchain and vendored dependencies, then invoke:

```sh
argus audit \
  --plan /absolute/plan.json \
  --plan-sha256 sha256:INDEPENDENTLY_RETAINED_PLAN_DIGEST \
  --results /absolute/results.json \
  --artifacts /absolute/evidence \
  --out /absolute/new-audit.md
```

All paths are absolute. Output is created exclusively with private permissions; an existing file is not overwritten. Failed writes return 2 and can leave a partial file. There is no atomic/crash-durable publication or automatic cleanup/retry promise. Metadata is rendered as quoted code (pipes encoded) so HTML, Markdown links and bare URLs cannot become active report content. Artifact bodies are not embedded; callers remain responsible for reviewing metadata and files for secrets before any publication.

| Exit | Meaning |
| --- | --- |
| 0 | All mandatory observations report PASS and local evidence checks pass. |
| 1 | Complete assessed result includes FAIL. |
| 2 | BLOCKED/NOT_RUN, malformed input, scope/integrity/IO failure. |
| 4 | An observation reports UNCERTAIN; reconcile unknown effects before retry. |

## CI integration boundary

Providers can invoke this CLI as a report stage and retain the `.md` and input/evidence digests. Preserve its exit code separately from upload status; successful artifact upload does not make tests pass. A finalizer that runs after ordinary test failure can report missing/failed stages. If the runner or finalizer is killed, this process cannot manufacture a report elsewhere. Guaranteed collection after loss requires the planned durable supervisor and reconciler. No hosted CI adapter is implemented or certified in this change.

The [example](../examples/audit-finalizer/README.md) has synthetic PASS and incomplete observations. It proves format/CLI behavior, not project, security or ML quality.