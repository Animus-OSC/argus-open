# Pinned DataLab SDK unit profile

`argus run-profile` is the first real project execution profile. It runs the public DataLab SDK's reviewed stdlib unit suite, then generates `audit.md` through the shared audit contract. This is a local Linux experiment for a trusted operator, not a general project runner or hosted CI service.

## Approved scope

- Profile: `datalab-sdk-unit/v1`.
- Source: public `Animus-OSC/animus-datalab-sdk`, commit `836c8dabf1899aec173ad2c240dfaa8b4968a297` (the published, unmerged PR18 candidate).
- Selected tree: all 22 files under `python/`, 116817 bytes. Root assets/docs are not executed or included in this profile.
- Additional tree identity: `sha256:2d47f977d4aabdd1f5544ef53b3fabab01584ab23fced97db6c87b7a9fdbaa83`. Algorithm: sorted relative file paths, NUL, Git executable mode 100644/100755, NUL, `sha256:` content digest, newline; SHA-256 of the concatenated UTF-8 bytes.
- Operation: Python 3.12 stdlib `unittest` discovery at fixed `/work/python/tests`, with fixed `/work/python/src` import path and the exact 33 reviewed test IDs. No shell, project-provided command, package installation, dependency download or dynamic profile registration is accepted.

The free SDK remains client/demo source. This profile does not start DataLab services, train a model, measure ML quality, call paid APIs or prove security/E2E/production readiness.

## Invocation and outputs

Use a trusted, stable, ordinary standalone Git clone with all pinned objects already available. The submodule checkout with a `.git` pointer file is deliberately unsupported by this snapshot path. Fetching source is an explicit operator/CI preparation step outside Argus; the profile never fetches or uses transports. For example, on an authorized engineering host:

```sh
git clone --no-checkout https://github.com/Animus-OSC/animus-datalab-sdk /absolute/sdk-clone
argus run-profile \
  --profile datalab-sdk-unit/v1 \
  --repo /absolute/sdk-clone \
  --source-sha 836c8dabf1899aec173ad2c240dfaa8b4968a297 \
  --run-id sdk-unit-unique-run \
  --out-dir /absolute/new-sdk-unit-run
```

The source SHA is required and must equal the approved catalog. A different revision requires a reviewed catalog change. The source checkout, object store, runtime binaries/libraries and filesystem parents are trusted and must remain stable. Dirty/untracked worktree files are not used. Git operates with private fixed config, no replacement objects or transports; the materialized committed subtree is checked against Git blobs and the additional SHA-256 pin before Python starts.

The output parent must exist and be canonical; output cannot be inside the source repository or reached through a symlink parent. Argus reserves a new 0700 output directory before source preparation. Existing output directories are rejected before launching a process. It does not overwrite, delete or automatically retry a prior attempt. Unique directory reservation is not distributed exactly-once execution or a fencing service.

Output includes `attempt.json`, independently generated `plan.json`/`plan.sha256`, source verification, bounded typed `unit-result.json` and stderr, process metadata, `results.json`, `audit.md` and a completion record binding the report hash. A failed or killed writer may leave partial artifacts; absence of a completion record must not be treated as success. Report export errors after launch return 4. Before launch they return 2. Hard-kill report delivery and recovery remain open.

## Result semantics

The trusted driver redirects test stdout into bounded stderr and emits one typed JSON record on stdout. It records discovered test identities and one outcome per executed test, including subtest failure/error semantics. A completed positive result requires the expected identities, no skipped/expected-failure/unexpected-success outcomes and a matching process exit code. The Go parser rejects duplicate/missing/unknown/null fields, invalid types, duplicate test IDs, malformed/trailing/oversized JSON and inconsistent completed sets.

[Python unittest](https://docs.python.org/3.12/library/unittest.html#unittest.TestResult) can report `OK` for skipped tests and treats expected failure as successful. Argus therefore inspects typed outcomes and approved test identities rather than parsing `OK` or relying only on exit 0. Test code and driver share an interpreter; this result channel is a reviewed-code boundary, not independent worker authentication.

| Condition | Result / exit |
| --- | --- |
| Exact reviewed source and all 33 unit tests complete successfully | PASS /0 |
| Complete expected suite with observed failures/errors and exit 1 | FAIL /1 |
| Unavailable/unapproved source/runtime, zero/dropped/unknown/skipped tests | BLOCKED /2 |
| Deadline/cancel, signal, truncated output, absent/malformed/partial result or contradictory exit after launch | UNCERTAIN /4 |

The report has mandatory source-snapshot and sdk-unit stages. A source refusal prevents test launch and leaves sdk-unit NOT_RUN. A sandbox refusal before process launch is BLOCKED; a launched process without a valid completion remains UNCERTAIN. A PASS applies only to this scoped SDK suite; it is not production permission.

## Execution boundary and CI use

The separate executor requires nonroot Linux amd64, Bubblewrap, Python 3.12 and the same fixed runtime library paths used by the offline tests. It has a read-only source mount, isolated user/network namespaces, no host home or sockets, cleared environment, no capabilities, no-new-privileges, and fixed CPU/address-space/process/file/output/wall limits. Threads are allowed within the new profile limit because SDK telemetry tests need them. The original byte-exact synthetic worker and its limits are unchanged.

Default limits: 20s wall, 10s CPU, 512MiB address space, 64 processes/threads, 64 open files, 1MiB file size, 16MiB tmpfs, no core dump; stdout 64KiB and stderr 128KiB. Cancel/deadline kills the process group and bounds teardown. These controls are not host-wide quotas, cgroup accounting or proof of hostile-kernel/multi-tenant isolation. See [Bubblewrap's stated boundary](https://github.com/containers/bubblewrap#sandbox-security).

Any CI can run the same command in a disposable Linux runner and retain the output directory. Preserve the command's exit code independently of artifact upload; successful upload does not turn a failed or incomplete test run into PASS. The pinned source must be prepared separately without production credentials in the runner. Provider-specific workflow/admission/recovery adapters and hosted CI validation remain future work. Kubernetes/Helm deployment and shared production Docker/cluster access are not used by this profile.

## Explicit integration acceptance

The ordinary offline entrypoint remains independent of a downloaded SDK clone. The additional acceptance is explicit and never treats an absent source/runtime as a skipped PASS:

```sh
ARGUS_GO_BIN=/absolute/go1.26.10/bin/go \
ARGUS_PROFILE_SDK_REPO=/absolute/sdk-clone \
./scripts/verify-sdk-profile.sh
```

It runs the real pinned source through snapshot, sandbox, typed assessment and Markdown, plus controlled failure/skip/empty-result/timeout/cancel scenarios. Fault injection replaces only the trusted test driver inside tagged Go tests; production CLI has no driver/source override flag. These deliberately failing scenarios prove result handling and do not claim that the unchanged SDK itself failed. Test-only override APIs are unexported. The script uses a cleared environment/private network namespace and refuses missing tools, wrong source and skipped acceptance. It does not fetch dependencies or register runners.
