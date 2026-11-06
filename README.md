# Argus Open Source

**Local-first engineering automation and verifiable QA — under development.**

Argus combines provider-neutral policy, isolated execution, model-assisted planning and evidence. The open-source core is usable without Argus Cloud, Enterprise, private DataLab or the private R&D repository.

## Current implementation

This experimental public core contains an **experimental synthetic offline QA slice**: a fixed fixture event, fake model, allowlisted Python tests, a local ledger, hash-bound receipts and an optional Temporal adapter. It rejects arbitrary project code. It also provides an offline audit finalizer for caller-collected stage observations and local evidence. A separate [pinned DataLab SDK unit profile](docs/SDK-UNIT-PROFILE.md) runs 33 real stdlib tests in a disposable Linux sandbox and produces audit.md. No live Ollama integration, Cloud/MCP service, general project executor or production runtime is included.

**Production/beta: NO-GO.** See [status](docs/STATUS.md), [known limitations](docs/KNOWN-LIMITATIONS.md) and [security](SECURITY.md). An unkeyed receipt hash does not authenticate the worker. Receipt decoding rejects missing/null wire fields. This public fix was implemented independently of unpublished private work. Neither receipts nor local audit hashes authenticate workers.

## Local verification

Linux x86-64, non-root user, user/network namespaces, Bubblewrap, Python 3.12, prlimit and Go 1.26.10 are required by the exercised synthetic worker.

```sh
ARGUS_GO_BIN=/absolute/path/to/go1.26.10/bin/go ./scripts/verify-offline.sh
```

Dependencies are vendored. Verification uses a cleared environment and private network namespaces. Optional Temporal verification requires the explicitly supplied digest-pinned development CLI; see [operations](docs/OPERATIONS.md).

## Components and submodules

- `modules/sdk` — public Argus SDK contracts.
- `examples/datalab-sdk` — free public DataLab client/demo.
- `modules/cloud`, `modules/enterprise`, `testbeds/datalab`, `research/argus-rd` — optional private repositories.

Initialize public modules:

```sh
python3 scripts/bootstrap_modules.py
```

Private modules default to `update = none`. Authorized operators may opt in with `--with-private`; access is enforced by GitHub. Private modules are not required for the core build or default public bootstrap. Private nested submodules are intentionally not recursively initialized.

Start with [the research and implementation plan](docs/IMPLEMENTATION-PLAN.md) and [audit CLI contract](docs/AUDIT-CONTRACT.md).

See [repository boundaries](docs/REPOSITORIES.md), [product model](docs/PRODUCT-MODEL.md) and [roadmap](docs/ROADMAP.md).

## License

Argus first-party source is Apache-2.0. Vendored third-party code retains its original licenses and notices. Private submodule repositories are independently governed and are not relicensed by this repository.
