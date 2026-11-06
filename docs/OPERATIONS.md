# Synthetic operations

Use Linux x86-64, a non-root user, Git, Bubblewrap, util-linux prlimit and Python 3.12. The worker requires /usr/bin/{git,bwrap,prlimit,python3.12}, /usr/lib/python3.12, /usr/lib/x86_64-linux-gnu and /usr/lib64.

Run ARGUS_GO_BIN=/absolute/path/to/go1.26.10/bin/go ./scripts/verify-offline.sh. This runs offline tests, race/vet, model/security-gate logic tests and dedicated loopback/wall-timeout probes.

Optional: ARGUS_TEMPORAL_BIN=/absolute/path/to/temporal plus ARGUS_GO_BIN ./scripts/verify-temporal.sh. The script checks Temporal CLI 1.10.0 SHA-256 6968c86c97d91d4b49e19c0c9b0842bfb5eb2d356f22b989006d1e09164eab5b and uses only a temporary loopback development server.

The CLI demo is synthetic-only. Preserve unknown-execution fences; do not delete a ledger to force a retry. There is no production reconciliation service, chat admission, GPU integration or host-wide resource authority.

## Offline audit and schema acceptance

The provider-neutral argus audit finalizes caller-collected observations without executing project code. See [contract and exit codes](AUDIT-CONTRACT.md). A local report PASS does not grant production permission.

Receipt schema acceptance is an explicit separate test-only gate, with a real date-time checker and pinned dependencies: [schema test instructions](../pkg/evidence/SCHEMA-TESTS.md). Missing tooling returns BLOCKED. It is not silently counted as part of the dependency-free offline entrypoint.

## Pinned SDK unit profile

See [SDK-UNIT-PROFILE.md](SDK-UNIT-PROFILE.md) for the fixed source, command, result semantics and explicit prepared-source integration acceptance. It uses no Cloud account or private platform module.
