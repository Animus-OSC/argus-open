# Explicit receipt schema verification

The Go receipt wire regression tests and CLI tests run with the normal offline
verification and introduce no Python or Go runtime dependencies. They reject
required null/missing/type-invalid fields and check valid PASS and FAIL receipts,
canonical digests, duplicate/case-aliased/unknown keys, trailing data and size.

A separate, explicit test-only gate invokes the actual Draft 2020-12 JSON
Schema on the same selected corpus. It includes an active RFC3339 date-time
checker; a missing dependency, different pinned tool version or missing format
checker returns **BLOCKED / exit 2**, never a skipped PASS.

Prepare a dedicated test environment on an engineering machine with authorized
package-index access; do not install these packages into the application runtime:

```sh
python3 -m venv /absolute/path/to/schema-venv
/absolute/path/to/schema-venv/bin/python -m pip install \
  -r pkg/evidence/schema-requirements.txt
```

Then run without network, for example on Linux:

```sh
unshare --user --map-current-user --net -- \
  /absolute/path/to/schema-venv/bin/python -B scripts/verify-receipt-schema.py
```

The script only reads the checked-in schema and corpus and reports to stdout.
It does not install packages, fetch remote schema references or contact a
service. The current schema uses local references only.

The corpus records schema validity separately from Decode/Verify validity.
Schema validation does not authenticate a digest, require an independently
retained digest, or express every receipt cross-field invariant. Go tests
explicitly cover those stricter semantics. Duplicate-key and trailing-byte
checks operate on JSON encoding and are tested separately in Go.

The ordinary full-offline entrypoint remains independent of this optional
test-tool installation. An acceptance that requires schema verification must
invoke this gate explicitly and preserve its actual exit code. Tool and
download hashes from the observed environment belong in the test evidence;
version pins alone are not publisher provenance.
