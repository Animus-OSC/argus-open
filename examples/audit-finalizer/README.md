# Synthetic audit-format example

Every observation and evidence file here is a labelled synthetic fixture. No real tests, security scan, ML training or E2E were performed to produce them.

After building `argus`, run from the repository root:

```sh
example="$(pwd)/examples/audit-finalizer"
argus audit --plan "$example/plan.json" \
  --plan-sha256 "$(cat "$example/plan.sha256")" \
  --results "$example/results-pass.json" --artifacts "$example/evidence" \
  --out /absolute/new-fixture-pass.md
```

This fixture returns 0. Replacing results-pass.json with results-incomplete.json returns 2 and writes a BLOCKED report with E2E NOT_RUN. Always choose a new output file. The digest stored beside this public fixture is convenient for demonstration; a real caller must independently approve/pin its plan instead of trusting a repository-supplied digest.

See [the complete trust and exit-code contract](../../docs/AUDIT-CONTRACT.md).