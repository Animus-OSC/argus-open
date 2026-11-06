# External adapter boundary

This separate Go module compiles against the public Argus contracts and
injects provider-neutral adapters. It does not provision a real worker, forge,
model, event verifier or tenant store. Real external-project execution remains
blocked until those adapters and isolation are independently validated.

The offline verification script compiles this module with an empty module
cache and no network; the core boundary does not require the Temporal SDK.
