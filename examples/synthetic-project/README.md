# Independent synthetic project fixture

The offline `argus demo` copies `calculator.py` and `tests/` into a temporary,
independent Git repository, makes a deterministic synthetic commit, registers
its tenant/project policy in memory and runs the required unittest operation in
the disposable worker. The Go file embeds only those fixture files; it is not
part of the generated project. No real external repository or provider is read.

Use `--tenant`, `--project`, `--task-id` and `--idempotency-key` to exercise
different synthetic registrations. This is an example of an interface boundary,
not a live multi-user onboarding service or an authorization mechanism.
