module example.invalid/argus-security-negative-control

go 1.26.0

// Intentionally vulnerable test data. It is not part of Argus's module graph.
require golang.org/x/net v0.58.0
