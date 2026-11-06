# Security boundary

Argus is experimental and not approved for beta or production.

The existing worker accepts only fixed synthetic fixture bytes. A separate local SDK unit profile accepts one reviewed public commit and fixed driver; it does not authorize arbitrary source or commands. The fixture signing key is public test data, not tenant authentication. The local ledger requires trusted immutable parent paths and a trusted OS identity; it is not a distributed lock. Temporal activities and their queue remain trusted boundaries. Receipt hashes are integrity checks against a separately retained digest, not signatures or proof of execution.

The source object store must be trusted and stable. Namespace/process limits do not establish hostile-kernel resistance, cross-tenant isolation or host-wide capacity enforcement.

Do not initialize private modules unless independently authorized. Do not grant model-generated commands host credentials, Docker sockets or unrestricted egress.

Use GitHub private vulnerability reporting if enabled; otherwise request a private maintainer channel without posting sensitive details. No private reporting endpoint or response SLA is claimed.

The SDK unit profile additionally trusts the operator-owned Git object store, runtime and quiescent filesystem. Its typed test records share the test interpreter and are not independently authenticated. See docs/SDK-UNIT-PROFILE.md.
