# Known limitations

The public receipt decoder now enforces required non-nullable wire fields. Canonical hashes still do not establish producer identity or proof of execution. Production verification remains blocked by the trust gates below.

The worker only accepts byte-exact synthetic fixtures. The local event key is public. A trusted activity can self-hash fabricated evidence; hashes do not establish worker authenticity or test semantics. Ledger path checks assume trusted stable storage and do not prevent a hostile same-user race.

Private Cloud/Enterprise/DataLab modules are optional and do not supply missing core authorization. No automatic external inference, model fallback, production deployment or paid compute is enabled.

The public receipt fix is independently implemented; unpublished work in the private R&D repository was not copied.

The audit finalizer trusts caller declarations and a stable local evidence store. It checks completeness and hashes, not scanner/test semantics. A killed finalizer cannot guarantee report delivery; durable recovery, authenticated collectors, real project profiles and production promotion are still open. See AUDIT-CONTRACT.md.
