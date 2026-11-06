# Known limitations

The receipt decoder's required non-nullable wire types still need hardening. Current published synthetic code may normalize JSON null for a scalar field; do not use it as a production verifier.

The worker only accepts byte-exact synthetic fixtures. The local event key is public. A trusted activity can self-hash fabricated evidence; hashes do not establish worker authenticity or test semantics. Ledger path checks assume trusted stable storage and do not prevent a hostile same-user race.

Private Cloud/Enterprise/DataLab modules are optional and do not supply missing core authorization. No automatic external inference, model fallback, production deployment or paid compute is enabled.

The public bootstrap preserves these limitations explicitly instead of applying unpublished work owned by a separate R&D task.
