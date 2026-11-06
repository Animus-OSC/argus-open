# Security checks

scripts/verify-offline.sh tests the offline implementation and gate logic. Mocked security.main tests do not query vulnerability databases.

scripts/security.py is separately invoked. A live Go vulnerability database query requires the explicit --allow-online-go-db flag and independent operator authorization. Without it the gate returns BLOCKED. Pinned tools, fresh database inputs and a clean checkout are required.

No fresh network vulnerability scan, upstream publisher attestation, full OS/container scan, hostile sandbox assurance or production security approval is implied by public repository creation.
