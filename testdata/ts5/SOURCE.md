# Source

Synthetic fixtures hand-written against EC TS5 v1.3 (2026-02-13):
`SignedWRPArray` / `SignedWRP` / `SignedIntendedUseCheckResult` payload
schemas from `api/ts5-openapi31-registrar-api.yml`, data model from §2 and
`api/ts5-json-common-rp-data-model.json`. No real registry data, no PII.
JWS signatures are produced at test runtime with in-test generated keys
(ADR-0007: no committed keys/signatures).
