# go-eudi-rpcert

Regulatory identity for EUDI Wallet relying parties:

- **WRPAC** — access-certificate profile checks (ETSI TS 119 411-8 V1.1.1:
  NCP/QCP-n/l-eudiwrp policy OIDs, contact SAN, KU/EKU, entitlement OIDs)
  and chain validation against AccessCA trust anchors.
- **WRPRC** — registration certificates as JWT (JOSE `typ` `rc-wrp+jwt`) or
  CWT (COSE `typ` label-16 media type `application/rc-wrp+cwt`) per ETSI
  TS 119 475 V1.2.1 §5.2: issuer signature via WRPRCIssuer anchors, validity
  window (exp ≤ iat + 12 months), Annex A.2 entitlements, registered
  credential/claim extraction for scope checks.
- **RegistrationRef** — the RPRC_19a registration reference (client name,
  unique ID, registry URI, intended-use identifier) always embedded in
  authorization requests.
- **ts5** — data model + typed client for the TS5 v1.3 Registrar API
  (`GET /wrp`, `GET /wrp/{identifier}`, `GET /wrp/check-intended-use`),
  JWS-signed responses, cursor pagination, per-registry key pinning.

Framework-free: injectable HTTP doer and clock, typed errors, no logging.
All JOSE/COSE/X.509 via github.com/gmb-eudi/go-eudi-crypto; trust anchors
only via github.com/gmb-eudi/go-eudi-trust.

Status: pre-v1 (not yet tagged/published — CI resolves sibling gmb-eudi
modules once they are). Functionally, WP-07 is complete (T-07.1–T-07.9):

- `ts5` data model — golden-decode + schema-drift tests + fuzz target
  (T-07.1).
- `LoadWRPAC` profile checks: policy OID, contact SAN, KU/EKU, Annex A.2
  entitlement extraction, plus the `internal/testpki` synthetic CA builder
  reused by every later task's tests (T-07.2).
- `WRPAC.ValidateAgainst`, chaining the WRPAC to `AccessCA` trust anchors via
  `go-eudi-trust` (granted + time-valid anchors only, issuing-territory-
  then-EU order, fail closed on cache expiry or no trust path — T-07.3).
- `ParseWRPRC` + `WRPRC.Verify` for the JWT form (`rc-wrp+jwt`):
  parse-without-trust then verify-before-trust — chain to `WRPRCIssuer`
  anchors, issuer-signature check via go-eudi-crypto, validity window
  (exp ≤ iat + 12 months), Annex A.2 entitlement and wrprc policy-OID
  checks, plus registered credential/claim extraction for downstream scope
  checks (T-07.4).
- The CWT form over COSE_Sign1 (RFC 8392/9052/9360) — the same
  `ParseWRPRC`/`Verify` matrix with hardened CBOR decoding and the COSE
  `typ` label 16 carried as the full media type `application/rc-wrp+cwt`
  (T-07.5).
- `RegistrationRef` builder/serializer for the RPRC_19a registration
  reference, always embedded in built requests (T-07.6, pulled forward for
  WP-08).
- `RegistrarClient.GetWRP`/`GetWRPByID`: TS5 v1.3 `GET /wrp` +
  `GET /wrp/{identifier}`, cursor-paginated, JWS-signed-response verified
  (per-registry key pinning, `Provenance` in the report), physicalAddress/
  postalAddress rejected before it can enter a struct (T-07.7).
- `RegistrarClient.CheckIntendedUse` (JWS-signed boolean) + `IntendedUseActive`/
  `IntendedUseStatus`, the `revokedAt` monitoring predicate driving
  `err:registrar:intended-use-revoked` (T-07.8).
- `RegistrarClient.VerifyIntermediaryLinkage`: confirms via the Registrar API
  that a client's `usesIntermediary` lists the operator by identifier — the
  only way to check this (TS5 v1.3 §2.1 Note; not present in any certificate)
  — superseding `WRPAC.IsIntermediaryCapable` as the authoritative check
  (T-07.9).

See SPECREFS.md for pinned spec versions.
