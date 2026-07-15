package rpcert

import "errors"

// Sentinel errors. Services map them to err:domain:reason problem codes
// (docs/conventions.md): ErrIntendedUseRevoked →
// err:registrar:intended-use-revoked; ErrRegistrarUnavailable/-Status →
// err:registrar:unavailable; ErrWRPNotFound/ErrNotLinked →
// err:client:not-registered; ErrNoTrustPath (or a propagated
// trust.ErrCacheExpired) → err:trust:anchor-unavailable. No HTTP semantics
// here (ADR-0004); no attribute values in messages, ever (hard rule 3).
// NOTE: this var block is the complete sentinel set for the whole library.
// WP-07 Tasks 4/5/9 (WRPRC/registrar linkage) consume the sentinels already
// declared below — do not redefine ErrRegistrationRef or replace this file.
var (
	ErrMalformed = errors.New("rpcert: malformed input")

	// WRPAC profile checks (ETSI TS 119 411-8 §6.6.1 / TS 119 475 Annex A)
	ErrChainEmpty         = errors.New("rpcert: certificate chain is empty")
	ErrPolicyOID          = errors.New("rpcert: no eudiwrp certificate policy OID (TS 119 411-8 GEN-6.6.1-03)")
	ErrContactSAN         = errors.New("rpcert: no contact SAN - URI, email or telephone otherName (TS 119 411-8 GEN-6.6.1-07)")
	ErrKeyUsage           = errors.New("rpcert: keyUsage lacks digitalSignature (WP-07 Decision 3)")
	ErrExtKeyUsage        = errors.New("rpcert: extended key usage restricts wallet-facing use (WP-07 Decision 3)")
	ErrUnknownEntitlement = errors.New("rpcert: unknown OID under id-etsi-wrpa-entitlement arc (TS 119 475 Annex A.2)")

	// Trust-anchor validation (fail closed — CLAUDE.md rules 6/7)
	ErrNoTrustPath = errors.New("rpcert: no chain to a valid trust anchor")

	// WRPRC (ETSI TS 119 475 §5.2 / §6.1.3)
	ErrWRPRCFormat  = errors.New("rpcert: WRPRC is neither a compact JWS nor a COSE_Sign1 (GEN-5.2.1-01)")
	ErrWRPRCType    = errors.New("rpcert: WRPRC typ header mismatch (GEN-5.2.2-01 / GEN-5.2.3-01)")
	ErrClaimMissing = errors.New("rpcert: required WRPRC claim missing (GEN-5.2.4-01/-02)")
	ErrSignature    = errors.New("rpcert: WRPRC signature verification failed")
	ErrExpired      = errors.New("rpcert: WRPRC expired")
	ErrValidity     = errors.New("rpcert: WRPRC validity window violated (GEN-5.2.4-08)")
	ErrEntitlement  = errors.New("rpcert: WRPRC lacks a TS 119 475 Annex A.2 entitlement (GEN-5.2.4-03)")
	ErrPolicyID     = errors.New("rpcert: WRPRC policy_id lacks the wrprc policy OID (TS 119 475 OVR-6.1.3-01)")

	// RegistrationRef (ARF RPRC_19a / ADR-0003 decision 2)
	ErrRegistrationRef = errors.New("rpcert: incomplete registration reference")

	// ARF TS5 Registrar API client
	ErrNoRegistrarKey       = errors.New("rpcert: no verification key configured for registry")
	ErrResponseSignature    = errors.New("rpcert: registrar response JWS verification failed")
	ErrStaleResponse        = errors.New("rpcert: registrar response too old")
	ErrRegistrarStatus      = errors.New("rpcert: registrar returned an error status")
	ErrRegistrarUnavailable = errors.New("rpcert: registrar unreachable")
	ErrWRPNotFound          = errors.New("rpcert: wallet-relying party not found in registry")
	ErrPagination           = errors.New("rpcert: inconsistent pagination in registrar response")
	ErrTooManyPages         = errors.New("rpcert: registrar pagination exceeded page cap")
	ErrIntendedUseNotFound  = errors.New("rpcert: intended use not found on registered WRP")
	ErrIntendedUseRevoked   = errors.New("rpcert: intended use revoked or not yet active")
	ErrNotLinked            = errors.New("rpcert: client does not list operator as intermediary (TS5 v1.3 usesIntermediary)")
)
