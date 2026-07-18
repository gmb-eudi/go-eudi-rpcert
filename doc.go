// Package rpcert implements the regulatory-identity layer of an EUDI Wallet
// relying party (verifier): WRPAC access-certificate profile checks and
// trust-anchor validation (ETSI TS 119 411-8 V1.1.1), WRPRC registration
// certificates in JWT and CWT form (ETSI TS 119 475 V1.2.1), the ARF RPRC_19a
// registration reference embedded in every authorization request, and a
// typed client for the ARF TS5 v1.3 Registrar API (CIR (EU) 2025/848).
//
// Dual path: validate + attach WRPRCs where a Member State
// issues them; always embed the RegistrationRef; consume the Registrar API
// directly for onboarding verification, intended-use lifecycle monitoring
// and intermediary-linkage checks.
package rpcert
