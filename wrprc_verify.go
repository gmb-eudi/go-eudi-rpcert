package rpcert

import (
	"fmt"
	"slices"
	"time"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
	trust "github.com/gmb-eudi/go-eudi-trust"
)

// Verify validates the WRPRC end-to-end, fail closed:
//
//  1. signer chain (x5c/x5chain, leaf first) to WRPRCIssuer anchors —
//     trust anchored, never from the token; ETSI TS 119 475 GEN-5.2.1-03 (the provider's
//     signing certificate is published on a trusted list)
//  2. token signature with the leaf key via go-eudi-crypto —
//     GEN-5.2.1-04 (JAdES B-B) / GEN-5.2.1-05 (COSE per RFC 9052/9360)
//  3. validity window — GEN-5.2.4-01 iat, GEN-5.2.4-07/-08 exp ≤ iat+12mo
//  4. entitlements include ≥1 Annex A.2 entitlement — GEN-5.2.4-03
//  5. policy_id references the wrprc policy OID — OVR-6.1.3-01/-02
//
// Verify-before-trust: no payload-derived field (validity, entitlements,
// policy_id, credential list) is acted upon until the chain (1) and the
// cryptographic signature (2) both pass — the extraction that ParseWRPRC
// performed is only trustworthy after this point.
//
// Status-list state (status.status_list) is NOT checked here — services
// check it via go-statuslist; Verify only surfaces StatusRef
// (revocation is surfaced, not resolved, here).
func (r *WRPRC) Verify(src trust.AnchorSource, clock func() time.Time) error {
	if clock == nil {
		return fmt.Errorf("%w: nil clock", ErrMalformed)
	}
	if len(r.Chain) == 0 {
		return ErrChainEmpty
	}
	at := clock()
	leaf := r.Chain[0]

	// (1) chain to WRPRCIssuer anchors (territory-scoped).
	if err := chainToAnchors(leaf, r.Chain[1:], src, trust.WRPRCIssuer, at); err != nil {
		return err
	}

	// (2) signature — algorithm policy enforced inside go-eudi-crypto
	// (alg derived from the key, never from the token).
	switch r.Format {
	case FormatJWT:
		if _, _, err := eudicrypto.VerifyJWS(r.Raw, leaf.PublicKey); err != nil {
			return fmt.Errorf("%w: %v", ErrSignature, err)
		}
	case FormatCWT:
		if _, _, err := eudicrypto.VerifyCOSESign1(r.Raw, leaf.PublicKey); err != nil {
			return fmt.Errorf("%w: %v", ErrSignature, err)
		}
	default:
		return fmt.Errorf("%w: %q", ErrWRPRCFormat, r.Format)
	}

	// (3) validity — ETSI TS 119 475 GEN-5.2.4-08.
	if at.Before(r.IssuedAt) {
		return fmt.Errorf("%w: iat is in the future", ErrValidity)
	}
	if !r.ExpiresAt.IsZero() {
		if !at.Before(r.ExpiresAt) {
			return fmt.Errorf("%w: exp passed", ErrExpired)
		}
		if r.ExpiresAt.After(r.IssuedAt.AddDate(0, 12, 0)) {
			return fmt.Errorf("%w: exp later than iat + 12 months", ErrValidity)
		}
	}

	// (4) ETSI TS 119 475 GEN-5.2.4-03.
	if !slices.ContainsFunc(r.Entitlements, func(e string) bool { return knownEntitlementURIs[e] }) {
		return ErrEntitlement
	}

	// (5) ETSI TS 119 475 OVR-6.1.3-01/-02.
	if !slices.Contains(r.PolicyIDs, WRPRCPolicyOID) {
		return ErrPolicyID
	}
	return nil
}
