package rpcert

import (
	"crypto/x509"
	"fmt"
	"time"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
	trust "github.com/gmb-eudi/go-eudi-trust"
)

// Trust-anchor service-status vocabulary (ETSI TS 119 612 V2.4.1 / trust-
// anchor D4): only a "granted" anchor is usable. go-eudi-trust serves
// Anchor.Status VERBATIM as the full service-status URI (…/Svcstatus/granted —
// see go-eudi-trust anchor.go "TS 119 612 service-status URI, verbatim",
// client.go and its testdata); a manual/EU-level overlay may instead carry the
// bare token. Both granted forms are accepted; everything else is rejected.
//
// The trust cache never re-filters by status (withdrawal arrives as snapshot
// replacement, not status mutation — go-eudi-trust cache.go/resolve.go), so
// this granted check is the pipeline's only status guard: a real fail-closed
// defense, not merely belt-and-braces (CLAUDE.md rule 7).
//
// Plan correction (EXECUTION.md "Consumed contracts" assumed Status=="granted"
// bare token): matching only the bare token would reject every real anchor and
// the operator's own valid WRPAC would never validate — see the
// granted_status_uri_form regression test.
const (
	anchorStatusGranted    = "granted"
	anchorStatusGrantedURI = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/" + anchorStatusGranted
)

// isGrantedStatus reports whether a TS 119 612 service-status value is
// "granted", accepting both the full service-status URI and the bare token.
func isGrantedStatus(status string) bool {
	return status == anchorStatusGranted || status == anchorStatusGrantedURI
}

// usableAnchors filters to granted, time-valid anchors (fail closed).
//
// Zero-ValidUntil handling mirrors go-eudi-trust's own canonical filter
// (CachingSource.AnchorsFor, cache.go: "if !a.ValidUntil.After(now) {
// continue }"): a ZERO ValidUntil is excluded, not treated as "never
// expires". Anchor.ValidUntil is documented "REQUIRED upstream," so a zero
// value signals malformed/incomplete anchor data, not eternal validity
// (CLAUDE.md rule 7 — fail closed on ambiguous trust data; fix-wave item 1).
func usableAnchors(anchors []trust.Anchor, at time.Time) []*x509.Certificate {
	var out []*x509.Certificate
	for _, a := range anchors {
		if a.Cert == nil || !isGrantedStatus(a.Status) {
			continue
		}
		if !a.ValidUntil.After(at) {
			continue
		}
		out = append(out, a.Cert)
	}
	return out
}

// subjectCountry returns the leaf's first subject countryName (C), or "".
func subjectCountry(c *x509.Certificate) string {
	if len(c.Subject.Country) > 0 {
		return c.Subject.Country[0]
	}
	return ""
}

// chainToAnchors validates leaf(+intermediates) against anchors of type t
// via go-eudi-crypto VerifyChain (RFC 5280 §6.1). Territory order per the
// WP-06 decision mirrored as WP-07 Decision 6: issuing territory (subject C
// of the leaf) first, then EU level (""). Anchor-source errors — including
// trust cache expiry — propagate wrapped with %w so services can map them
// to err:trust:anchor-unavailable (fail closed, CLAUDE.md rule 7).
func chainToAnchors(leaf *x509.Certificate, intermediates []*x509.Certificate, src trust.AnchorSource, t trust.AnchorType, at time.Time) error {
	countries := []string{subjectCountry(leaf)}
	if countries[0] != "" {
		countries = append(countries, "")
	}
	var lastErr error
	for _, country := range countries {
		anchors, err := src.AnchorsFor(t, country)
		if err != nil {
			return fmt.Errorf("rpcert: anchors for %s/%q: %w", t, country, err)
		}
		usable := usableAnchors(anchors, at)
		if len(usable) == 0 {
			continue
		}
		if _, err := eudicrypto.VerifyChain(leaf, intermediates, eudicrypto.ChainOptions{Anchors: usable, At: at}); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("%w: %v", ErrNoTrustPath, lastErr)
	}
	return fmt.Errorf("%w: no usable anchors", ErrNoTrustPath)
}
