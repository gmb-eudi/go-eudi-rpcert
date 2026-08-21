package rpcert

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// Certificate policy OIDs — [ETSI TS 119 411-8 V1.1.1 §5.3] (their inclusion
// mandated by GEN-6.6.1-03): itu-t(0) identified-organization(4) etsi(0)
// eudiwrp(194118) policy-identifiers(1) {ncp-natural(1), ncp-legal(2),
// qcp-natural(3), qcp-legal(4)}.
var wrpacPolicyOIDs = []x509.OID{
	mustOID(0, 4, 0, 194118, 1, 1), // NCP-n-eudiwrp
	mustOID(0, 4, 0, 194118, 1, 2), // NCP-l-eudiwrp
	mustOID(0, 4, 0, 194118, 1, 3), // QCP-n-eudiwrp
	mustOID(0, 4, 0, 194118, 1, 4), // QCP-l-eudiwrp
}

// id-etsi-wrpa-entitlement arc — ETSI TS 119 475 V1.2.1 Annex A.1:
// itu-t(0) identified-organization(4) etsi(0) eudiwrpa(19475) entitlement(1).
// The trailing dot matters: it keeps 0.4.0.19475.10.* out of the arc.
const entitlementArcPrefix = "0.4.0.19475.1."

// Entitlement URIs — ETSI TS 119 475 V1.2.1 Annex A.2 (exhaustive; also the
// vocabulary of ARF TS5 v1.3 `entitlements`).
const (
	EntitlementServiceProvider           = "https://uri.etsi.org/19475/Entitlement/Service_Provider"
	EntitlementQEAAProvider              = "https://uri.etsi.org/19475/Entitlement/QEAA_Provider"
	EntitlementNonQEAAProvider           = "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"
	EntitlementPubEAAProvider            = "https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider"
	EntitlementPIDProvider               = "https://uri.etsi.org/19475/Entitlement/PID_Provider"
	EntitlementQCertESealProvider        = "https://uri.etsi.org/19475/Entitlement/QCert_for_ESeal_Provider"
	EntitlementQCertESigProvider         = "https://uri.etsi.org/19475/Entitlement/QCert_for_ESig_Provider"
	EntitlementRQSealCDsProvider         = "https://uri.etsi.org/19475/Entitlement/rQSealCDs_Provider"
	EntitlementRQSigCDsProvider          = "https://uri.etsi.org/19475/Entitlement/rQSigCDs_Provider"
	EntitlementESigESealCreationProvider = "https://uri.etsi.org/19475/Entitlement/ESig_ESeal_Creation_Provider"
)

// entitlementURIByOID maps Annex A.2 OIDs (children 1..10 of the arc) to
// their canonical URI form. Exhaustive; unknown arc children are rejected.
var entitlementURIByOID = map[string]string{
	"0.4.0.19475.1.1":  EntitlementServiceProvider,
	"0.4.0.19475.1.2":  EntitlementQEAAProvider,
	"0.4.0.19475.1.3":  EntitlementNonQEAAProvider,
	"0.4.0.19475.1.4":  EntitlementPubEAAProvider,
	"0.4.0.19475.1.5":  EntitlementPIDProvider,
	"0.4.0.19475.1.6":  EntitlementQCertESealProvider,
	"0.4.0.19475.1.7":  EntitlementQCertESigProvider,
	"0.4.0.19475.1.8":  EntitlementRQSealCDsProvider,
	"0.4.0.19475.1.9":  EntitlementRQSigCDsProvider,
	"0.4.0.19475.1.10": EntitlementESigESealCreationProvider,
}

// knownEntitlementURIs is the Annex A.2 URI membership set, derived from
// entitlementURIByOID's values so the two vocabularies never drift. Consumed
// by WRPRC entitlement validation (WRPRC.Verify, GEN-5.2.4-03).
var knownEntitlementURIs = func() map[string]bool {
	m := make(map[string]bool, len(entitlementURIByOID))
	for _, uri := range entitlementURIByOID {
		m[uri] = true
	}
	return m
}()

// intermediaryEntitlementURIs is intentionally EMPTY: TS 119 475 Annex A.2
// defines no intermediary entitlement and [ARF TS5 v1.3 §2.1] (Note) makes
// isIntermediary available only via the Registrar API. When a national or
// EU profile defines one, add it here; until then IsIntermediaryCapable is
// always false and RegistrarClient.VerifyIntermediaryLinkage is
// the authoritative check.
var intermediaryEntitlementURIs = map[string]bool{}

var (
	oidSubjectAltName  = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTelephoneNumber = asn1.ObjectIdentifier{2, 5, 4, 20} // [X.520 §6.7.1]
)

func mustOID(ints ...uint64) x509.OID {
	oid, err := x509.OIDFromInts(ints)
	if err != nil {
		panic(err) // static table values — programmer error only
	}
	return oid
}

// WRPAC is the operator's (or an intermediary's) wallet-relying party
// access certificate (CIR (EU) 2025/848 Art. 7 / Annex IV).
type WRPAC struct {
	Chain                 []*x509.Certificate
	Entitlements          []string
	IsIntermediaryCapable bool
}

// LoadWRPAC parses a WRPAC chain (leaf first; each element PEM or DER) and
// runs the TS 119 411-8 profile checks. Each broken element yields its own
// sentinel:
//
//   - certificatePolicies includes an eudiwrp policy OID
//     (TS 119 411-8 GEN-6.6.1-03, OIDs from [ETSI TS 119 411-8 §5.3])        → ErrPolicyOID
//   - contact SAN: URI / rfc822Name / telephone otherName
//     (TS 119 411-8 GEN-6.6.1-07 [CHOICE])               → ErrContactSAN
//   - keyUsage includes digitalSignature (
//     the WRPAC signs OID4VP request objects)            → ErrKeyUsage
//   - EKU absent, anyExtendedKeyUsage or clientAuth      → ErrExtKeyUsage
//   - entitlement OIDs under 0.4.0.19475.1 map to Annex A.2
//     URIs; unknown arc children rejected (fail closed)  → ErrUnknownEntitlement
func LoadWRPAC(chain [][]byte) (*WRPAC, error) {
	if len(chain) == 0 {
		return nil, ErrChainEmpty
	}
	var certs []*x509.Certificate
	for i, raw := range chain {
		cs, err := eudicrypto.ParseCertChain(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: chain[%d]: %w", ErrMalformed, i, err)
		}
		certs = append(certs, cs...)
	}
	leaf := certs[0]
	if !hasEudiwrpPolicy(leaf) {
		return nil, ErrPolicyOID
	}
	entitlements, err := entitlementsFromPolicies(leaf)
	if err != nil {
		return nil, err
	}
	ok, err := hasContactSAN(leaf)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrContactSAN
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, ErrKeyUsage
	}
	if err := checkEKU(leaf); err != nil {
		return nil, err
	}
	return &WRPAC{
		Chain:                 certs,
		Entitlements:          entitlements,
		IsIntermediaryCapable: isIntermediaryCapable(entitlements),
	}, nil
}

// hasEudiwrpPolicy — TS 119 411-8 GEN-6.6.1-03 [CHOICE]: at least one of
// the four [ETSI TS 119 411-8 §5.3] policy identifiers.
func hasEudiwrpPolicy(leaf *x509.Certificate) bool {
	for _, oid := range leaf.Policies {
		for _, want := range wrpacPolicyOIDs {
			if oid.Equal(want) {
				return true
			}
		}
	}
	return false
}

// entitlementsFromPolicies extracts Annex A.2 entitlements expressed as
// certificatePolicies OIDs under the id-etsi-wrpa-entitlement arc
// ([ETSI TS 119 475 §4.2] + Annex A.1; placement interpretation pinned here).
func entitlementsFromPolicies(leaf *x509.Certificate) ([]string, error) {
	var out []string
	for _, oid := range leaf.Policies {
		s := oid.String()
		if !strings.HasPrefix(s, entitlementArcPrefix) {
			continue
		}
		uri, ok := entitlementURIByOID[s]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownEntitlement, s)
		}
		out = append(out, uri)
	}
	return out, nil
}

func isIntermediaryCapable(entitlements []string) bool {
	for _, e := range entitlements {
		if intermediaryEntitlementURIs[e] {
			return true
		}
	}
	return false
}

// hasContactSAN — TS 119 411-8 GEN-6.6.1-07 [CHOICE]: SAN URI, rfc822Name,
// or otherName with type-id id-at-telephoneNumber (2.5.4.20).
func hasContactSAN(cert *x509.Certificate) (bool, error) {
	if len(cert.URIs) > 0 || len(cert.EmailAddresses) > 0 {
		return true, nil
	}
	return hasTelephoneOtherName(cert)
}

// hasTelephoneOtherName walks the raw SubjectAltName extension: Go's parser
// surfaces URI/email/DNS/IP GeneralNames but drops otherName, so the
// telephone form ([RFC 5280 §4.2.1.6] GeneralName CHOICE [0]) is parsed here.
func hasTelephoneOtherName(cert *x509.Certificate) (bool, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		var seq asn1.RawValue
		rest, err := asn1.Unmarshal(ext.Value, &seq)
		if err != nil || len(rest) != 0 || !seq.IsCompound || seq.Tag != asn1.TagSequence {
			return false, fmt.Errorf("%w: SubjectAltName extension", ErrMalformed)
		}
		data := seq.Bytes
		for len(data) > 0 {
			var gn asn1.RawValue
			data, err = asn1.Unmarshal(data, &gn)
			if err != nil {
				return false, fmt.Errorf("%w: GeneralName: %w", ErrMalformed, err)
			}
			// otherName ::= [0] { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }
			if gn.Class == asn1.ClassContextSpecific && gn.Tag == 0 && gn.IsCompound {
				var typeID asn1.ObjectIdentifier
				if _, err := asn1.Unmarshal(gn.Bytes, &typeID); err == nil && typeID.Equal(oidTelephoneNumber) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// checkEKU: EKU absent is fine; when present it must
// include anyExtendedKeyUsage or clientAuth, otherwise the certificate is
// scoped away from wallet-facing use.
func checkEKU(c *x509.Certificate) error {
	if len(c.ExtKeyUsage) == 0 && len(c.UnknownExtKeyUsage) == 0 {
		return nil
	}
	for _, e := range c.ExtKeyUsage {
		if e == x509.ExtKeyUsageAny || e == x509.ExtKeyUsageClientAuth {
			return nil
		}
	}
	return ErrExtKeyUsage
}
