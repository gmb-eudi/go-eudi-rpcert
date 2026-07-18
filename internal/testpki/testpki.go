// Package testpki generates the test PKI at test runtime: an access-CA
// / WRPRC-issuer CA and end-entity certificates with every TS 119 411-8
// profile knob the certificate-profile matrix mutates. No private key or certificate is
// ever committed.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// Fixed test epoch. Certificates are valid 2026-01-01..2028-01-01; the
// plan-wide test clock is 2026-07-04T10:00:00Z (fixture iat 1783155600 =
// 09:00Z the same day).
var (
	NotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	NotAfter  = time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
	Clock     = time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC)
)

var (
	oidSubjectAltName  = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTelephoneNumber = asn1.ObjectIdentifier{2, 5, 4, 20} // [X.520 §6.7.1] id-at-telephoneNumber
	oidOrganizationID  = asn1.ObjectIdentifier{2, 5, 4, 97} // [ETSI EN 319 412-1 §5.1.4] organizationIdentifier
)

// CA is an in-test certification authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

func genKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustOID(t testing.TB, ints ...uint64) x509.OID {
	t.Helper()
	oid, err := x509.OIDFromInts(ints)
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

// NewCA creates a self-signed CA (country DE — the plan's test territory).
func NewCA(t testing.TB, cn string) *CA {
	t.Helper()
	key := genKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn, Country: []string{"DE"}, Organization: []string{"WP-07 Test PKI"}},
		NotBefore:             NotBefore,
		NotAfter:              NotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{Cert: cert, Key: key}
}

// CertOpts drives the profile knobs the certificate-profile matrix mutates.
type CertOpts struct {
	CommonName string
	Country    string
	OrgID      string     // organizationIdentifier (2.5.4.97); "" = omit
	Policies   [][]uint64 // certificatePolicies: policy + entitlement OIDs
	SANURIs    []string
	SANEmails  []string
	SANPhone   string // otherName id-at-telephoneNumber (GEN-6.6.1-07)
	KeyUsage   x509.KeyUsage
	EKUs       []x509.ExtKeyUsage
	NotBefore  time.Time // zero = testpki.NotBefore
	NotAfter   time.Time // zero = testpki.NotAfter
}

// DefaultWRPAC is a fully conformant QCP-l-eudiwrp legal-person WRPAC with a
// Service_Provider entitlement (TS 119 411-8 GEN-6.6.1-03/-05/-07).
func DefaultWRPAC() CertOpts {
	return CertOpts{
		CommonName: "Example Age Check",
		Country:    "DE",
		OrgID:      "NTRDE-HRB123456",
		Policies: [][]uint64{
			{0, 4, 0, 194118, 1, 4}, // QCP-l-eudiwrp ([ETSI TS 119 411-8 §5.3])
			{0, 4, 0, 19475, 1, 1},  // Service_Provider (TS 119 475 A.2.1)
		},
		SANURIs:  []string{"https://rp.example.com/support"},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
}

// Issue creates an end-entity certificate under the CA.
func (ca *CA) Issue(t testing.TB, opts CertOpts) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := genKey(t)
	nb, na := opts.NotBefore, opts.NotAfter
	if nb.IsZero() {
		nb = NotBefore
	}
	if na.IsZero() {
		na = NotAfter
	}
	subject := pkix.Name{CommonName: opts.CommonName, Organization: []string{"Example Retail GmbH"}}
	if opts.Country != "" {
		subject.Country = []string{opts.Country}
	}
	if opts.OrgID != "" {
		subject.ExtraNames = append(subject.ExtraNames,
			pkix.AttributeTypeAndValue{Type: oidOrganizationID, Value: opts.OrgID})
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     opts.KeyUsage,
		ExtKeyUsage:  opts.EKUs,
	}
	for _, p := range opts.Policies {
		tmpl.Policies = append(tmpl.Policies, mustOID(t, p...))
	}
	if ext, ok := buildSAN(t, opts); ok {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// buildSAN assembles SubjectAltName by hand so the otherName/telephoneNumber
// GeneralName ([RFC 5280 §4.2.1.6]; TS 119 411-8 GEN-6.6.1-07) can be
// produced — Go's template fields cannot express otherName.
func buildSAN(t testing.TB, opts CertOpts) (pkix.Extension, bool) {
	t.Helper()
	var names []asn1.RawValue
	for _, u := range opts.SANURIs {
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(u)})
	}
	for _, e := range opts.SANEmails {
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte(e)})
	}
	if opts.SANPhone != "" {
		typeID, err := asn1.Marshal(oidTelephoneNumber)
		if err != nil {
			t.Fatal(err)
		}
		phone, err := asn1.MarshalWithParams(opts.SANPhone, "utf8")
		if err != nil {
			t.Fatal(err)
		}
		value, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: phone})
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(typeID, value...)})
	}
	if len(names) == 0 {
		return pkix.Extension{}, false
	}
	der, err := asn1.Marshal(names) // SEQUENCE OF GeneralName
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidSubjectAltName, Value: der}, true
}

// ChainDER returns the raw chain (leaf first) for rpcert.LoadWRPAC.
func ChainDER(certs ...*x509.Certificate) [][]byte {
	out := make([][]byte, len(certs))
	for i, c := range certs {
		out[i] = c.Raw
	}
	return out
}
