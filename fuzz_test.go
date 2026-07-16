package rpcert_test

import (
	"crypto/x509"
	"testing"

	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	"github.com/gmb-eudi/go-eudi-rpcert/internal/testpki"
)

// ParseWRPRC consumes untrusted wallet-request attachments and
// must never panic. Seeds: valid JWT, valid CWT,
// malformed skeletons.
func FuzzParseWRPRC(f *testing.F) {
	ca, leaf, key := wrprcSigner(f)
	chain := []*x509.Certificate{leaf, ca.Cert}
	f.Add(buildWRPRCJWT(f, chain, key, nil))
	f.Add(buildWRPRCCWT(f, chain, key, nil))              // valid CWT corpus
	f.Add([]byte("eyJ0eXAiOiJyYy13cnAramd0In0.e30.AAAA")) // near-miss typ
	f.Add([]byte("a.b.c"))
	f.Add([]byte{0xd2, 0x84}) // truncated tagged COSE_Sign1
	f.Add([]byte{0x84})
	f.Add([]byte(""))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = rpcert.ParseWRPRC(data) // must not panic
	})
}

// LoadWRPAC's hasTelephoneOtherName does a
// hand-rolled asn1.Unmarshal walk over the raw SubjectAltName extension
// bytes of an UNTRUSTED certificate chain (Go's x509 parser surfaces
// URI/email/DNS/IP GeneralNames but drops otherName, so this package parses
// the extension itself) — exactly the untrusted-parser class that requires a
// fuzz target for. Seeds cover the contact-SAN matrix (uri-only,
// email-only, phone-otherName — the one that actually walks the SAN bytes,
// and none-at-all) plus malformed near-miss byte skeletons; LoadWRPAC is
// fuzzed end-to-end (not hasTelephoneOtherName directly) so the corpus
// exercises the real untrusted-bytes entry point: ParseCertChain ->
// hasContactSAN -> hasTelephoneOtherName.
func FuzzLoadWRPAC(f *testing.F) {
	ca := testpki.NewCA(f, "TEST ACCESS CA")
	seed := func(mutate func(*testpki.CertOpts)) {
		opts := testpki.DefaultWRPAC()
		if mutate != nil {
			mutate(&opts)
		}
		leaf, _ := ca.Issue(f, opts)
		f.Add(leaf.Raw, ca.Cert.Raw)
	}
	seed(nil) // default: uri_only contact SAN
	seed(func(o *testpki.CertOpts) { o.SANURIs = nil; o.SANEmails = []string{"support@rp.example.com"} })
	seed(func(o *testpki.CertOpts) { o.SANURIs = nil; o.SANPhone = "+491234567890" }) // reaches the otherName ASN.1 walk
	seed(func(o *testpki.CertOpts) { o.SANURIs = nil; o.SANEmails = nil; o.SANPhone = "" })
	f.Add([]byte("not a certificate"), []byte(""))
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00}, []byte{0x30, 0x00}) // near-miss ASN.1 skeletons
	f.Fuzz(func(_ *testing.T, leafDER, caDER []byte) {
		_, _ = rpcert.LoadWRPAC([][]byte{leafDER, caDER}) // must not panic
	})
}
