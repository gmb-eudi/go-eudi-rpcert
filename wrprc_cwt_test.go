package rpcert_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	"github.com/gmb-eudi/go-eudi-rpcert/internal/testpki"
	"github.com/gmb-eudi/go-eudi-rpcert/ts5"
	trust "github.com/gmb-eudi/go-eudi-trust"
)

// COSE header labels (RFC 9052 §3.1 alg=1; RFC 9596 typ=16; RFC 9360
// x5chain=33) — test-local mirror of the values wrprc_cwt.go pins.
const (
	hdrAlg     = int64(1)
	hdrTyp     = int64(16)
	hdrX5Chain = int64(33)
)

// buildWRPRCCWT signs claims as rc-wrp+cwt via go-eudi-crypto COSE_Sign1
// (GEN-5.2.1-05 structure per RFC 9052 + RFC 9360).
func buildWRPRCCWT(t testing.TB, chain []*x509.Certificate, key *ecdsa.PrivateKey, mutate func(map[string]any)) []byte {
	t.Helper()
	claims := baseWRPRCClaims()
	if mutate != nil {
		mutate(claims)
	}
	payload, err := cbor.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	chainBytes := make([][]byte, len(chain))
	for i, c := range chain {
		chainBytes[i] = c.Raw
	}
	protected := eudicrypto.COSEHeader{hdrTyp: "application/rc-wrp+cwt", hdrX5Chain: chainBytes}
	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"k": key})
	raw, err := eudicrypto.SignCOSESign1(context.Background(), kp, "k", protected, payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// rawSign1 mirrors COSE_Sign1 for tamper tests (test-local; the library's
// own decoder stays private).
type rawSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[any]any
	Payload     []byte
	Signature   []byte
}

// tamperCWTPayload swaps the signed payload for a broader claim set without
// re-signing — Verify must fail ErrSignature.
func tamperCWTPayload(t *testing.T, raw []byte) []byte {
	t.Helper()
	var tag cbor.RawTag
	if err := cbor.Unmarshal(raw, &tag); err != nil || tag.Number != 18 {
		t.Fatalf("expected tag-18 COSE_Sign1, err=%v", err)
	}
	var s rawSign1
	if err := cbor.Unmarshal(tag.Content, &s); err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := cbor.Unmarshal(s.Payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims["intended_use_id"] = "iu-tampered"
	p, err := cbor.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	s.Payload = p
	content, err := cbor.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	out, err := cbor.Marshal(cbor.RawTag{Number: 18, Content: content})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParseWRPRCCWTGolden(t *testing.T) {
	ca, leaf, key := wrprcSigner(t)
	raw := buildWRPRCCWT(t, []*x509.Certificate{leaf, ca.Cert}, key, nil)
	r, err := rpcert.ParseWRPRC(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.Format != rpcert.FormatCWT {
		t.Errorf("Format = %q, want cwt", r.Format)
	}
	if len(r.Chain) != 2 {
		t.Errorf("len(Chain) = %d, want 2", len(r.Chain))
	}
	if r.Subject != "NTRDE-HRB123456" || r.IntendedUseID != "iu-age-001" {
		t.Errorf("sub/intended_use_id = %q/%q", r.Subject, r.IntendedUseID)
	}
	if r.IssuedAt.Unix() != 1783155600 || r.ExpiresAt.Unix() != 1809075600 {
		t.Errorf("iat/exp = %v/%v", r.IssuedAt, r.ExpiresAt)
	}
	want := []rpcert.RegisteredCredential{
		{
			Format:         rpcert.CredentialFormatSDJWTVC,
			DoctypesOrVCTs: []string{"urn:eudi:pid:1"},
			Claims:         []ts5.ClaimPath{{"age_equal_or_over", "18"}},
		},
		{
			Format:         rpcert.CredentialFormatMdoc,
			DoctypesOrVCTs: []string{"eu.europa.ec.eudi.pid.1"},
			Claims:         []ts5.ClaimPath{{"eu.europa.ec.eudi.pid.1", "age_over_18"}},
		},
	}
	if !reflect.DeepEqual(r.RegisteredCredentials, want) {
		t.Errorf("RegisteredCredentials =\n%+v\nwant\n%+v", r.RegisteredCredentials, want)
	}
}

// WP-07 Decision 5: RFC 8392 integer keys 6 (iat) / 4 (exp) are accepted.
func TestParseWRPRCCWTIntegerTimeKeys(t *testing.T) {
	ca, leaf, key := wrprcSigner(t)
	base := baseWRPRCClaims()
	claims := make(map[any]any, len(base))
	for k, v := range base {
		claims[k] = v
	}
	delete(claims, "iat")
	delete(claims, "exp")
	claims[int64(6)] = int64(1783155600)
	claims[int64(4)] = int64(1809075600)
	payload, err := cbor.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	chainBytes := [][]byte{leaf.Raw, ca.Cert.Raw}
	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"k": key})
	raw, err := eudicrypto.SignCOSESign1(context.Background(), kp, "k",
		eudicrypto.COSEHeader{hdrTyp: "application/rc-wrp+cwt", hdrX5Chain: chainBytes}, payload)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rpcert.ParseWRPRC(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.IssuedAt.Unix() != 1783155600 || r.ExpiresAt.Unix() != 1809075600 {
		t.Errorf("iat/exp = %v/%v", r.IssuedAt, r.ExpiresAt)
	}
}

// T-07.5 acceptance: "same matrix over CWT".
func TestWRPRCVerifyCWT(t *testing.T) {
	ca, leaf, key := wrprcSigner(t)
	chain := []*x509.Certificate{leaf, ca.Cert}
	goodSrc := anchorsFor(trust.WRPRCIssuer, "DE", grantedAnchor(ca, trust.WRPRCIssuer, "DE"))

	verify := func(t *testing.T, raw []byte, src *fakeAnchors) error {
		t.Helper()
		r, err := rpcert.ParseWRPRC(raw)
		if err != nil {
			t.Fatalf("ParseWRPRC: %v", err)
		}
		return r.Verify(src, testClock)
	}

	t.Run("valid", func(t *testing.T) {
		if err := verify(t, buildWRPRCCWT(t, chain, key, nil), goodSrc); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})

	t.Run("forged_signature", func(t *testing.T) {
		otherKey := genP256(t)
		raw := buildWRPRCCWT(t, chain, otherKey, nil) // x5chain leaf ≠ signing key
		if err := verify(t, raw, goodSrc); !errors.Is(err, rpcert.ErrSignature) {
			t.Fatalf("err = %v, want ErrSignature", err)
		}
	})

	t.Run("tampered_claim_list", func(t *testing.T) {
		raw := tamperCWTPayload(t, buildWRPRCCWT(t, chain, key, nil))
		if err := verify(t, raw, goodSrc); !errors.Is(err, rpcert.ErrSignature) {
			t.Fatalf("err = %v, want ErrSignature", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		raw := buildWRPRCCWT(t, chain, key, func(c map[string]any) { c["exp"] = 1783158000 })
		if err := verify(t, raw, goodSrc); !errors.Is(err, rpcert.ErrExpired) {
			t.Fatalf("err = %v, want ErrExpired", err)
		}
	})

	t.Run("exp_beyond_12_months", func(t *testing.T) {
		raw := buildWRPRCCWT(t, chain, key, func(c map[string]any) { c["exp"] = 1817456400 })
		if err := verify(t, raw, goodSrc); !errors.Is(err, rpcert.ErrValidity) {
			t.Fatalf("err = %v, want ErrValidity", err)
		}
	})

	t.Run("no_annex_a2_entitlement", func(t *testing.T) {
		raw := buildWRPRCCWT(t, chain, key, func(c map[string]any) { c["entitlements"] = []any{} })
		if err := verify(t, raw, goodSrc); !errors.Is(err, rpcert.ErrEntitlement) {
			t.Fatalf("err = %v, want ErrEntitlement", err)
		}
	})

	t.Run("issuer_chain_not_anchored", func(t *testing.T) {
		other := testpki.NewCA(t, "OTHER CA")
		src := anchorsFor(trust.WRPRCIssuer, "DE", grantedAnchor(other, trust.WRPRCIssuer, "DE"))
		if err := verify(t, buildWRPRCCWT(t, chain, key, nil), src); !errors.Is(err, rpcert.ErrNoTrustPath) {
			t.Fatalf("err = %v, want ErrNoTrustPath", err)
		}
	})
}

func TestParseWRPRCCWTHeaderChecks(t *testing.T) {
	ca, leaf, key := wrprcSigner(t)
	chainBytes := [][]byte{leaf.Raw, ca.Cert.Raw}
	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"k": key})
	payload, err := cbor.Marshal(baseWRPRCClaims())
	if err != nil {
		t.Fatal(err)
	}
	sign := func(t *testing.T, protected eudicrypto.COSEHeader) []byte {
		t.Helper()
		raw, err := eudicrypto.SignCOSESign1(context.Background(), kp, "k", protected, payload)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	t.Run("missing_typ", func(t *testing.T) {
		raw := sign(t, eudicrypto.COSEHeader{hdrX5Chain: chainBytes})
		if _, err := rpcert.ParseWRPRC(raw); !errors.Is(err, rpcert.ErrWRPRCType) {
			t.Fatalf("err = %v, want ErrWRPRCType", err)
		}
	})

	t.Run("wrong_typ", func(t *testing.T) {
		// A valid media type (veraison requires type/subtype form for COSE
		// label 16) that is nonetheless not the WRPRC CWT typ.
		raw := sign(t, eudicrypto.COSEHeader{hdrTyp: "application/cwt", hdrX5Chain: chainBytes})
		if _, err := rpcert.ParseWRPRC(raw); !errors.Is(err, rpcert.ErrWRPRCType) {
			t.Fatalf("err = %v, want ErrWRPRCType", err)
		}
	})

	t.Run("missing_x5chain", func(t *testing.T) {
		raw := sign(t, eudicrypto.COSEHeader{hdrTyp: "application/rc-wrp+cwt"})
		if _, err := rpcert.ParseWRPRC(raw); !errors.Is(err, rpcert.ErrChainEmpty) {
			t.Fatalf("err = %v, want ErrChainEmpty", err)
		}
	})

	t.Run("truncated_cose", func(t *testing.T) {
		if _, err := rpcert.ParseWRPRC([]byte{0xd2, 0x84, 0x40}); !errors.Is(err, rpcert.ErrWRPRCFormat) {
			t.Fatalf("err = %v, want ErrWRPRCFormat", err)
		}
	})
}
