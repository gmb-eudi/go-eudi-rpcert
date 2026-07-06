package rpcert_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/gmb-eudi/go-eudi-rpcert/internal/testpki"
)

// Plan-wide test clock: 2026-07-04T10:00:00Z (fixtures use iat 09:00Z).
func testClock() time.Time { return testpki.Clock }

func genP256(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// signCompactJWS hand-rolls a compact ES256 JWS (RFC 7515 §5.1; signature
// is the raw R||S pair, 32+32 bytes for P-256 per RFC 7518 §3.4).
func signCompactJWS(t testing.TB, header map[string]any, payload []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hb) + "." + enc.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return []byte(signingInput + "." + enc.EncodeToString(sig))
}

// x5c encodes a chain per RFC 7515 §4.1.6 (standard base64 of DER).
func x5c(certs ...*x509.Certificate) []any {
	out := make([]any, len(certs))
	for i, c := range certs {
		out[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	return out
}

// baseWRPRCClaims mirrors the ETSI TS 119 475 Annex C example, adjusted to
// the plan's test identities and clock. iat = 2026-07-04T09:00:00Z
// (1783155600); exp = iat + 300 days (1809075600) — inside the 12-month
// window of GEN-5.2.4-08.
func baseWRPRCClaims() map[string]any {
	return map[string]any{
		"name":         "Example Age Check",
		"sub_ln":       "Example Retail GmbH",
		"sub":          "NTRDE-HRB123456",
		"country":      "DE",
		"registry_uri": "https://registrar.example-ms.eu/api",
		"srv_description": []any{
			[]any{map[string]any{"lang": "en", "value": "Online age verification"}},
		},
		"entitlements":   []any{"https://uri.etsi.org/19475/Entitlement/Service_Provider"},
		"privacy_policy": "https://rp.example.com/privacy",
		"info_uri":       "https://rp.example.com",
		"support_uri":    "https://rp.example.com/support",
		"supervisory_authority": map[string]any{
			"email": "dpa@example-ms.eu",
			"phone": "+491234567890",
			"uri":   "https://dpa.example-ms.eu/report",
		},
		"policy_id":          []any{"0.4.0.19475.3.1"},
		"certificate_policy": "https://wrprc-provider.example-ms.eu/cp",
		"iat":                1783155600,
		"exp":                1809075600,
		"status": map[string]any{
			"status_list": map[string]any{"idx": 42, "uri": "https://wrprc-provider.example-ms.eu/statuslists/1"},
		},
		"purpose": []any{map[string]any{"lang": "en", "value": "Proof of age for online purchase"}},
		"credentials": []any{
			map[string]any{
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
				"claim":  []any{map[string]any{"path": []any{"age_equal_or_over", "18"}}},
			},
			map[string]any{
				"format": "mso_mdoc",
				"meta":   map[string]any{"doctype_value": "eu.europa.ec.eudi.pid.1"},
				"claim":  []any{map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "age_over_18"}}},
			},
		},
		"provides_attestations": []any{
			map[string]any{
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{"https://rp.example.com/attestations/age_over_18"}},
			},
		},
		"intended_use_id": "iu-age-001",
		"public_body":     false,
		"intermediary": map[string]any{
			"sub":  "LEIXG-529900EXAMPLE0000001",
			"name": "Verifier Operator",
		},
	}
}

// buildWRPRCJWT signs claims as rc-wrp+jwt (TS 119 475 GEN-5.2.2-01) with
// the given chain; mutate edits the claim set before signing (nil = as-is).
func buildWRPRCJWT(t testing.TB, chain []*x509.Certificate, key *ecdsa.PrivateKey, mutate func(map[string]any)) []byte {
	t.Helper()
	claims := baseWRPRCClaims()
	if mutate != nil {
		mutate(claims)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]any{"typ": "rc-wrp+jwt", "alg": "ES256", "x5c": x5c(chain...)}
	return signCompactJWS(t, header, payload, key)
}

// wrprcSigner issues a WRPRC-provider signing certificate under a fresh
// WRPRC-issuer CA (country DE).
func wrprcSigner(t testing.TB) (ca *testpki.CA, leaf *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()
	ca = testpki.NewCA(t, "TEST WRPRC ISSUER CA")
	leaf, key = ca.Issue(t, testpki.CertOpts{
		CommonName: "WRPRC Provider",
		Country:    "DE",
		KeyUsage:   x509.KeyUsageDigitalSignature,
	})
	return ca, leaf, key
}
