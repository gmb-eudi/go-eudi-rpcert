package rpcert_test

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	"github.com/gmb-eudi/go-eudi-rpcert/internal/testpki"
	"github.com/gmb-eudi/go-eudi-rpcert/ts5"
	trust "github.com/gmb-eudi/go-eudi-trust"
)

func TestParseWRPRCJWTGolden(t *testing.T) {
	ca, leaf, key := wrprcSigner(t)
	raw := buildWRPRCJWT(t, []*x509.Certificate{leaf, ca.Cert}, key, nil)
	r, err := rpcert.ParseWRPRC(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.Format != rpcert.FormatJWT {
		t.Errorf("Format = %q, want jwt", r.Format)
	}
	if len(r.Chain) != 2 {
		t.Errorf("len(Chain) = %d, want 2", len(r.Chain))
	}
	if r.Name != "Example Age Check" || r.LegalName != "Example Retail GmbH" {
		t.Errorf("name/sub_ln = %q/%q", r.Name, r.LegalName)
	}
	if r.Subject != "NTRDE-HRB123456" || r.Country != "DE" {
		t.Errorf("sub/country = %q/%q", r.Subject, r.Country)
	}
	if r.RegistryURI != "https://registrar.example-ms.eu/api" {
		t.Errorf("registry_uri = %q", r.RegistryURI)
	}
	if r.IntendedUseID != "iu-age-001" {
		t.Errorf("intended_use_id = %q", r.IntendedUseID)
	}
	if r.IssuedAt.Unix() != 1783155600 || r.ExpiresAt.Unix() != 1809075600 {
		t.Errorf("iat/exp = %v/%v", r.IssuedAt, r.ExpiresAt)
	}
	if r.Status == nil || r.Status.Index != 42 || r.Status.URI != "https://wrprc-provider.example-ms.eu/statuslists/1" {
		t.Errorf("status = %+v", r.Status)
	}
	if len(r.Purpose) != 1 || r.Purpose[0].Lang != "en" {
		t.Errorf("purpose = %+v", r.Purpose)
	}
	if r.Intermediary == nil || r.Intermediary.Subject != "LEIXG-529900EXAMPLE0000001" || r.Intermediary.Name != "Verifier Operator" {
		t.Errorf("intermediary = %+v", r.Intermediary)
	}
	if r.PublicBody {
		t.Error("public_body = true, want false")
	}
	// Extraction feeds dcql.WithinScope: 1:1 field map
	// to dcql.RegisteredCredential.
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
	if len(r.ProvidesAttestations) != 1 || !r.ProvidesAttestations[0].AllClaims {
		t.Errorf("ProvidesAttestations = %+v (claim absent ⇒ AllClaims)", r.ProvidesAttestations)
	}
}

func TestParseWRPRCJWTHeaderAndClaims(t *testing.T) {
	ca, leaf, key := wrprcSigner(t)
	chain := []*x509.Certificate{leaf, ca.Cert}
	tests := []struct {
		name    string
		raw     func(t *testing.T) []byte
		wantErr error
	}{
		{"wrong_typ", func(t *testing.T) []byte {
			payload := []byte(`{"iat":1783155600,"sub":"NTRDE-HRB123456"}`)
			return signCompactJWS(t, map[string]any{"typ": "JWT", "alg": "ES256", "x5c": x5c(chain...)}, payload, key)
		}, rpcert.ErrWRPRCType},
		{"missing_x5c", func(t *testing.T) []byte {
			payload := []byte(`{"iat":1783155600,"sub":"NTRDE-HRB123456"}`)
			return signCompactJWS(t, map[string]any{"typ": "rc-wrp+jwt", "alg": "ES256"}, payload, key)
		}, rpcert.ErrChainEmpty},
		{"missing_alg", func(t *testing.T) []byte {
			payload := []byte(`{"iat":1783155600,"sub":"NTRDE-HRB123456"}`)
			return signCompactJWS(t, map[string]any{"typ": "rc-wrp+jwt", "x5c": x5c(chain...)}, payload, key)
		}, rpcert.ErrMalformed},
		{"missing_iat", func(t *testing.T) []byte {
			return buildWRPRCJWT(t, chain, key, func(c map[string]any) { delete(c, "iat") })
		}, rpcert.ErrClaimMissing},
		{"missing_sub", func(t *testing.T) []byte {
			return buildWRPRCJWT(t, chain, key, func(c map[string]any) { delete(c, "sub") })
		}, rpcert.ErrClaimMissing},
		{"invalid_claim_path", func(t *testing.T) []byte {
			return buildWRPRCJWT(t, chain, key, func(c map[string]any) {
				c["credentials"] = []any{map[string]any{
					"format": "dc+sd-jwt",
					"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
					"claim":  []any{map[string]any{"path": []any{true}}},
				}}
			})
		}, rpcert.ErrMalformed},
		{"not_a_jws_or_cwt", func(*testing.T) []byte { return []byte("garbage-without-dots") }, rpcert.ErrWRPRCFormat},
		{"empty", func(*testing.T) []byte { return nil }, rpcert.ErrMalformed},
		{"bad_base64_header", func(*testing.T) []byte { return []byte("!!!.AAAA.AAAA") }, rpcert.ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := rpcert.ParseWRPRC(tt.raw(t))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// Forged sig, expired, tampered claim list — fail.
func TestWRPRCVerifyJWT(t *testing.T) {
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
		if err := verify(t, buildWRPRCJWT(t, chain, key, nil), goodSrc); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})

	t.Run("forged_signature", func(t *testing.T) {
		otherKey := genP256(t) // signs with a key that does not match the x5c leaf
		raw := buildWRPRCJWT(t, chain, otherKey, nil)
		if err := verify(t, raw, goodSrc); !errors.Is(err, rpcert.ErrSignature) {
			t.Fatalf("err = %v, want ErrSignature", err)
		}
	})

	t.Run("tampered_claim_list", func(t *testing.T) {
		raw := buildWRPRCJWT(t, chain, key, nil)
		// Re-sign-free tamper: swap the payload segment for one claiming a
		// broader credential set; signature must no longer verify.
		tampered := buildWRPRCJWT(t, chain, key, nil)
		parts := bytes.Split(tampered, []byte("."))
		broad, _ := json.Marshal(map[string]any{"iat": 1783155600, "sub": "NTRDE-HRB123456", "credentials": []any{}})
		parts[1] = []byte(base64.RawURLEncoding.EncodeToString(broad))
		_ = raw
		if err := verify(t, bytes.Join(parts, []byte(".")), goodSrc); !errors.Is(err, rpcert.ErrSignature) {
			t.Fatalf("err = %v, want ErrSignature", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		raw := buildWRPRCJWT(t, chain, key, func(c map[string]any) { c["exp"] = 1783158000 }) // 09:40Z < clock 10:00Z
		if err := verify(t, raw, goodSrc); !errors.Is(err, rpcert.ErrExpired) {
			t.Fatalf("err = %v, want ErrExpired", err)
		}
	})

	t.Run("exp_beyond_12_months", func(t *testing.T) { // GEN-5.2.4-08
		raw := buildWRPRCJWT(t, chain, key, func(c map[string]any) { c["exp"] = 1817456400 }) // iat + 397 days
		if err := verify(t, raw, goodSrc); !errors.Is(err, rpcert.ErrValidity) {
			t.Fatalf("err = %v, want ErrValidity", err)
		}
	})

	t.Run("iat_in_future", func(t *testing.T) {
		raw := buildWRPRCJWT(t, chain, key, func(c map[string]any) { c["iat"] = 1783162800; delete(c, "exp") }) // 11:00Z
		if err := verify(t, raw, goodSrc); !errors.Is(err, rpcert.ErrValidity) {
			t.Fatalf("err = %v, want ErrValidity", err)
		}
	})

	t.Run("no_annex_a2_entitlement", func(t *testing.T) { // GEN-5.2.4-03
		for name, ents := range map[string]any{
			"empty":        []any{},
			"unknown_only": []any{"https://uri.example.org/not-etsi/Entitlement/X"},
		} {
			t.Run(name, func(t *testing.T) {
				raw := buildWRPRCJWT(t, chain, key, func(c map[string]any) { c["entitlements"] = ents })
				if err := verify(t, raw, goodSrc); !errors.Is(err, rpcert.ErrEntitlement) {
					t.Fatalf("err = %v, want ErrEntitlement", err)
				}
			})
		}
	})

	t.Run("policy_id_missing_wrprc_oid", func(t *testing.T) { // OVR-6.1.3-01
		raw := buildWRPRCJWT(t, chain, key, func(c map[string]any) { c["policy_id"] = []any{"1.2.3.4"} })
		if err := verify(t, raw, goodSrc); !errors.Is(err, rpcert.ErrPolicyID) {
			t.Fatalf("err = %v, want ErrPolicyID", err)
		}
	})

	t.Run("issuer_chain_not_anchored", func(t *testing.T) {
		other := testpki.NewCA(t, "OTHER CA")
		src := anchorsFor(trust.WRPRCIssuer, "DE", grantedAnchor(other, trust.WRPRCIssuer, "DE"))
		raw := buildWRPRCJWT(t, chain, key, nil)
		if err := verify(t, raw, src); !errors.Is(err, rpcert.ErrNoTrustPath) {
			t.Fatalf("err = %v, want ErrNoTrustPath", err)
		}
	})

	t.Run("anchor_source_error_propagates", func(t *testing.T) {
		raw := buildWRPRCJWT(t, chain, key, nil)
		if err := verify(t, raw, &fakeAnchors{err: errCacheExpired}); !errors.Is(err, errCacheExpired) {
			t.Fatalf("err = %v, want wrapped errCacheExpired", err)
		}
	})

	t.Run("nil_clock_rejected", func(t *testing.T) {
		r, err := rpcert.ParseWRPRC(buildWRPRCJWT(t, chain, key, nil))
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Verify(goodSrc, nil); !errors.Is(err, rpcert.ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})
}
