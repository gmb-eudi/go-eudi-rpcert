package ts5_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/gmb-eudi/go-eudi-rpcert/ts5"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	//nolint:gosec // G304: name is always a compile-time constant fixture filename from this test file, never external input.
	b, err := os.ReadFile("../testdata/ts5/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Golden decode of the recorded /wrp payload (T-07.1 acceptance).
func TestGoldenDecodeWRPPage1(t *testing.T) {
	env, err := ts5.DecodeSignedWRPArray(readFixture(t, "wrp-page1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if env.Iss != "https://registrar.example-ms.eu" {
		t.Errorf("iss = %q", env.Iss)
	}
	if env.Iat != 1783155600 {
		t.Errorf("iat = %d", env.Iat)
	}
	if len(env.Data) != 1 {
		t.Fatalf("len(data) = %d, want 1", len(env.Data))
	}
	wrp := env.Data[0]
	if wrp.TradeName != "Example Age Check" {
		t.Errorf("tradeName = %q", wrp.TradeName)
	}
	if wrp.IsPSB || wrp.IsIntermediary {
		t.Errorf("isPSB=%v isIntermediary=%v, want false/false", wrp.IsPSB, wrp.IsIntermediary)
	}
	if got := wrp.Entitlements; len(got) != 1 || got[0] != "https://uri.etsi.org/19475/Entitlement/Service_Provider" {
		t.Errorf("entitlements = %v", got)
	}
	if wrp.SupervisoryAuthority.Name != "Example State DPA" || wrp.SupervisoryAuthority.Country != "DE" {
		t.Errorf("supervisoryAuthority = %+v", wrp.SupervisoryAuthority)
	}
	if len(wrp.SupervisoryAuthority.FormURI) != 1 || wrp.SupervisoryAuthority.FormURI[0] != "https://dpa.example-ms.eu/report" {
		t.Errorf("formURI = %v", wrp.SupervisoryAuthority.FormURI)
	}
	if wrp.RegistryURI != "https://registrar.example-ms.eu/api" {
		t.Errorf("registryURI = %q", wrp.RegistryURI)
	}
	if len(wrp.Identifiers) != 1 || wrp.Identifiers[0].Type != "http://data.europa.eu/eudi/id/EUID" || wrp.Identifiers[0].Identifier != "DEUTR.HRB123456" {
		t.Errorf("identifier = %+v", wrp.Identifiers)
	}
	if wrp.LegalPerson == nil || len(wrp.LegalPerson.LegalName) != 1 || wrp.LegalPerson.LegalName[0] != "Example Retail GmbH" {
		t.Errorf("legalPerson = %+v", wrp.LegalPerson)
	}
	if len(wrp.SrvDescription) != 1 || len(wrp.SrvDescription[0]) != 2 || wrp.SrvDescription[0][1].Lang != "de" {
		t.Errorf("srvDescription = %+v", wrp.SrvDescription)
	}
	// IntendedUse §2.4.3
	if len(wrp.IntendedUse) != 2 {
		t.Fatalf("len(intendedUse) = %d, want 2", len(wrp.IntendedUse))
	}
	iu := wrp.IntendedUse[0]
	if iu.IntendedUseIdentifier != "iu-age-001" || iu.CreatedAt != "2026-01-15" || iu.RevokedAt != "" {
		t.Errorf("intendedUse[0] = %+v", iu)
	}
	if len(iu.PrivacyPolicy) != 1 || iu.PrivacyPolicy[0].Type != "http://data.europa.eu/eudi/policy/privacy-policy" {
		t.Errorf("privacyPolicy = %+v", iu.PrivacyPolicy)
	}
	if len(iu.Credentials) != 2 {
		t.Fatalf("len(credentials) = %d, want 2", len(iu.Credentials))
	}
	// Credential §2.4.4 + Claim §2.4.1
	sd := iu.Credentials[0]
	if sd.Format != "dc+sd-jwt" {
		t.Errorf("format = %q", sd.Format)
	}
	var meta struct {
		VCTValues []string `json:"vct_values"`
	}
	if err := json.Unmarshal(sd.Meta, &meta); err != nil || len(meta.VCTValues) != 1 || meta.VCTValues[0] != "urn:eudi:pid:1" {
		t.Errorf("meta = %s (err %v)", sd.Meta, err)
	}
	if len(sd.Claims) != 1 || !reflect.DeepEqual(sd.Claims[0].Path, ts5.ClaimPath{"age_equal_or_over", "18"}) {
		t.Errorf("claims = %+v", sd.Claims)
	}
	if wrp.IntendedUse[1].RevokedAt != "2026-06-01" {
		t.Errorf("intendedUse[1].revokedAt = %q", wrp.IntendedUse[1].RevokedAt)
	}
	// usesIntermediary §2.1
	if len(wrp.UsesIntermediary) != 1 {
		t.Fatalf("len(usesIntermediary) = %d, want 1", len(wrp.UsesIntermediary))
	}
	im := wrp.UsesIntermediary[0]
	if !im.IsIntermediary || im.Identifiers[0].Identifier != "529900EXAMPLE0000001" {
		t.Errorf("usesIntermediary[0] = %+v", im)
	}
	// pagination
	if env.Pagination == nil || !env.Pagination.HasNextPage || env.Pagination.NextCursor != "b3BhcXVlLXBhZ2UtMg" {
		t.Errorf("pagination = %+v", env.Pagination)
	}
}

func TestGoldenDecodeWRPPage2(t *testing.T) {
	env, err := ts5.DecodeSignedWRPArray(readFixture(t, "wrp-page2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Data) != 1 || !env.Data[0].IsIntermediary {
		t.Fatalf("page2 data = %+v", env.Data)
	}
	if env.Pagination == nil || env.Pagination.HasNextPage {
		t.Errorf("pagination = %+v, want has_next_page=false", env.Pagination)
	}
}

// TestDecodeSignedWRP is the direct ts5-package golden decode for
// GET /wrp/{identifier} (DecodeSignedWRP). The rpcert package only exercises
// this decoder indirectly through RegistrarClient.GetWRPByID/
// VerifyIntermediaryLinkage; this test closes that coverage gap for ts5
// itself (conventions.md 85% library gate).
func TestDecodeSignedWRP(t *testing.T) {
	env, err := ts5.DecodeSignedWRP(readFixture(t, "wrp-single.json"))
	if err != nil {
		t.Fatal(err)
	}
	if env.Iss != "https://registrar.example-ms.eu" || env.Iat != 1783155600 {
		t.Errorf("envelope = %+v", env)
	}
	if env.Data.TradeName != "Example Age Check" || env.Data.IsPSB || env.Data.IsIntermediary {
		t.Errorf("data = %+v", env.Data)
	}
	if len(env.Data.Identifiers) != 1 || env.Data.Identifiers[0].Identifier != "DEUTR.HRB123456" {
		t.Errorf("identifier = %+v", env.Data.Identifiers)
	}
}

// TestDecodeSignedWRPValidation mirrors TestEnvelopeValidation for the
// single-object envelope (DecodeSignedWRP has its own "data absent" probe,
// distinct from the array decoder's env.Data == nil check).
func TestDecodeSignedWRPValidation(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wantErr error
	}{
		{"missing_iss", `{"iat":1,"data":{}}`, ts5.ErrEnvelope},
		{"missing_iat", `{"iss":"x","data":{}}`, ts5.ErrEnvelope},
		{"missing_data", `{"iss":"x","iat":1}`, ts5.ErrEnvelope},
		{"not_json", `<html>`, ts5.ErrDecode},
		{"empty", ``, ts5.ErrDecode},
		{"physicalAddress_present", `{"iss":"x","iat":1,"data":{"physicalAddress":["street 1"],"isPSB":false,"isIntermediary":false}}`, ts5.ErrAddressPresent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ts5.DecodeSignedWRP([]byte(tt.payload))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestDecodeSignedIntendedUseCheckResult is the direct ts5-package golden
// decode for GET /wrp/check-intended-use. rpcert.CheckIntendedUse (T-07.8)
// only exercises this decoder from the rpcert package's own test binary,
// which does not count toward ts5's coverage — this test closes that gap.
func TestDecodeSignedIntendedUseCheckResult(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		env, err := ts5.DecodeSignedIntendedUseCheckResult(readFixture(t, "check-true.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !env.Data.IsRegistered {
			t.Errorf("data = %+v, want isRegistered=true", env.Data)
		}
	})
	t.Run("false_with_details", func(t *testing.T) {
		env, err := ts5.DecodeSignedIntendedUseCheckResult(readFixture(t, "check-false.json"))
		if err != nil {
			t.Fatal(err)
		}
		if env.Data.IsRegistered || env.Data.Details == "" {
			t.Errorf("data = %+v, want isRegistered=false with details", env.Data)
		}
	})
	for _, tt := range []struct {
		name    string
		payload string
		wantErr error
	}{
		{"missing_iss", `{"iat":1,"data":{"isRegistered":true}}`, ts5.ErrEnvelope},
		{"missing_data", `{"iss":"x","iat":1}`, ts5.ErrEnvelope},
		{"not_json", `<html>`, ts5.ErrDecode},
		// Fix-wave item 3: for symmetry with DecodeSignedWRP/
		// DecodeSignedWRPArray, this decoder must also run the
		// rejectAddressFields privacy walk. The current {isRegistered,
		// details} shape can't carry an address today, but a future schema
		// change (or a misbehaving registrar) should still fail closed
		// rather than silently pass one through.
		{"physicalAddress_present", `{"iss":"x","iat":1,"data":{"isRegistered":true,"physicalAddress":["street 1"]}}`, ts5.ErrAddressPresent},
		{"postalAddress_present", `{"iss":"x","iat":1,"data":{"isRegistered":true,"postalAddress":["street 1"]}}`, ts5.ErrAddressPresent},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ts5.DecodeSignedIntendedUseCheckResult([]byte(tt.payload))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// jsonNorm decodes JSON into a comparable tree (json.Number preserved).
func jsonNorm(t *testing.T, b []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// Schema-drift test (T-07.1 acceptance): (a) strict decode — a fixture field
// our structs do not model fails the build's tests, i.e. spec drift is
// caught here, not in production; (b) re-marshal equality — a struct field
// that renames/retypes an ARF TS5 v1.3 attribute is caught by tree comparison.
func TestSchemaDrift(t *testing.T) {
	for _, name := range []string{"wrp-page1.json", "wrp-page2.json"} {
		t.Run(name, func(t *testing.T) {
			raw := readFixture(t, name)
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			var env ts5.SignedWRPArray
			if err := dec.Decode(&env); err != nil {
				t.Fatalf("strict decode (unknown field = drift): %v", err)
			}
			out, err := json.Marshal(env)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := jsonNorm(t, out), jsonNorm(t, raw); !reflect.DeepEqual(got, want) {
				t.Errorf("round-trip drift:\n got: %s\nwant: %s", out, raw)
			}
		})
	}
}

func TestEnvelopeValidation(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wantErr error
	}{
		{"missing_iss", `{"iat":1,"data":[]}`, ts5.ErrEnvelope},
		{"missing_iat", `{"iss":"x","data":[]}`, ts5.ErrEnvelope},
		{"missing_data", `{"iss":"x","iat":1}`, ts5.ErrEnvelope},
		{"not_json", `<html>`, ts5.ErrDecode},
		{"empty", ``, ts5.ErrDecode},
		// ARF TS5 §3.2.1: responses exclude WalletRelyingParty.physicalAddress;
		// the JSON schema names the LegalEntity field postalAddress — both
		// spellings are privacy-rejected before any struct field could hold them.
		{"physicalAddress_present", `{"iss":"x","iat":1,"data":[{"physicalAddress":["street 1"],"isPSB":false,"isIntermediary":false}]}`, ts5.ErrAddressPresent},
		{"postalAddress_present", `{"iss":"x","iat":1,"data":[{"postalAddress":["street 1"],"isPSB":false,"isIntermediary":false}]}`, ts5.ErrAddressPresent},
		{"nested_address", `{"iss":"x","iat":1,"data":[{"usesIntermediary":[{"postalAddress":["s"],"isPSB":false,"isIntermediary":true}],"isPSB":false,"isIntermediary":false}]}`, ts5.ErrAddressPresent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ts5.DecodeSignedWRPArray([]byte(tt.payload))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestClaimPathValidation(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   string
		ok   bool
	}{
		{"key_and_index", `["degrees", 0, "type"]`, true},
		{"wildcard_null", `["degrees", null, "type"]`, true},
		{"empty", `[]`, false},
		{"negative_index", `["a", -1]`, false},
		{"bool_element", `["a", true]`, false},
		{"object_element", `[{"k":1}]`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var p ts5.ClaimPath
			err := json.Unmarshal([]byte(tt.in), &p)
			if (err == nil) != tt.ok {
				t.Errorf("Unmarshal(%s) err = %v, want ok=%v", tt.in, err, tt.ok)
			}
		})
	}
}
