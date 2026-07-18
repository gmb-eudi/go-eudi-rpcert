package rpcert_test

import (
	"encoding/json"
	"errors"
	"testing"

	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
)

func validRef(t *testing.T) rpcert.RegistrationRef {
	t.Helper()
	r, err := rpcert.NewRegistrationRef(
		"Example Age Check",
		"NTRDE-HRB123456",
		"https://registrar.example-ms.eu/api",
		"iu-age-001",
	)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Serializer golden: TS 119 475 Table 7/9 claim vocabulary —
// the request builder embeds exactly this object into the request object
// (ARF RPRC_19a).
func TestRegistrationRefGoldenJSON(t *testing.T) {
	out, err := json.Marshal(validRef(t))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"Example Age Check","sub":"NTRDE-HRB123456","registry_uri":"https://registrar.example-ms.eu/api","intended_use_id":"iu-age-001"}`
	if string(out) != want {
		t.Errorf("json = %s\nwant  %s", out, want)
	}
}

// Round-trip: the verifier stores RegistrationRef inside Session via generic
// encoding/json (SessionStore contract). MarshalJSON validates on write;
// UnmarshalJSON must reconstruct the exact same value, not silently zero it.
func TestRegistrationRefJSONRoundtrip(t *testing.T) {
	want := validRef(t)
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got rpcert.RegistrationRef
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("roundtrip = %+v, want %+v", got, want)
	}
}

// An incomplete/corrupted stored value must fail loudly on read (fail
// closed), not silently decode to a zero-value reference.
func TestRegistrationRefUnmarshalIncompleteFails(t *testing.T) {
	raw := []byte(`{"name":"Example Age Check","sub":"","registry_uri":"https://registrar.example-ms.eu/api","intended_use_id":"iu-age-001"}`)
	var got rpcert.RegistrationRef
	if err := json.Unmarshal(raw, &got); !errors.Is(err, rpcert.ErrRegistrationRef) {
		t.Fatalf("err = %v, want ErrRegistrationRef", err)
	}
}

func TestRegistrationRefClaims(t *testing.T) {
	claims, err := validRef(t).Claims()
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{
		"name":            "Example Age Check",
		"sub":             "NTRDE-HRB123456",
		"registry_uri":    "https://registrar.example-ms.eu/api",
		"intended_use_id": "iu-age-001",
	} {
		if claims[k] != want {
			t.Errorf("claims[%q] = %v, want %v", k, claims[k], want)
		}
	}
	if len(claims) != 4 {
		t.Errorf("len(claims) = %d, want 4", len(claims))
	}
}

// All four fields are named — each is required, and an
// incomplete reference can neither be built nor serialized (this is how
// the "request without RegistrationRef impossible" invariant holds).
func TestRegistrationRefValidation(t *testing.T) {
	tests := []struct {
		name                                          string
		clientName, clientID, registryURI, intendedID string
	}{
		{"missing_client_name", "", "NTRDE-HRB123456", "https://registrar.example-ms.eu/api", "iu-age-001"},
		{"missing_client_id", "Example Age Check", "", "https://registrar.example-ms.eu/api", "iu-age-001"},
		{"missing_registry_uri", "Example Age Check", "NTRDE-HRB123456", "", "iu-age-001"},
		{"missing_intended_use_id", "Example Age Check", "NTRDE-HRB123456", "https://registrar.example-ms.eu/api", ""},
		{"http_registry_uri", "Example Age Check", "NTRDE-HRB123456", "http://registrar.example-ms.eu/api", "iu-age-001"},
		{"relative_registry_uri", "Example Age Check", "NTRDE-HRB123456", "/api", "iu-age-001"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := rpcert.NewRegistrationRef(tt.clientName, tt.clientID, tt.registryURI, tt.intendedID); !errors.Is(err, rpcert.ErrRegistrationRef) {
				t.Errorf("err = %v, want ErrRegistrationRef", err)
			}
		})
	}

	t.Run("zero_value_cannot_marshal", func(t *testing.T) {
		if _, err := json.Marshal(rpcert.RegistrationRef{}); err == nil {
			t.Error("marshal of zero value succeeded; want error")
		}
	})
}
