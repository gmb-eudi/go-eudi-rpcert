package rpcert_test

import (
	"context"
	"crypto"
	"errors"
	"strings"
	"testing"
	"time"

	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	"github.com/gmb-eudi/go-eudi-rpcert/internal/testpki"
)

func newTestClient(t *testing.T, rs *registrarServer, keys rpcert.RegistrarKeys) *rpcert.RegistrarClient {
	t.Helper()
	return rpcert.NewRegistrarClient(rs.srv.Client(), keys,
		rpcert.WithClock(func() time.Time { return testpki.Clock }),
		rpcert.WithMaxResponseAge(48*time.Hour), // fixture iat is 1h before the clock
	)
}

func pinned(t *testing.T, rs *registrarServer) rpcert.RegistrarKeys {
	t.Helper()
	return rpcert.NewPinnedRegistrarKeys(map[string]crypto.PublicKey{rs.srv.URL: pinnedKeysFor(rs)})
}

// Recorded fixtures; pagination joins pages.
func TestGetWRPJoinsPages(t *testing.T) {
	key := genP256(t)
	rs := newRegistrarServer(t, key)
	c := newTestClient(t, rs, pinned(t, rs))

	wrps, err := c.GetWRP(context.Background(), rs.srv.URL, rpcert.WRPQuery{Identifier: "NTRDE-HRB123456"})
	if err != nil {
		t.Fatal(err)
	}
	if len(wrps) != 2 {
		t.Fatalf("len(wrps) = %d, want 2 (page1 + page2 joined)", len(wrps))
	}
	if wrps[0].TradeName != "Example Age Check" || !wrps[1].IsIntermediary {
		t.Errorf("joined data = %q / intermediary=%v", wrps[0].TradeName, wrps[1].IsIntermediary)
	}
	// Second request must carry the cursor from page 1's pagination.
	if len(rs.lastReqs) != 2 {
		t.Fatalf("server saw %d /wrp calls, want 2", len(rs.lastReqs))
	}
	if got := rs.lastReqs[0].Get("identifier"); got != "NTRDE-HRB123456" {
		t.Errorf("page1 identifier param = %q", got)
	}
	if got := rs.lastReqs[1].Get("cursor"); got != "b3BhcXVlLXBhZ2UtMg" {
		t.Errorf("page2 cursor param = %q, want the page1 next_cursor", got)
	}
}

// Every query parameter is mapped with its exact ARF TS5 lowercase name.
func TestGetWRPQueryParamMapping(t *testing.T) {
	key := genP256(t)
	rs := newRegistrarServer(t, key)
	rs.pages = map[string]string{"": "wrp-page2.json"} // single page, no join
	c := newTestClient(t, rs, pinned(t, rs))

	yes := true
	//nolint:gosec // G101: CredentialMeta/CredentialFormat are OpenID4VP data-format query params, not credentials (name matches gosec's "cred" heuristic, cf. wrprc.go CredentialFormatSDJWTVC).
	_, err := c.GetWRP(context.Background(), rs.srv.URL, rpcert.WRPQuery{
		Identifier:            "NTRDE-HRB123456",
		LegalName:             "Example Retail GmbH",
		TradeName:             "Example Age Check",
		Policy:                "https://rp.example.com/privacy",
		Entitlement:           rpcert.EntitlementServiceProvider,
		CredentialMeta:        "urn:eudi:pid:1",
		CredentialFormat:      rpcert.CredentialFormatSDJWTVC,
		UsesIntermediary:      "LEIXG-529900EXAMPLE0000001",
		IsIntermediary:        &yes,
		IntendedUseIdentifier: "iu-age-001",
		Limit:                 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	q := rs.lastReqs[0]
	//nolint:gosec // G101: credentialmeta/credentialformat are OpenID4VP data-format query params, not credentials (name matches gosec's "cred" heuristic).
	for k, want := range map[string]string{
		"identifier":            "NTRDE-HRB123456",
		"legalname":             "Example Retail GmbH",
		"tradename":             "Example Age Check",
		"policy":                "https://rp.example.com/privacy",
		"entitlement":           rpcert.EntitlementServiceProvider,
		"credentialmeta":        "urn:eudi:pid:1",
		"credentialformat":      rpcert.CredentialFormatSDJWTVC,
		"usesintermediary":      "LEIXG-529900EXAMPLE0000001",
		"isintermediary":        "true",
		"intendeduseidentifier": "iu-age-001",
		"limit":                 "50",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("query[%q] = %q, want %q", k, got, want)
		}
	}
}

func TestGetWRPByID(t *testing.T) {
	key := genP256(t)
	rs := newRegistrarServer(t, key)
	c := newTestClient(t, rs, pinned(t, rs))

	wrp, err := c.GetWRPByID(context.Background(), rs.srv.URL, "NTRDE-HRB123456")
	if err != nil {
		t.Fatal(err)
	}
	if wrp.TradeName != "Example Age Check" || wrp.Country != "DE" {
		t.Errorf("wrp = %+v", wrp)
	}
	// Provenance surfaces the pinned key.
	p := c.LastProvenance()
	if p.KeyProvenance != rpcert.ProvenancePinned || p.RegistryURI != rs.srv.URL {
		t.Errorf("provenance = %+v, want pinned/%s", p, rs.srv.URL)
	}
}

// Tampered JWS fails.
func TestGetWRPTamperedJWSFails(t *testing.T) {
	key := genP256(t)
	rs := newRegistrarServer(t, key)
	rs.tamper = true
	c := newTestClient(t, rs, pinned(t, rs))
	if _, err := c.GetWRP(context.Background(), rs.srv.URL, rpcert.WRPQuery{}); !errors.Is(err, rpcert.ErrResponseSignature) {
		t.Fatalf("err = %v, want ErrResponseSignature", err)
	}
}

func TestGetWRPWrongPinnedKeyFails(t *testing.T) {
	key := genP256(t)
	rs := newRegistrarServer(t, key)
	wrongKeys := rpcert.NewPinnedRegistrarKeys(map[string]crypto.PublicKey{rs.srv.URL: genP256(t).Public()})
	c := newTestClient(t, rs, wrongKeys)
	if _, err := c.GetWRP(context.Background(), rs.srv.URL, rpcert.WRPQuery{}); !errors.Is(err, rpcert.ErrResponseSignature) {
		t.Fatalf("err = %v, want ErrResponseSignature", err)
	}
}

func TestGetWRPNoKeyConfigured(t *testing.T) {
	key := genP256(t)
	rs := newRegistrarServer(t, key)
	empty := rpcert.NewPinnedRegistrarKeys(map[string]crypto.PublicKey{})
	c := newTestClient(t, rs, empty)
	if _, err := c.GetWRP(context.Background(), rs.srv.URL, rpcert.WRPQuery{}); !errors.Is(err, rpcert.ErrNoRegistrarKey) {
		t.Fatalf("err = %v, want ErrNoRegistrarKey", err)
	}
}

// physicalAddress-absent assertion — a registrar that
// leaks an address is rejected (ts5.ErrAddressPresent bubbles up).
func TestGetWRPRejectsLeakedAddress(t *testing.T) {
	key := genP256(t)
	rs := newRegistrarServer(t, key)
	rs.pages = map[string]string{"": "wrp-leaky.json"}
	writeLeakyFixture(t) // helper writes a page1 variant carrying postalAddress
	c := newTestClient(t, rs, pinned(t, rs))
	_, err := c.GetWRP(context.Background(), rs.srv.URL, rpcert.WRPQuery{})
	if err == nil || !strings.Contains(err.Error(), "address") {
		t.Fatalf("err = %v, want an address-present rejection", err)
	}
}

func TestGetWRPStaleResponseFails(t *testing.T) {
	key := genP256(t)
	rs := newRegistrarServer(t, key)
	// Clock far in the future so the fixture iat is older than MaxResponseAge.
	c := rpcert.NewRegistrarClient(rs.srv.Client(), pinned(t, rs),
		rpcert.WithClock(func() time.Time { return testpki.Clock.AddDate(0, 0, 3) }),
		rpcert.WithMaxResponseAge(24*time.Hour),
	)
	if _, err := c.GetWRP(context.Background(), rs.srv.URL, rpcert.WRPQuery{}); !errors.Is(err, rpcert.ErrStaleResponse) {
		t.Fatalf("err = %v, want ErrStaleResponse", err)
	}
}

func TestGetWRPServerErrorStatus(t *testing.T) {
	key := genP256(t)
	rs := newRegistrarServer(t, key)
	rs.status = 503
	c := newTestClient(t, rs, pinned(t, rs))
	if _, err := c.GetWRP(context.Background(), rs.srv.URL, rpcert.WRPQuery{}); !errors.Is(err, rpcert.ErrRegistrarStatus) {
		t.Fatalf("err = %v, want ErrRegistrarStatus", err)
	}
}

func TestGetWRPPageCapEnforced(t *testing.T) {
	key := genP256(t)
	rs := newRegistrarServer(t, key)
	// Every page points to itself → infinite has_next_page; cap must trip.
	rs.pages = map[string]string{"": "wrp-page1.json", "b3BhcXVlLXBhZ2UtMg": "wrp-page1.json"}
	c := rpcert.NewRegistrarClient(rs.srv.Client(), pinned(t, rs),
		rpcert.WithClock(func() time.Time { return testpki.Clock }),
		rpcert.WithMaxResponseAge(48*time.Hour),
		rpcert.WithMaxPages(3),
	)
	if _, err := c.GetWRP(context.Background(), rs.srv.URL, rpcert.WRPQuery{}); !errors.Is(err, rpcert.ErrTooManyPages) {
		t.Fatalf("err = %v, want ErrTooManyPages", err)
	}
}
