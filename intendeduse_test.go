package rpcert_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	"github.com/gmb-eudi/go-eudi-rpcert/internal/testpki"
	"github.com/gmb-eudi/go-eudi-rpcert/ts5"
)

// checkServer serves GET /wrp/check-intended-use JWS responses and captures
// the query it received; /wrp/{id} is served through the embedded
// registrarServer's "single" fixture (wrp-single.json by default, mutable by
// tests before making the request).
type checkServer struct {
	*registrarServer
	checkFixture string
	lastCheck    url.Values
}

// startCheckServer starts a purpose-built registrar exposing both
// /wrp/check-intended-use and /wrp/{id} on one httptest.Server (the fixed
// mux of newRegistrarServer only wires /wrp + /wrp/{id}).
func startCheckServer(t *testing.T, key *ecdsa.PrivateKey, fixture string) (*checkServer, string) {
	t.Helper()
	cs := &checkServer{
		registrarServer: &registrarServer{key: key, kid: "reg-key-1", single: "wrp-single.json"},
		checkFixture:    fixture,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/wrp/check-intended-use", func(w http.ResponseWriter, r *http.Request) {
		cs.lastCheck = r.URL.Query()
		payload, err := os.ReadFile("testdata/ts5/" + cs.checkFixture)
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/jwt")
		token := signRegistrarJWS(t, payload, key, "reg-key-1")
		if _, err := w.Write([]byte(token)); err != nil {
			t.Fatal(err)
		}
	})
	mux.HandleFunc("/wrp/", func(w http.ResponseWriter, r *http.Request) {
		cs.serveSingle(t, w, r)
	})
	srv := httptestNewServer(t, mux)
	cs.srv = srv
	return cs, srv.URL
}

// T-07.8 acceptance: TRUE / FALSE fixtures.
func TestCheckIntendedUse(t *testing.T) {
	key := genP256(t)
	for _, tt := range []struct {
		name    string
		fixture string
		want    bool
	}{
		{"true", "check-true.json", true},
		{"false", "check-false.json", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cs, urlStr := startCheckServer(t, key, tt.fixture)
			c := rpcert.NewRegistrarClient(cs.srv.Client(),
				rpcert.NewPinnedRegistrarKeys(map[string]crypto.PublicKey{urlStr: key.Public()}),
				rpcert.WithClock(func() time.Time { return testpki.Clock }),
				rpcert.WithMaxResponseAge(48*time.Hour),
			)
			got, err := c.CheckIntendedUse(context.Background(), urlStr, rpcert.IntendedUseQuery{
				RPIdentifier:          "NTRDE-HRB123456",
				IntendedUseIdentifier: "iu-age-001",
				CredentialFormat:      rpcert.CredentialFormatSDJWTVC,
				ClaimPath:             "age_equal_or_over",
			})
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("CheckIntendedUse = %v, want %v", got, tt.want)
			}
			// ARF TS5 OpenAPI: rpidentifier is required; the five optional
			// params carry their exact names.
			for k, want := range map[string]string{
				"rpidentifier":          "NTRDE-HRB123456",
				"intendeduseidentifier": "iu-age-001",
				"credentialformat":      rpcert.CredentialFormatSDJWTVC,
				"claimpath":             "age_equal_or_over",
			} {
				if got := cs.lastCheck.Get(k); got != want {
					t.Errorf("check query[%q] = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestCheckIntendedUseRequiresRPIdentifier(t *testing.T) {
	key := genP256(t)
	cs, urlStr := startCheckServer(t, key, "check-true.json")
	c := rpcert.NewRegistrarClient(cs.srv.Client(),
		rpcert.NewPinnedRegistrarKeys(map[string]crypto.PublicKey{urlStr: key.Public()}),
		rpcert.WithClock(func() time.Time { return testpki.Clock }))
	if _, err := c.CheckIntendedUse(context.Background(), urlStr, rpcert.IntendedUseQuery{IntendedUseIdentifier: "iu-age-001"}); !errors.Is(err, rpcert.ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed (rpidentifier required)", err)
	}
}

func TestCheckIntendedUseTamperedFails(t *testing.T) {
	key := genP256(t)
	cs, urlStr := startCheckServer(t, key, "check-true.json")
	// Pin the WRONG key so the (valid) signature fails to verify.
	c := rpcert.NewRegistrarClient(cs.srv.Client(),
		rpcert.NewPinnedRegistrarKeys(map[string]crypto.PublicKey{urlStr: genP256(t).Public()}),
		rpcert.WithClock(func() time.Time { return testpki.Clock }),
		rpcert.WithMaxResponseAge(48*time.Hour))
	if _, err := c.CheckIntendedUse(context.Background(), urlStr, rpcert.IntendedUseQuery{RPIdentifier: "NTRDE-HRB123456"}); !errors.Is(err, rpcert.ErrResponseSignature) {
		t.Fatalf("err = %v, want ErrResponseSignature", err)
	}
}

// T-07.8 acceptance: the revokedAt monitoring predicate.
func TestIntendedUseActive(t *testing.T) {
	iu := func(created, revoked string) ts5.IntendedUse {
		return ts5.IntendedUse{IntendedUseIdentifier: "iu", CreatedAt: created, RevokedAt: revoked}
	}
	tests := []struct {
		name       string
		iu         ts5.IntendedUse
		at         time.Time
		wantActive bool
		wantErr    error
	}{
		{"active_no_revoke", iu("2026-01-15", ""), testpki.Clock, true, nil},
		{"not_yet_created", iu("2026-08-01", ""), testpki.Clock, false, rpcert.ErrIntendedUseRevoked},
		{"revoked_in_past", iu("2026-01-15", "2026-06-01"), testpki.Clock, false, rpcert.ErrIntendedUseRevoked},
		// WP-07 Decision 10: revocation takes effect at 00:00:00 UTC of the
		// revokedAt date — the whole revokedAt day is already revoked.
		{"revoked_today_effective_midnight", iu("2026-01-15", "2026-07-04"), testpki.Clock, false, rpcert.ErrIntendedUseRevoked},
		{"revoke_in_future_still_active", iu("2026-01-15", "2026-12-31"), testpki.Clock, true, nil},
		{"bad_created_date", iu("15-01-2026", ""), testpki.Clock, false, rpcert.ErrMalformed},
		{"bad_revoked_date", iu("2026-01-15", "nope"), testpki.Clock, false, rpcert.ErrMalformed},
		// Regression (WP-07 Task 8 fix wave): a schema-nonconformant
		// registrar response with an empty createdAt must fail closed like
		// any other unparseable date — never "always active".
		{"empty_created_date", iu("", ""), testpki.Clock, false, rpcert.ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			active, err := rpcert.IntendedUseActive(tt.iu, tt.at)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err %v", err)
			}
			if active != tt.wantActive {
				t.Errorf("active = %v, want %v", active, tt.wantActive)
			}
		})
	}
}

// IntendedUseStatus resolves the WRP by id and evaluates the named intended
// use — drives err:registrar:intended-use-revoked. The wrp-single fixture
// carries no intendedUse, so we serve a purpose-built one here.
func TestIntendedUseStatus(t *testing.T) {
	key := genP256(t)
	writeIntendedUseFixture(t, "wrp-iu-revoked.json", "iu-age-001", "2026-01-15", "2026-06-01")
	cs, urlStr := startCheckServer(t, key, "check-true.json")
	cs.single = "wrp-iu-revoked.json"
	c := rpcert.NewRegistrarClient(cs.srv.Client(),
		rpcert.NewPinnedRegistrarKeys(map[string]crypto.PublicKey{urlStr: key.Public()}),
		rpcert.WithClock(func() time.Time { return testpki.Clock }),
		rpcert.WithMaxResponseAge(48*time.Hour))

	t.Run("revoked", func(t *testing.T) {
		err := c.IntendedUseStatus(context.Background(), urlStr, "NTRDE-HRB123456", "iu-age-001")
		if !errors.Is(err, rpcert.ErrIntendedUseRevoked) {
			t.Fatalf("err = %v, want ErrIntendedUseRevoked", err)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		err := c.IntendedUseStatus(context.Background(), urlStr, "NTRDE-HRB123456", "iu-does-not-exist")
		if !errors.Is(err, rpcert.ErrIntendedUseNotFound) {
			t.Fatalf("err = %v, want ErrIntendedUseNotFound", err)
		}
	})
}
