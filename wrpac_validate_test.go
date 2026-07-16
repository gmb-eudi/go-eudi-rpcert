package rpcert_test

import (
	"errors"
	"testing"
	"time"

	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	"github.com/gmb-eudi/go-eudi-rpcert/internal/testpki"
	trust "github.com/gmb-eudi/go-eudi-trust"
)

// Pin the package clock to the plan-wide test instant (ValidateAgainst has
// no clock parameter per the README interface — see README corrections).
func pinClock(t *testing.T) {
	t.Helper()
	old := *rpcert.TimeNow
	*rpcert.TimeNow = func() time.Time { return testpki.Clock }
	t.Cleanup(func() { *rpcert.TimeNow = old })
}

func grantedAnchor(ca *testpki.CA, at trust.AnchorType, country string) trust.Anchor {
	return trust.Anchor{Cert: ca.Cert, Type: at, Country: country, Status: "granted", ValidUntil: testpki.NotAfter}
}

func loadDefaultWRPAC(t *testing.T, ca *testpki.CA) *rpcert.WRPAC {
	t.Helper()
	leaf, _ := ca.Issue(t, testpki.DefaultWRPAC())
	w, err := rpcert.LoadWRPAC(testpki.ChainDER(leaf, ca.Cert))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// Valid / expired / withdrawn-anchor cases.
func TestValidateAgainst(t *testing.T) {
	pinClock(t)
	ca := testpki.NewCA(t, "TEST ACCESS CA DE")
	w := loadDefaultWRPAC(t, ca)

	t.Run("valid_anchor", func(t *testing.T) {
		src := anchorsFor(trust.AccessCA, "DE", grantedAnchor(ca, trust.AccessCA, "DE"))
		if err := w.ValidateAgainst(src); err != nil {
			t.Fatalf("ValidateAgainst: %v", err)
		}
	})

	// Production status form: go-eudi-trust ships Anchor.Status
	// VERBATIM as the full TS 119 612 service-status URI, not the bare
	// "granted" token (confirmed against go-eudi-trust anchor.go/client.go and
	// its testdata). The granted filter MUST accept it, otherwise the
	// operator's own valid WRPAC never validates against a real AnchorSource.
	t.Run("granted_status_uri_form", func(t *testing.T) {
		a := grantedAnchor(ca, trust.AccessCA, "DE")
		a.Status = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
		src := anchorsFor(trust.AccessCA, "DE", a)
		if err := w.ValidateAgainst(src); err != nil {
			t.Fatalf("ValidateAgainst with full-URI granted status: %v", err)
		}
	})

	t.Run("expired_anchor_fails_closed", func(t *testing.T) {
		a := grantedAnchor(ca, trust.AccessCA, "DE")
		a.ValidUntil = testpki.Clock.Add(-time.Hour) // anchor validity already over
		src := anchorsFor(trust.AccessCA, "DE", a)
		if err := w.ValidateAgainst(src); !errors.Is(err, rpcert.ErrNoTrustPath) {
			t.Fatalf("err = %v, want ErrNoTrustPath", err)
		}
	})

	// A zero ValidUntil must NOT be read as "never expires".
	// go-eudi-trust's own canonical filter (CachingSource.AnchorsFor,
	// cache.go: "if !a.ValidUntil.After(now) { continue }") drops a
	// zero-ValidUntil anchor — Anchor.ValidUntil is documented "REQUIRED
	// upstream," so zero signals bad anchor data, not eternal validity.
	// usableAnchors must match that fail-closed predicate.
	t.Run("zero_valid_until_fails_closed", func(t *testing.T) {
		a := grantedAnchor(ca, trust.AccessCA, "DE")
		a.ValidUntil = time.Time{} // zero value — must be treated as invalid, not eternal
		src := anchorsFor(trust.AccessCA, "DE", a)
		if err := w.ValidateAgainst(src); !errors.Is(err, rpcert.ErrNoTrustPath) {
			t.Fatalf("err = %v, want ErrNoTrustPath", err)
		}
	})

	t.Run("withdrawn_anchor_fails_closed", func(t *testing.T) {
		a := grantedAnchor(ca, trust.AccessCA, "DE")
		a.Status = "withdrawn"
		src := anchorsFor(trust.AccessCA, "DE", a)
		if err := w.ValidateAgainst(src); !errors.Is(err, rpcert.ErrNoTrustPath) {
			t.Fatalf("err = %v, want ErrNoTrustPath", err)
		}
	})

	t.Run("unrelated_anchor_no_chain", func(t *testing.T) {
		other := testpki.NewCA(t, "UNRELATED CA")
		src := anchorsFor(trust.AccessCA, "DE", grantedAnchor(other, trust.AccessCA, "DE"))
		if err := w.ValidateAgainst(src); !errors.Is(err, rpcert.ErrNoTrustPath) {
			t.Fatalf("err = %v, want ErrNoTrustPath", err)
		}
	})

	// Territory fallback: no DE anchors, EU-level ("")
	// anchors hold the chain.
	t.Run("eu_level_fallback", func(t *testing.T) {
		src := anchorsFor(trust.AccessCA, "", grantedAnchor(ca, trust.AccessCA, ""))
		if err := w.ValidateAgainst(src); err != nil {
			t.Fatalf("ValidateAgainst: %v", err)
		}
	})

	// Fail closed on source errors: ErrCacheExpired-like
	// errors propagate unwrapped for the service's errors.Is mapping.
	t.Run("anchor_source_error_propagates", func(t *testing.T) {
		src := &fakeAnchors{err: errCacheExpired}
		if err := w.ValidateAgainst(src); !errors.Is(err, errCacheExpired) {
			t.Fatalf("err = %v, want wrapped errCacheExpired", err)
		}
	})

	t.Run("empty_chain", func(t *testing.T) {
		empty := &rpcert.WRPAC{}
		if err := empty.ValidateAgainst(anchorsFor(trust.AccessCA, "DE")); !errors.Is(err, rpcert.ErrChainEmpty) {
			t.Fatalf("err = %v, want ErrChainEmpty", err)
		}
	})
}
