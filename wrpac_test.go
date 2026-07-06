package rpcert_test

import (
	"crypto/x509"
	"errors"
	"testing"

	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	"github.com/gmb-eudi/go-eudi-rpcert/internal/testpki"
)

// T-07.2 acceptance: test-PKI matrix — each missing/wrong profile element
// yields a DISTINCT typed error (TS 119 411-8 §6.6.1, TS 119 475 Annex A).

// All four policy identifiers of TS 119 411-8 §5.3 are accepted.
func TestLoadWRPACAcceptsAllEudiwrpPolicies(t *testing.T) {
	ca := testpki.NewCA(t, "TEST ACCESS CA")
	for _, tt := range []struct {
		name   string
		policy []uint64
	}{
		{"NCP-n-eudiwrp", []uint64{0, 4, 0, 194118, 1, 1}},
		{"NCP-l-eudiwrp", []uint64{0, 4, 0, 194118, 1, 2}},
		{"QCP-n-eudiwrp", []uint64{0, 4, 0, 194118, 1, 3}},
		{"QCP-l-eudiwrp", []uint64{0, 4, 0, 194118, 1, 4}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := testpki.DefaultWRPAC()
			opts.Policies = [][]uint64{tt.policy, {0, 4, 0, 19475, 1, 1}}
			leaf, _ := ca.Issue(t, opts)
			w, err := rpcert.LoadWRPAC(testpki.ChainDER(leaf, ca.Cert))
			if err != nil {
				t.Fatalf("LoadWRPAC: %v", err)
			}
			if len(w.Chain) != 2 {
				t.Errorf("len(Chain) = %d, want 2", len(w.Chain))
			}
		})
	}
}

// GEN-6.6.1-07 [CHOICE]: URI, email or telephone otherName each suffice.
func TestLoadWRPACContactSANChoices(t *testing.T) {
	ca := testpki.NewCA(t, "TEST ACCESS CA")
	for _, tt := range []struct {
		name   string
		mutate func(*testpki.CertOpts)
	}{
		{"uri_only", func(o *testpki.CertOpts) {
			o.SANURIs = []string{"https://rp.example.com/support"}
			o.SANEmails = nil
			o.SANPhone = ""
		}},
		{"email_only", func(o *testpki.CertOpts) {
			o.SANURIs = nil
			o.SANEmails = []string{"support@rp.example.com"}
			o.SANPhone = ""
		}},
		{"phone_otherName_only", func(o *testpki.CertOpts) { o.SANURIs = nil; o.SANEmails = nil; o.SANPhone = "+491234567890" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := testpki.DefaultWRPAC()
			tt.mutate(&opts)
			leaf, _ := ca.Issue(t, opts)
			if _, err := rpcert.LoadWRPAC(testpki.ChainDER(leaf, ca.Cert)); err != nil {
				t.Fatalf("LoadWRPAC: %v", err)
			}
		})
	}
}

// The negative matrix: each broken element → its own sentinel.
func TestLoadWRPACProfileMatrix(t *testing.T) {
	ca := testpki.NewCA(t, "TEST ACCESS CA")
	tests := []struct {
		name    string
		mutate  func(*testpki.CertOpts)
		wantErr error
	}{
		{
			"no_policy_extension",
			func(o *testpki.CertOpts) { o.Policies = nil },
			rpcert.ErrPolicyOID,
		},
		{
			// A TSP-allocated policy alone does not satisfy GEN-6.6.1-03's
			// eudiwrp requirement for our verifier (fail closed).
			"wrong_policy_oid",
			func(o *testpki.CertOpts) { o.Policies = [][]uint64{{1, 3, 6, 1, 4, 1, 99999, 1}} },
			rpcert.ErrPolicyOID,
		},
		{
			"no_contact_san",
			func(o *testpki.CertOpts) { o.SANURIs = nil; o.SANEmails = nil; o.SANPhone = "" },
			rpcert.ErrContactSAN,
		},
		{
			"keyusage_missing_digitalSignature",
			func(o *testpki.CertOpts) { o.KeyUsage = x509.KeyUsageKeyEncipherment },
			rpcert.ErrKeyUsage,
		},
		{
			"eku_restricts_to_serverAuth",
			func(o *testpki.CertOpts) { o.EKUs = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
			rpcert.ErrExtKeyUsage,
		},
		{
			// Unknown child of the id-etsi-wrpa-entitlement arc: reject,
			// never fall through (TS 119 475 Annex A.2 is exhaustive).
			"unknown_entitlement_arc_child",
			func(o *testpki.CertOpts) {
				o.Policies = append(o.Policies, []uint64{0, 4, 0, 19475, 1, 99})
			},
			rpcert.ErrUnknownEntitlement,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testpki.DefaultWRPAC()
			tt.mutate(&opts)
			leaf, _ := ca.Issue(t, opts)
			_, err := rpcert.LoadWRPAC(testpki.ChainDER(leaf, ca.Cert))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// EKU absent, EKU=any and EKU=clientAuth are all acceptable (Decision 3).
func TestLoadWRPACEKUAllowed(t *testing.T) {
	ca := testpki.NewCA(t, "TEST ACCESS CA")
	for _, tt := range []struct {
		name string
		ekus []x509.ExtKeyUsage
	}{
		{"absent", nil},
		{"any", []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
		{"clientAuth", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := testpki.DefaultWRPAC()
			opts.EKUs = tt.ekus
			leaf, _ := ca.Issue(t, opts)
			if _, err := rpcert.LoadWRPAC(testpki.ChainDER(leaf, ca.Cert)); err != nil {
				t.Fatalf("LoadWRPAC: %v", err)
			}
		})
	}
}

// Entitlement extraction: arc children map to their Annex A.2 URIs; a WRPAC
// without entitlements is legal (the ≥1 rule is WRPRC-only, GEN-5.2.4-03).
func TestLoadWRPACEntitlementExtraction(t *testing.T) {
	ca := testpki.NewCA(t, "TEST ACCESS CA")

	opts := testpki.DefaultWRPAC()
	opts.Policies = [][]uint64{
		{0, 4, 0, 194118, 1, 4}, // QCP-l-eudiwrp
		{0, 4, 0, 19475, 1, 1},  // Service_Provider
		{0, 4, 0, 19475, 1, 3},  // Non_Q_EAA_Provider
	}
	leaf, _ := ca.Issue(t, opts)
	w, err := rpcert.LoadWRPAC(testpki.ChainDER(leaf, ca.Cert))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		rpcert.EntitlementServiceProvider,
		rpcert.EntitlementNonQEAAProvider,
	}
	if len(w.Entitlements) != 2 || w.Entitlements[0] != want[0] || w.Entitlements[1] != want[1] {
		t.Errorf("Entitlements = %v, want %v", w.Entitlements, want)
	}

	t.Run("no_entitlements_is_legal", func(t *testing.T) {
		opts := testpki.DefaultWRPAC()
		opts.Policies = [][]uint64{{0, 4, 0, 194118, 1, 4}}
		leaf, _ := ca.Issue(t, opts)
		w, err := rpcert.LoadWRPAC(testpki.ChainDER(leaf, ca.Cert))
		if err != nil {
			t.Fatal(err)
		}
		if len(w.Entitlements) != 0 {
			t.Errorf("Entitlements = %v, want empty", w.Entitlements)
		}
	})
}

// Decision 2: no intermediary entitlement exists at EU level (TS 119 475
// Annex A.2 has none; TS5 §2.1 Note: isIntermediary is API-only). Even a
// WRPAC carrying every Annex A.2 entitlement is NOT intermediary-capable;
// the authoritative check is T-07.9's registrar linkage.
func TestLoadWRPACIntermediaryCapabilityIsAPIOnly(t *testing.T) {
	ca := testpki.NewCA(t, "TEST ACCESS CA")
	opts := testpki.DefaultWRPAC()
	opts.Policies = [][]uint64{{0, 4, 0, 194118, 1, 4}}
	for child := uint64(1); child <= 10; child++ {
		opts.Policies = append(opts.Policies, []uint64{0, 4, 0, 19475, 1, child})
	}
	leaf, _ := ca.Issue(t, opts)
	w, err := rpcert.LoadWRPAC(testpki.ChainDER(leaf, ca.Cert))
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Entitlements) != 10 {
		t.Errorf("len(Entitlements) = %d, want 10", len(w.Entitlements))
	}
	if w.IsIntermediaryCapable {
		t.Error("IsIntermediaryCapable = true; no certificate-level intermediary marker exists (TS5 §2.1)")
	}
}

func TestLoadWRPACMalformedInput(t *testing.T) {
	if _, err := rpcert.LoadWRPAC(nil); !errors.Is(err, rpcert.ErrChainEmpty) {
		t.Errorf("nil chain: err = %v, want ErrChainEmpty", err)
	}
	if _, err := rpcert.LoadWRPAC([][]byte{[]byte("not a certificate")}); !errors.Is(err, rpcert.ErrMalformed) {
		t.Errorf("garbage: err = %v, want ErrMalformed", err)
	}
	if _, err := rpcert.LoadWRPAC([][]byte{{}}); !errors.Is(err, rpcert.ErrMalformed) {
		t.Errorf("empty element: err = %v, want ErrMalformed", err)
	}
}
