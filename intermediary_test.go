package rpcert_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	"github.com/gmb-eudi/go-eudi-rpcert/internal/testpki"
)

// linkageServer serves GET /wrp/{id} from a chosen fixture, JWS-signed.
func startLinkageServer(t *testing.T, key *ecdsa.PrivateKey, fixture string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/wrp/", func(w http.ResponseWriter, _ *http.Request) {
		//nolint:gosec // G304: fixture is always one of this test file's compile-time-constant fixture filenames, never external input.
		payload, err := os.ReadFile("testdata/ts5/" + fixture)
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/jwt")
		if _, err := w.Write([]byte(signRegistrarJWS(t, payload, key, "reg-key-1"))); err != nil {
			t.Fatal(err)
		}
	})
	srv := httptestNewServer(t, mux)
	return srv.URL
}

func linkageClient(t *testing.T, urlStr string, key *ecdsa.PrivateKey) *rpcert.RegistrarClient {
	t.Helper()
	return rpcert.NewRegistrarClient(&http.Client{},
		rpcert.NewPinnedRegistrarKeys(map[string]crypto.PublicKey{urlStr: key.Public()}),
		rpcert.WithClock(func() time.Time { return testpki.Clock }),
		rpcert.WithMaxResponseAge(48*time.Hour),
	)
}

// T-07.9 acceptance: linked / unlinked / stale fixtures. Linkage is only
// verifiable via the API (ARF TS5 v1.3 §2.1 Note — isIntermediary/
// usesIntermediary are not in certificates).
func TestVerifyIntermediaryLinkage(t *testing.T) {
	key := genP256(t)
	const operatorID = "529900EXAMPLE0000001"
	const clientID = "DEUTR.HRB123456"

	t.Run("linked", func(t *testing.T) {
		urlStr := startLinkageServer(t, key, "wrp-linked.json")
		c := linkageClient(t, urlStr, key)
		res, err := c.VerifyIntermediaryLinkage(context.Background(), urlStr, clientID, operatorID)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Linked || res.OperatorID != operatorID || res.ClientID != clientID {
			t.Errorf("result = %+v, want linked", res)
		}
		if res.Provenance.KeyProvenance != rpcert.ProvenancePinned {
			t.Errorf("provenance = %+v, want pinned", res.Provenance)
		}
	})

	t.Run("unlinked_lists_other_operator", func(t *testing.T) {
		urlStr := startLinkageServer(t, key, "wrp-unlinked.json")
		c := linkageClient(t, urlStr, key)
		res, err := c.VerifyIntermediaryLinkage(context.Background(), urlStr, clientID, operatorID)
		if !errors.Is(err, rpcert.ErrNotLinked) {
			t.Fatalf("err = %v, want ErrNotLinked", err)
		}
		if res.Linked {
			t.Error("result.Linked = true for a different operator")
		}
	})

	t.Run("stale_no_intermediary_listed", func(t *testing.T) {
		urlStr := startLinkageServer(t, key, "wrp-stale.json")
		c := linkageClient(t, urlStr, key)
		if _, err := c.VerifyIntermediaryLinkage(context.Background(), urlStr, clientID, operatorID); !errors.Is(err, rpcert.ErrNotLinked) {
			t.Fatalf("err = %v, want ErrNotLinked", err)
		}
	})

	t.Run("client_not_found", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/wrp/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
		srv := httptestNewServer(t, mux)
		c := linkageClient(t, srv.URL, key)
		if _, err := c.VerifyIntermediaryLinkage(context.Background(), srv.URL, clientID, operatorID); !errors.Is(err, rpcert.ErrWRPNotFound) {
			t.Fatalf("err = %v, want ErrWRPNotFound", err)
		}
	})

	t.Run("empty_operator_id", func(t *testing.T) {
		urlStr := startLinkageServer(t, key, "wrp-linked.json")
		c := linkageClient(t, urlStr, key)
		if _, err := c.VerifyIntermediaryLinkage(context.Background(), urlStr, clientID, ""); !errors.Is(err, rpcert.ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})
}
