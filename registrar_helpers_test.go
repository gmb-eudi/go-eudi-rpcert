package rpcert_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// signRegistrarJWS produces a compact ES256 JWS over payload with kid in the
// protected header (TS5 v1.3 §3.2.2: "signed according to IETF 7515").
func signRegistrarJWS(t testing.TB, payload []byte, key *ecdsa.PrivateKey, kid string) string {
	t.Helper()
	return string(signCompactJWS(t, map[string]any{"alg": "ES256", "kid": kid, "typ": "JWT"}, payload, key))
}

// registrarServer is an httptest registrar serving JWS-signed fixtures.
type registrarServer struct {
	srv      *httptest.Server
	key      *ecdsa.PrivateKey
	kid      string
	pages    map[string]string // cursor "" = first page; value = fixture file
	single   string            // fixture for /wrp/{id}
	tamper   bool              // corrupt the signature
	status   int               // non-zero overrides 200
	lastReqs []url.Values      // captured query params per /wrp call
}

func newRegistrarServer(t testing.TB, key *ecdsa.PrivateKey) *registrarServer {
	t.Helper()
	rs := &registrarServer{
		key:    key,
		kid:    "reg-key-1",
		pages:  map[string]string{"": "wrp-page1.json", "b3BhcXVlLXBhZ2UtMg": "wrp-page2.json"},
		single: "wrp-single.json",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/wrp", func(w http.ResponseWriter, r *http.Request) { rs.serveList(t, w, r) })
	mux.HandleFunc("/wrp/", func(w http.ResponseWriter, r *http.Request) { rs.serveSingle(t, w, r) })
	rs.srv = httptest.NewServer(mux)
	t.Cleanup(rs.srv.Close)
	return rs
}

func (rs *registrarServer) serveList(t testing.TB, w http.ResponseWriter, r *http.Request) {
	rs.lastReqs = append(rs.lastReqs, r.URL.Query())
	if rs.status != 0 {
		w.WriteHeader(rs.status)
		return
	}
	fixture, ok := rs.pages[r.URL.Query().Get("cursor")]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	rs.writeSigned(t, w, fixture)
}

func (rs *registrarServer) serveSingle(t testing.TB, w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/wrp/")
	if id == "" || rs.single == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	rs.writeSigned(t, w, rs.single)
}

func (rs *registrarServer) writeSigned(t testing.TB, w http.ResponseWriter, fixture string) {
	//nolint:gosec // G304: fixture is always one of registrarServer's compile-time-constant page/single filenames from this test file, never external input.
	payload, err := os.ReadFile("testdata/ts5/" + fixture)
	if err != nil {
		t.Fatal(err)
	}
	token := signRegistrarJWS(t, payload, rs.key, rs.kid)
	if rs.tamper {
		token = flipLastByte(token)
	}
	w.Header().Set("Content-Type", "application/jwt")
	if _, err := w.Write([]byte(token)); err != nil {
		t.Fatal(err)
	}
}

// flipLastByte corrupts the signature segment (base64url) so verification fails.
func flipLastByte(token string) string {
	parts := strings.Split(token, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if len(sig) == 0 {
		sig = []byte{0}
	}
	sig[len(sig)-1] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join(parts, ".")
}

// pinnedKeysFor builds a RegistrarKeys pinning the server's public key to
// the server URL (per-registry key pinning — WP-07 Decision 8).
func pinnedKeysFor(rs *registrarServer) crypto.PublicKey { return rs.key.Public() }

// jsonPayload marshals v for ad-hoc fixtures.
func jsonPayload(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var _ = sha256.Sum256 // keep import stable if helpers evolve

// httptestNewServer starts a server and registers cleanup.
func httptestNewServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

// writeIntendedUseFixture writes a SignedWRP whose data has one intended use
// with the given lifecycle dates, then removes it on cleanup.
func writeIntendedUseFixture(t testing.TB, name, iuID, created, revoked string) {
	t.Helper()
	iu := map[string]any{
		"purpose":               []any{map[string]any{"lang": "en", "content": "x"}},
		"privacyPolicy":         []any{map[string]any{"type": "http://data.europa.eu/eudi/policy/privacy-policy", "policyURI": "https://rp.example.com/privacy"}},
		"intendedUseIdentifier": iuID,
		"createdAt":             created,
		"credentials":           []any{map[string]any{"format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:eudi:pid:1"}}, "claims": []any{map[string]any{"path": []any{"given_name"}}}}},
	}
	if revoked != "" {
		iu["revokedAt"] = revoked
	}
	doc := map[string]any{
		"iss": "https://registrar.example-ms.eu", "iat": 1783155600,
		"data": map[string]any{
			"tradeName": "Example Age Check", "supportURI": []any{"https://rp.example.com/support"},
			"srvDescription": []any{[]any{map[string]any{"lang": "en", "content": "svc"}}},
			"isPSB":          false, "isIntermediary": false,
			"entitlements":         []any{"https://uri.etsi.org/19475/Entitlement/Service_Provider"},
			"supervisoryAuthority": map[string]any{"name": "DPA", "country": "DE"},
			"registryURI":          "https://registrar.example-ms.eu/api",
			"country":              "DE",
			"identifier":           []any{map[string]any{"type": "http://data.europa.eu/eudi/id/EUID", "identifier": "DEUTR.HRB123456"}},
			"intendedUse":          []any{iu},
		},
	}
	path := "testdata/ts5/" + name
	if err := os.WriteFile(path, jsonPayload(t, doc), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
}

// writeLeakyFixture writes testdata/ts5/wrp-leaky.json — a wrp-page1.json
// variant with a top-level postalAddress injected into data[0] — to exercise
// the physicalAddress-absent assertion (ts5.ErrAddressPresent). The fixture
// is removed via t.Cleanup so it never lands in a commit.
func writeLeakyFixture(t testing.TB) {
	t.Helper()
	raw, err := os.ReadFile("testdata/ts5/wrp-page1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	data, ok := doc["data"].([]any)
	if !ok || len(data) == 0 {
		t.Fatal("wrp-page1.json: data[0] missing")
	}
	entry, ok := data[0].(map[string]any)
	if !ok {
		t.Fatal("wrp-page1.json: data[0] is not an object")
	}
	entry["postalAddress"] = []any{"Musterstr. 1"}
	data[0] = entry
	doc["data"] = data
	out := jsonPayload(t, doc)
	const path = "testdata/ts5/wrp-leaky.json"
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
}
