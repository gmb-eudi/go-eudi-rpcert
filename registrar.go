package rpcert

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
	"github.com/gmb-eudi/go-eudi-rpcert/ts5"
)

// Default limits (WP-07 Decision 7 + a pagination safety cap).
const (
	defaultMaxResponseAge = 24 * time.Hour
	defaultMaxPages       = 100
	defaultLimit          = 20 // TS5 OpenAPI default
)

// Provenance is attached to the verification report so an operator can see
// which registry answered and how its signing key was trusted.
type Provenance struct {
	RegistryURI   string
	KeyProvenance KeyProvenance
}

// RegistrarClient is a typed TS5 v1.3 Registrar API client with JWS
// response verification. Framework-free: injected Doer + clock (ADR-0004).
type RegistrarClient struct {
	doer           Doer
	keys           RegistrarKeys
	clock          func() time.Time
	maxResponseAge time.Duration
	maxPages       int

	mu   sync.Mutex
	prov Provenance
}

// RegistrarOption configures a RegistrarClient.
type RegistrarOption func(*RegistrarClient)

// WithClock injects the clock (docs/conventions.md time rule).
func WithClock(clock func() time.Time) RegistrarOption {
	return func(c *RegistrarClient) {
		if clock != nil {
			c.clock = clock
		}
	}
}

// WithMaxResponseAge sets the freshness window for the response iat
// (WP-07 Decision 7).
func WithMaxResponseAge(d time.Duration) RegistrarOption {
	return func(c *RegistrarClient) {
		if d > 0 {
			c.maxResponseAge = d
		}
	}
}

// WithMaxPages caps cursor pagination (fail closed against a runaway
// registrar).
func WithMaxPages(n int) RegistrarOption {
	return func(c *RegistrarClient) {
		if n > 0 {
			c.maxPages = n
		}
	}
}

// NewRegistrarClient builds the client.
func NewRegistrarClient(doer Doer, keys RegistrarKeys, opts ...RegistrarOption) *RegistrarClient {
	c := &RegistrarClient{
		doer:           doer,
		keys:           keys,
		clock:          time.Now,
		maxResponseAge: defaultMaxResponseAge,
		maxPages:       defaultMaxPages,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// LastProvenance returns the provenance of the most recent verified
// response (for the report). Safe for concurrent use.
func (c *RegistrarClient) LastProvenance() Provenance {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.prov
}

func (c *RegistrarClient) setProvenance(p Provenance) {
	c.mu.Lock()
	c.prov = p
	c.mu.Unlock()
}

// WRPQuery mirrors the GET /wrp query parameters (TS5 v1.3 OpenAPI). Empty
// fields are omitted; IsIntermediary is a *bool so "unset" ≠ "false".
type WRPQuery struct {
	Identifier            string
	LegalName             string
	TradeName             string
	Policy                string
	Entitlement           string
	CredentialMeta        string
	CredentialFormat      string
	UsesIntermediary      string
	IsIntermediary        *bool
	IntendedUseIdentifier string
	Limit                 int
}

func (q WRPQuery) values() url.Values {
	v := url.Values{}
	set := func(k, val string) {
		if val != "" {
			v.Set(k, val)
		}
	}
	set("identifier", q.Identifier)
	set("legalname", q.LegalName)
	set("tradename", q.TradeName)
	set("policy", q.Policy)
	set("entitlement", q.Entitlement)
	set("credentialmeta", q.CredentialMeta)
	set("credentialformat", q.CredentialFormat)
	set("usesintermediary", q.UsesIntermediary)
	set("intendeduseidentifier", q.IntendedUseIdentifier)
	if q.IsIntermediary != nil {
		v.Set("isintermediary", strconv.FormatBool(*q.IsIntermediary))
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	return v
}

// GetWRP queries GET /wrp and joins all cursor pages (TS5 v1.3 §3.2.2).
func (c *RegistrarClient) GetWRP(ctx context.Context, registryURI string, q WRPQuery) ([]ts5.WalletRelyingParty, error) {
	base := q.values()
	var all []ts5.WalletRelyingParty
	cursor := ""
	for page := 0; ; page++ {
		if page >= c.maxPages {
			return nil, fmt.Errorf("%w: > %d pages", ErrTooManyPages, c.maxPages)
		}
		params := cloneValues(base)
		if cursor != "" {
			params.Set("cursor", cursor)
		}
		payload, err := c.fetch(ctx, registryURI, "/wrp", params)
		if err != nil {
			return nil, err
		}
		env, err := ts5.DecodeSignedWRPArray(payload)
		if err != nil {
			return nil, err
		}
		all = append(all, env.Data...)
		if env.Pagination == nil || !env.Pagination.HasNextPage {
			break
		}
		if env.Pagination.NextCursor == "" {
			return nil, fmt.Errorf("%w: has_next_page with empty next_cursor", ErrPagination)
		}
		// NOTE: a repeating cursor (registrar stuck on the same page) is
		// deliberately NOT rejected here — maxPages (WithMaxPages) is the
		// single fail-closed backstop against any runaway pagination,
		// repeating-cursor or otherwise (WP-07 T-07.7 self-review: an
		// earlier "cursor did not advance" check pre-empted the page-cap
		// test before the cap could trip).
		cursor = env.Pagination.NextCursor
	}
	return all, nil
}

// GetWRPByID queries GET /wrp/{identifier} (TS5 v1.3 §3.2.2).
func (c *RegistrarClient) GetWRPByID(ctx context.Context, registryURI, identifier string) (*ts5.WalletRelyingParty, error) {
	if identifier == "" {
		return nil, fmt.Errorf("%w: empty identifier", ErrMalformed)
	}
	payload, err := c.fetch(ctx, registryURI, "/wrp/"+url.PathEscape(identifier), nil)
	if err != nil {
		return nil, err
	}
	env, err := ts5.DecodeSignedWRP(payload)
	if err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// fetch performs one GET, checks status, verifies the JWS response and its
// freshness, and returns the decoded payload bytes. Verified-payload bytes
// are the ts5 decoders' input; this method owns all trust decisions.
func (c *RegistrarClient) fetch(ctx context.Context, registryURI, path string, params url.Values) ([]byte, error) {
	u, err := joinURL(registryURI, path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(params) > 0 {
		u.RawQuery = params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	req.Header.Set("Accept", "application/jwt")
	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRegistrarUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrWRPNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrRegistrarStatus, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // 8 MiB cap
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRegistrarUnavailable, err)
	}
	return c.verifyResponse(registryURI, body)
}

// verifyResponse checks the JWS signature (via the pinned/trust-service key)
// and the payload iat freshness, and records provenance.
func (c *RegistrarClient) verifyResponse(registryURI string, token []byte) ([]byte, error) {
	kid, err := jwsKID(token)
	if err != nil {
		return nil, err
	}
	key, prov, err := c.keys.KeyFor(registryURI, kid)
	if err != nil {
		return nil, err
	}
	payload, _, err := eudicrypto.VerifyJWS(token, key) // alg from key (hard rule 4)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrResponseSignature, err)
	}
	if err := c.checkFreshness(payload); err != nil {
		return nil, err
	}
	c.setProvenance(Provenance{RegistryURI: registryURI, KeyProvenance: prov})
	return payload, nil
}

// checkFreshness enforces the response-age window against the payload iat
// (WP-07 Decision 7). All TS5 envelopes carry iat.
func (c *RegistrarClient) checkFreshness(payload []byte) error {
	var env struct {
		Iat int64 `json:"iat"`
	}
	if err := json.Unmarshal(payload, &env); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if env.Iat <= 0 {
		return fmt.Errorf("%w: missing iat", ErrMalformed)
	}
	issued := time.Unix(env.Iat, 0).UTC()
	if c.clock().Sub(issued) > c.maxResponseAge {
		return fmt.Errorf("%w: issued %s", ErrStaleResponse, issued.Format(time.RFC3339))
	}
	return nil
}

// jwsKID reads the kid from the compact JWS protected header without
// verifying — only to select the verification key.
func jwsKID(token []byte) (string, error) {
	seg, _, ok := strings.Cut(string(token), ".")
	if !ok {
		return "", fmt.Errorf("%w: not a compact JWS", ErrResponseSignature)
	}
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return "", fmt.Errorf("%w: header segment: %v", ErrResponseSignature, err)
	}
	var h struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return "", fmt.Errorf("%w: header: %v", ErrResponseSignature, err)
	}
	return h.Kid, nil
}

func joinURL(base, path string) (*url.URL, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	if !u.IsAbs() {
		return nil, fmt.Errorf("registry URI is not absolute")
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u, nil
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}

var _ crypto.PublicKey // key type used via RegistrarKeys
