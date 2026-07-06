package rpcert

import "crypto"

// KeyProvenance records how a registrar verification key was obtained, for
// the verification report's provenance (WP-07 Decision 8; README Decisions).
type KeyProvenance string

const (
	// ProvenancePinned — key came from explicit per-registry config
	// (until MS registrars publish keys uniformly).
	ProvenancePinned KeyProvenance = "pinned"
	// ProvenanceTrustService — key resolved via the trust service
	// wrprc_issuer/registrar metadata (wired in WP-09).
	ProvenanceTrustService KeyProvenance = "trust-service"
)

// RegistrarKeys resolves a registrar's JWS verification key. kid is the JWS
// "kid" header (may be empty when a registry publishes a single key).
type RegistrarKeys interface {
	KeyFor(registryURI, kid string) (crypto.PublicKey, KeyProvenance, error)
}

// PinnedRegistrarKeys is the config-driven pinning implementation: one
// public key per registry base URL (TS5 §3.2.2 leaves key discovery to
// deployment — see WP-07 README Decisions).
type PinnedRegistrarKeys struct {
	byURI map[string]crypto.PublicKey
}

// NewPinnedRegistrarKeys copies the provided registry-URI → key map.
func NewPinnedRegistrarKeys(keys map[string]crypto.PublicKey) *PinnedRegistrarKeys {
	m := make(map[string]crypto.PublicKey, len(keys))
	for k, v := range keys {
		m[k] = v
	}
	return &PinnedRegistrarKeys{byURI: m}
}

// KeyFor returns the pinned key for registryURI (kid ignored — one key per
// registry in the pinned model).
func (p *PinnedRegistrarKeys) KeyFor(registryURI, _ string) (crypto.PublicKey, KeyProvenance, error) {
	k, ok := p.byURI[registryURI]
	if !ok {
		return nil, "", ErrNoRegistrarKey
	}
	return k, ProvenancePinned, nil
}
