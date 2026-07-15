package rpcert

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// RegistrationRef is the ARF RPRC_19a registration reference embedded in EVERY
// authorization request (ADR-0003 decision 2) — with or without an attached
// WRPRC — so wallets can query the registrar themselves: the client's
// display name, its registered unique identifier, the national registry
// API URL (CIR (EU) 2025/848 Art. 3(5)) and the intended-use identifier.
type RegistrationRef struct {
	ClientName    string
	ClientID      string
	RegistryURI   string
	IntendedUseID string
}

// NewRegistrationRef validates and builds the reference. All four fields
// are required (ADR-0003 names all four); an incomplete reference cannot be
// built, so WP-08 can guarantee "always present" structurally.
func NewRegistrationRef(clientName, clientID, registryURI, intendedUseID string) (RegistrationRef, error) {
	r := RegistrationRef{
		ClientName:    clientName,
		ClientID:      clientID,
		RegistryURI:   registryURI,
		IntendedUseID: intendedUseID,
	}
	if err := r.Validate(); err != nil {
		return RegistrationRef{}, err
	}
	return r, nil
}

// Validate re-checks completeness (WP-08 calls it before request build).
func (r RegistrationRef) Validate() error {
	switch {
	case r.ClientName == "":
		return fmt.Errorf("%w: client name", ErrRegistrationRef)
	case r.ClientID == "":
		return fmt.Errorf("%w: client id", ErrRegistrationRef)
	case r.IntendedUseID == "":
		return fmt.Errorf("%w: intended-use id", ErrRegistrationRef)
	}
	u, err := url.Parse(r.RegistryURI)
	if err != nil || !u.IsAbs() || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%w: registry URI must be an absolute https URL", ErrRegistrationRef)
	}
	return nil
}

// registrationRefJSON pins the wire form to the TS 119 475 §5.2.4 Table 7/9
// claim vocabulary — name, sub, registry_uri, intended_use_id (WP-07
// Decision 9). The enclosing request-object claim name is WP-08's decision.
type registrationRefJSON struct {
	Name          string `json:"name"`
	Sub           string `json:"sub"`
	RegistryURI   string `json:"registry_uri"`
	IntendedUseID string `json:"intended_use_id"`
}

// MarshalJSON serializes the reference; an incomplete reference fails, so a
// half-built RegistrationRef can never reach a request object.
func (r RegistrationRef) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(registrationRefJSON{
		Name:          r.ClientName,
		Sub:           r.ClientID,
		RegistryURI:   r.RegistryURI,
		IntendedUseID: r.IntendedUseID,
	})
}

// UnmarshalJSON parses the wire shape written by MarshalJSON and validates
// completeness, so a corrupted or truncated stored value fails loudly
// rather than silently decoding to a zero-value reference (hard rule 7,
// fail closed) — MarshalJSON alone made RegistrationRef write-only under
// encoding/json (the default field-name-matching reflection cannot map
// "registry_uri" etc. back onto ClientName/ClientID/RegistryURI/
// IntendedUseID), which broke WP-08's Session/SessionStore JSON
// round-trip contract (Session embeds RegistrationRef directly).
func (r *RegistrationRef) UnmarshalJSON(data []byte) error {
	var wire registrationRefJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	ref := RegistrationRef{
		ClientName:    wire.Name,
		ClientID:      wire.Sub,
		RegistryURI:   wire.RegistryURI,
		IntendedUseID: wire.IntendedUseID,
	}
	if err := ref.Validate(); err != nil {
		return err
	}
	*r = ref
	return nil
}

// Claims returns the reference as request-object claim values for WP-08's
// request builder (ARF RPRC_19a extension).
func (r RegistrationRef) Claims() (map[string]any, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return map[string]any{
		"name":            r.ClientName,
		"sub":             r.ClientID,
		"registry_uri":    r.RegistryURI,
		"intended_use_id": r.IntendedUseID,
	}, nil
}
