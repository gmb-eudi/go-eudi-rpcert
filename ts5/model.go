package ts5

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// WalletRelyingParty — [ARF TS5 v1.3 §2.1]. Inherits the LegalEntity attributes
// ([ARF TS5 §2.3]: "WalletRelyingParty class inherits all attributes of this class").
// physicalAddress/postalAddress deliberately has NO field: API responses
// exclude it ([ARF TS5 §3.2.1]) and the decoders reject it (ErrAddressPresent).
type WalletRelyingParty struct {
	TradeName            string                `json:"tradeName,omitempty"`
	SupportURI           []string              `json:"supportURI,omitempty"`
	SrvDescription       [][]MultiLangString   `json:"srvDescription,omitempty"`
	IntendedUse          []IntendedUse         `json:"intendedUse,omitempty"`
	IsPSB                bool                  `json:"isPSB"`
	Entitlements         []string              `json:"entitlements,omitempty"`
	ProvidesAttestations []ProvidedAttestation `json:"providesAttestations,omitempty"`
	SupervisoryAuthority SupervisoryAuthority  `json:"supervisoryAuthority,omitempty"`
	RegistryURI          string                `json:"registryURI,omitempty"`
	UsesIntermediary     []WalletRelyingParty  `json:"usesIntermediary,omitempty"`
	IsIntermediary       bool                  `json:"isIntermediary"`

	// LegalEntity attributes ([ARF TS5 §2.3] / TS 119 475 Annex B.2.2)
	LegalPerson   *LegalPerson   `json:"legalPerson,omitempty"`
	NaturalPerson *NaturalPerson `json:"naturalPerson,omitempty"`
	Identifiers   []Identifier   `json:"identifier,omitempty"`
	Country       string         `json:"country,omitempty"`
	Email         []string       `json:"email,omitempty"`
	Phone         []string       `json:"phone,omitempty"`
	InfoURI       []string       `json:"infoURI,omitempty"`
}

// IntendedUse — [ARF TS5 v1.3 §2.4.3].
type IntendedUse struct {
	Purpose               []MultiLangString `json:"purpose"`
	PrivacyPolicy         []Policy          `json:"privacyPolicy"`
	IntendedUseIdentifier string            `json:"intendedUseIdentifier"`
	CreatedAt             string            `json:"createdAt"`           // ISO 8601-1 YYYY-MM-DD
	RevokedAt             string            `json:"revokedAt,omitempty"` // ISO 8601-1 YYYY-MM-DD
	Credentials           []Credential      `json:"credentials"`
}

// Credential — [ARF TS5 v1.3 §2.4.4]. Meta is the [OID4VP §6.1] per-format object
// (e.g. {"vct_values": [...]} for dc+sd-jwt, {"doctype_value": "..."} for
// mso_mdoc).
type Credential struct {
	Format string          `json:"format"`
	Meta   json.RawMessage `json:"meta,omitempty"`
	Claims []Claim         `json:"claims,omitempty"`
}

// Claim — [ARF TS5 v1.3 §2.4.1].
type Claim struct {
	Path ClaimPath `json:"path"`
}

// ClaimPath is an [OID4VP §7] claims path pointer: non-empty array of string
// (object key), non-negative integer (array index, stored as int) or null
// (wildcard, stored as nil). Untrusted input — validated on unmarshal.
type ClaimPath []any

// UnmarshalJSON enforces [OID4VP §7] element syntax.
func (p *ClaimPath) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var raw []any
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		return fmt.Errorf("claim path must be a non-empty array (OID4VP §7)")
	}
	out := make(ClaimPath, 0, len(raw))
	for i, e := range raw {
		switch v := e.(type) {
		case nil:
			out = append(out, nil)
		case string:
			out = append(out, v)
		case json.Number:
			n, err := strconv.Atoi(string(v))
			if err != nil || n < 0 {
				return fmt.Errorf("claim path[%d]: index must be a non-negative integer (OID4VP §7)", i)
			}
			out = append(out, n)
		default:
			return fmt.Errorf("claim path[%d]: element must be string, non-negative integer or null (OID4VP §7)", i)
		}
	}
	*p = out
	return nil
}

// MultiLangString — [ARF TS5 v1.3 §2.4.5].
type MultiLangString struct {
	Lang    string `json:"lang"`
	Content string `json:"content"`
}

// SupervisoryAuthority — [ARF TS5 v1.3 §2.4.6].
type SupervisoryAuthority struct {
	Name    string   `json:"name,omitempty"`
	Country string   `json:"country,omitempty"`
	Email   []string `json:"email,omitempty"`
	Phone   []string `json:"phone,omitempty"`
	FormURI []string `json:"formURI,omitempty"`
}

// ProvidedAttestation — [ARF TS5 v1.3 §2.4.7].
type ProvidedAttestation struct {
	Format string          `json:"format"`
	Meta   json.RawMessage `json:"meta,omitempty"`
}

// Identifier — TS 119 475 Annex B.2.5 (referenced by [ARF TS5 §2.4.2]). Type is
// one of the http://data.europa.eu/eudi/id/* URIs (or a national extension).
type Identifier struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

// Policy — TS 119 475 Annex B.2.8 (referenced by [ARF TS5 §2.4.8]).
type Policy struct {
	Type      string `json:"type"`
	PolicyURI string `json:"policyURI"`
}

// LegalPerson — TS 119 475 Annex B.2.3.
type LegalPerson struct {
	LegalName        []string `json:"legalName"`
	EstablishedByLaw []Law    `json:"establishedBylaw,omitempty"`
}

// NaturalPerson — TS 119 475 Annex B.2.4.
type NaturalPerson struct {
	GivenName    string `json:"givenName"`
	FamilyName   string `json:"familyName"`
	DateOfBirth  string `json:"dateOfBirth,omitempty"`
	PlaceOfBirth string `json:"placeOfBirth,omitempty"`
}

// Law — TS 119 475 Annex B.2.11.
type Law struct {
	Lang       string `json:"lang"`
	LegalBasis string `json:"legalBasis"`
}

// SignedWRPArray is the JWS payload of GET /wrp (OpenAPI components:
// SignedWRPArray; iss/iat/data required).
type SignedWRPArray struct {
	Iss        string               `json:"iss"`
	Iat        int64                `json:"iat"`
	Data       []WalletRelyingParty `json:"data"`
	Pagination *Pagination          `json:"pagination,omitempty"`
}

// Pagination — cursor-based (OpenAPI: next_cursor / has_next_page).
type Pagination struct {
	NextCursor  string `json:"next_cursor,omitempty"`
	HasNextPage bool   `json:"has_next_page"`
}

// SignedWRP is the JWS payload of GET /wrp/{identifier}.
type SignedWRP struct {
	Iss  string             `json:"iss"`
	Iat  int64              `json:"iat"`
	Data WalletRelyingParty `json:"data"`
}

// SignedIntendedUseCheckResult is the JWS payload of
// GET /wrp/check-intended-use.
type SignedIntendedUseCheckResult struct {
	Iss  string                 `json:"iss"`
	Iat  int64                  `json:"iat"`
	Data IntendedUseCheckResult `json:"data"`
}

// IntendedUseCheckResult — OpenAPI: data.isRegistered (+ optional details).
type IntendedUseCheckResult struct {
	IsRegistered bool   `json:"isRegistered"`
	Details      string `json:"details,omitempty"`
}
