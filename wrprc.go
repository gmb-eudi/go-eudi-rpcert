package rpcert

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
	"github.com/gmb-eudi/go-eudi-rpcert/ts5"
)

// WRPRC serialization formats (WP-07 README public interface).
const (
	FormatJWT = "jwt"
	FormatCWT = "cwt"
)

// Credential format identifiers used in WRPRC/ARF TS5 credential entries —
// OpenID4VP 1.0 Annex B format ids (data formats, not crypto algorithms;
// hard rule 4 concerns algorithms only).
const (
	CredentialFormatSDJWTVC = "dc+sd-jwt" //nolint:gosec // G101: OpenID4VP data-format identifier, not a credential (name matches gosec's "cred" heuristic)
	CredentialFormatMdoc    = "mso_mdoc"
)

// WRPRCPolicyOID — ETSI TS 119 475 §6.1.3: itu-t(0)
// identified-organization(4) etsi(0) eudiwrpa(19475) policy-identifiers(3)
// wrprc(1). policy_id must reference it (OVR-6.1.3-01/-02).
const WRPRCPolicyOID = "0.4.0.19475.3.1"

// typ header values — ETSI TS 119 475 GEN-5.2.2-01 / GEN-5.2.3-01.
// The JWT form uses the abbreviated JOSE typ (RFC 7515/8725: the
// "application/" prefix is dropped). The CWT form carries the type in COSE
// protected-header label 16 (RFC 9596), whose value is a full media type —
// so the "application/" prefix is REQUIRED there (WP-07 Decision, T-07.5;
// same convention as go-statuslist's application/statuslist+cwt, and the
// only form the veraison/go-cose encoder in go-eudi-crypto accepts for a
// media-type header). "rc-wrp+cwt" alone is the media subtype, not the
// label-16 value.
const (
	wrprcTypJWT = "rc-wrp+jwt"
	wrprcTypCWT = "application/rc-wrp+cwt"
)

// LangValue is a TS 119 475 §5.2.4 localized string ({lang, value} — note:
// the WRPRC uses "value" where ARF TS5's MultiLangString uses "content").
type LangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// StatusRef points into the issuer's Token Status List
// (TS 119 475 GEN-6.2.6.1-04: status.status_list.{idx,uri}). Checked by the
// service via go-statuslist (WP-04) — see WP-07 Decision 11.
type StatusRef struct {
	Index int64  `json:"idx"`
	URI   string `json:"uri"`
}

// IntermediaryRef identifies the intermediary the WRP acts through
// (TS 119 475 Table 10 `intermediary`; Annex C uses subfield "name",
// Table 10 says "sname" — both accepted, see README corrections).
type IntermediaryRef struct {
	Subject string
	Name    string
}

// SupervisoryContact — TS 119 475 Table 7 supervisory_authority.
type SupervisoryContact struct {
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
	URI   string `json:"uri,omitempty"`
}

// RegisteredCredential mirrors one WRPRC credentials/provides_attestations
// entry (TS 119 475 Tables 8/9). It maps 1:1 onto dcql.RegisteredCredential
// (WP-05) for WithinScope checks; AllClaims=true when the claim list is
// absent (WP-07 Decision 12, OID4VP §6.1 semantics).
type RegisteredCredential struct {
	Format         string
	DoctypesOrVCTs []string
	AllClaims      bool
	Claims         []ts5.ClaimPath
}

// WRPRC is a parsed wallet-relying party registration certificate
// (ETSI TS 119 475 §5.2; CIR (EU) 2025/848 Art. 8 / Annex V).
type WRPRC struct {
	Raw    []byte
	Format string // FormatJWT | FormatCWT
	Chain  []*x509.Certificate

	Name                  string
	LegalName             string // sub_ln (legal person)
	GivenName             string // sub_gn (natural person)
	FamilyName            string // sub_fn (natural person)
	Subject               string // sub — registered WRP identifier (GEN-5.2.4-02)
	Country               string
	RegistryURI           string
	SrvDescription        [][]LangValue
	Entitlements          []string
	PrivacyPolicy         string
	InfoURI               string
	SupportURI            string
	SupervisoryAuthority  SupervisoryContact
	PolicyIDs             []string
	CertificatePolicy     string
	PublicBody            bool
	IssuedAt              time.Time
	ExpiresAt             time.Time // zero = no exp claim
	Status                *StatusRef
	Purpose               []LangValue
	IntendedUseID         string
	RegisteredCredentials []RegisteredCredential
	ProvidesAttestations  []RegisteredCredential
	Intermediary          *IntermediaryRef
}

// ParseWRPRC parses a WRPRC in JWT or CWT form WITHOUT verifying its
// signature — call (*WRPRC).Verify next (TS 119 475 GEN-5.2.1-01: "signed
// JSON Web Token (JWT) or CBOR Web Token (CWT)").
func ParseWRPRC(raw []byte) (*WRPRC, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty input", ErrMalformed)
	}
	// COSE_Sign1 sniff: tag 18 (0xd2) or the 4-element array (0x84) —
	// RFC 9052 §4.2. Everything else with exactly two dots is compact JWS.
	if raw[0] == 0xd2 || raw[0] == 0x84 {
		return parseWRPRCCWT(raw)
	}
	if bytes.Count(raw, []byte(".")) == 2 {
		return parseWRPRCJWT(raw)
	}
	return parseWRPRCCWT(raw)
}

// parseWRPRCJWT — header per TS 119 475 GEN-5.2.2-01 (Table 5): typ
// rc-wrp+jwt, alg, x5c. The alg VALUE is judged only by go-eudi-crypto at
// Verify time (hard rule 4) — here only its presence is structural.
func parseWRPRCJWT(raw []byte) (*WRPRC, error) {
	parts := bytes.Split(raw, []byte("."))
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: compact JWS needs 3 segments", ErrWRPRCFormat)
	}
	headRaw, err := base64.RawURLEncoding.DecodeString(string(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("%w: header segment: %v", ErrMalformed, err)
	}
	var head struct {
		Typ string   `json:"typ"`
		Alg string   `json:"alg"`
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(headRaw, &head); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	if head.Typ != wrprcTypJWT {
		return nil, fmt.Errorf("%w: typ %q, want %q", ErrWRPRCType, head.Typ, wrprcTypJWT)
	}
	if head.Alg == "" {
		return nil, fmt.Errorf("%w: alg header missing", ErrMalformed)
	}
	if len(head.X5C) == 0 {
		return nil, fmt.Errorf("%w: x5c header missing (GEN-5.2.2-01)", ErrChainEmpty)
	}
	var chain []*x509.Certificate
	for i, b64 := range head.X5C {
		der, err := base64.StdEncoding.DecodeString(b64) // RFC 7515 §4.1.6
		if err != nil {
			return nil, fmt.Errorf("%w: x5c[%d]: %v", ErrMalformed, i, err)
		}
		certs, err := eudicrypto.ParseCertChain(der)
		if err != nil {
			return nil, fmt.Errorf("%w: x5c[%d]: %v", ErrMalformed, i, err)
		}
		chain = append(chain, certs...)
	}
	payload, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("%w: payload segment: %v", ErrMalformed, err)
	}
	claims, err := decodeWRPRCClaims(payload)
	if err != nil {
		return nil, err
	}
	return claims.toWRPRC(raw, FormatJWT, chain)
}

// --- shared payload decoding (JWT json / CWT converted to json) ---

type wrprcClaims struct {
	Name                 string             `json:"name"`
	SubLN                string             `json:"sub_ln"`
	SubGN                string             `json:"sub_gn"`
	SubFN                string             `json:"sub_fn"`
	Sub                  string             `json:"sub"`
	Country              string             `json:"country"`
	RegistryURI          string             `json:"registry_uri"`
	SrvDescription       [][]LangValue      `json:"srv_description"`
	Entitlements         []string           `json:"entitlements"`
	PrivacyPolicy        string             `json:"privacy_policy"`
	InfoURI              string             `json:"info_uri"`
	SupportURI           string             `json:"support_uri"`
	SupervisoryAuthority SupervisoryContact `json:"supervisory_authority"`
	PolicyID             []string           `json:"policy_id"`
	CertificatePolicy    string             `json:"certificate_policy"`
	IAT                  *int64             `json:"iat"`
	EXP                  *int64             `json:"exp"`
	Status               *statusJSON        `json:"status"`
	Purpose              []LangValue        `json:"purpose"`
	Credentials          []credentialJSON   `json:"credentials"`
	ProvidesAttestations []credentialJSON   `json:"provides_attestations"`
	IntendedUseID        string             `json:"intended_use_id"`
	PublicBody           bool               `json:"public_body"`
	Intermediary         *intermediaryJSON  `json:"intermediary"`
}

type statusJSON struct {
	StatusList struct {
		Idx int64  `json:"idx"`
		URI string `json:"uri"`
	} `json:"status_list"`
}

// credentialJSON — TS 119 475 Tables 8/9 use subfield "claim" (singular;
// Annex C example confirms), unlike ARF TS5's Credential.claims.
type credentialJSON struct {
	Format string      `json:"format"`
	Meta   metaJSON    `json:"meta"`
	Claim  []claimJSON `json:"claim"`
}

type metaJSON struct {
	VCTValues    []string `json:"vct_values"`    // dc+sd-jwt (OID4VP B.3.5)
	DoctypeValue string   `json:"doctype_value"` // mso_mdoc (OID4VP B.2.3)
}

type claimJSON struct {
	Path ts5.ClaimPath `json:"path"`
}

// intermediaryJSON accepts both the Annex C subfield "name" and Table 10's
// "sname" (spec-internal inconsistency; see README corrections).
type intermediaryJSON struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	SName string `json:"sname"`
}

func decodeWRPRCClaims(payload []byte) (*wrprcClaims, error) {
	var c wrprcClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	return &c, nil
}

func (c *wrprcClaims) toWRPRC(raw []byte, format string, chain []*x509.Certificate) (*WRPRC, error) {
	// Structural presence per GEN-5.2.4-01 (iat is a technical "shall") and
	// GEN-5.2.4-02 (sub is the WRPAC-linkage identifier).
	if c.IAT == nil {
		return nil, fmt.Errorf("%w: iat", ErrClaimMissing)
	}
	if c.Sub == "" {
		return nil, fmt.Errorf("%w: sub", ErrClaimMissing)
	}
	w := &WRPRC{
		Raw:                   raw,
		Format:                format,
		Chain:                 chain,
		Name:                  c.Name,
		LegalName:             c.SubLN,
		GivenName:             c.SubGN,
		FamilyName:            c.SubFN,
		Subject:               c.Sub,
		Country:               c.Country,
		RegistryURI:           c.RegistryURI,
		SrvDescription:        c.SrvDescription,
		Entitlements:          c.Entitlements,
		PrivacyPolicy:         c.PrivacyPolicy,
		InfoURI:               c.InfoURI,
		SupportURI:            c.SupportURI,
		SupervisoryAuthority:  c.SupervisoryAuthority,
		PolicyIDs:             c.PolicyID,
		CertificatePolicy:     c.CertificatePolicy,
		PublicBody:            c.PublicBody,
		IssuedAt:              time.Unix(*c.IAT, 0).UTC(),
		Purpose:               c.Purpose,
		IntendedUseID:         c.IntendedUseID,
		RegisteredCredentials: mapCredentials(c.Credentials),
		ProvidesAttestations:  mapCredentials(c.ProvidesAttestations),
	}
	if c.EXP != nil {
		w.ExpiresAt = time.Unix(*c.EXP, 0).UTC()
	}
	if c.Status != nil {
		w.Status = &StatusRef{Index: c.Status.StatusList.Idx, URI: c.Status.StatusList.URI}
	}
	if c.Intermediary != nil {
		name := c.Intermediary.Name
		if name == "" {
			name = c.Intermediary.SName
		}
		w.Intermediary = &IntermediaryRef{Subject: c.Intermediary.Sub, Name: name}
	}
	return w, nil
}

// mapCredentials — Tables 8/9 → RegisteredCredential. Unknown formats are
// retained with empty DoctypesOrVCTs: scope matching downstream will simply
// never treat them as covering (fail closed at the consumer).
func mapCredentials(in []credentialJSON) []RegisteredCredential {
	if len(in) == 0 {
		return nil
	}
	out := make([]RegisteredCredential, 0, len(in))
	for _, cj := range in {
		rc := RegisteredCredential{Format: cj.Format, AllClaims: len(cj.Claim) == 0}
		switch cj.Format {
		case CredentialFormatSDJWTVC:
			rc.DoctypesOrVCTs = cj.Meta.VCTValues
		case CredentialFormatMdoc:
			if cj.Meta.DoctypeValue != "" {
				rc.DoctypesOrVCTs = []string{cj.Meta.DoctypeValue}
			}
		}
		for _, cl := range cj.Claim {
			rc.Claims = append(rc.Claims, cl.Path)
		}
		out = append(out, rc)
	}
	return out
}
