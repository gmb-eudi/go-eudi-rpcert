package rpcert

import (
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// Hardened CBOR decode options: bounded nesting and
// sizes, duplicate map keys rejected, indefinite lengths forbidden, integers
// normalized to int64. cbor stays wrapped — never in the public API
// (framework-free).
var cborDec = func() cbor.DecMode {
	dm, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		IntDec:           cbor.IntDecConvertSignedOrFail,
		MaxNestedLevels:  16,
		MaxArrayElements: 4096,
		MaxMapPairs:      1024,
	}.DecMode()
	if err != nil {
		panic(err) // static options — programmer error only
	}
	return dm
}()

// COSE header labels: alg ([RFC 9052 §3.1]), typ (RFC 9596), x5chain
// ([RFC 9360 §2]). Values per ETSI TS 119 475 GEN-5.2.3-01 Table 6.
const (
	coseHeaderAlg     = int64(1)
	coseHeaderTyp     = int64(16)
	coseHeaderX5Chain = int64(33)
)

// coseSign1 mirrors COSE_Sign1 = [protected bstr, unprotected map,
// payload bstr, signature bstr] ([RFC 9052 §4.2]).
type coseSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[any]any
	Payload     []byte
	Signature   []byte
}

// parseWRPRCCWT — header per TS 119 475 GEN-5.2.3-01 (Table 6): typ
// application/rc-wrp+cwt (protected only), alg, x5chain
// (protected preferred, unprotected accepted). Signature
// verification happens in Verify via eudicrypto.VerifyCOSESign1.
func parseWRPRCCWT(raw []byte) (*WRPRC, error) {
	body := raw
	var tag cbor.RawTag
	if err := cborDec.Unmarshal(raw, &tag); err == nil && tag.Number == 18 { // [RFC 9052 §2] CBOR tag 18
		body = tag.Content
	}
	var s coseSign1
	if err := cborDec.Unmarshal(body, &s); err != nil {
		return nil, fmt.Errorf("%w: not a COSE_Sign1 structure: %w", ErrWRPRCFormat, err)
	}
	protected := map[any]any{}
	if len(s.Protected) > 0 {
		if err := cborDec.Unmarshal(s.Protected, &protected); err != nil {
			return nil, fmt.Errorf("%w: protected header: %w", ErrMalformed, err)
		}
	}
	typ, _ := protected[coseHeaderTyp].(string)
	if typ != wrprcTypCWT {
		return nil, fmt.Errorf("%w: CWT typ %q, want %q", ErrWRPRCType, typ, wrprcTypCWT)
	}
	if _, ok := protected[coseHeaderAlg]; !ok {
		return nil, fmt.Errorf("%w: alg header missing", ErrMalformed)
	}
	rawChain, err := coseChain(protected, s.Unprotected)
	if err != nil {
		return nil, err
	}
	var chain []*x509.Certificate
	for i, der := range rawChain {
		certs, err := eudicrypto.ParseCertChain(der)
		if err != nil {
			return nil, fmt.Errorf("%w: x5chain[%d]: %w", ErrMalformed, i, err)
		}
		chain = append(chain, certs...)
	}
	if len(s.Payload) == 0 {
		return nil, fmt.Errorf("%w: empty CWT payload", ErrMalformed)
	}
	var claims map[any]any
	if err := cborDec.Unmarshal(s.Payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: CWT payload: %w", ErrMalformed, err)
	}
	jsonPayload, err := cwtClaimsToJSON(claims)
	if err != nil {
		return nil, err
	}
	c, err := decodeWRPRCClaims(jsonPayload)
	if err != nil {
		return nil, err
	}
	return c.toWRPRC(raw, FormatCWT, chain)
}

// coseChain extracts x5chain ([RFC 9360 §2]: single bstr or array of bstr),
// protected header first, unprotected accepted (the
// chain's trust comes from path validation, not signature coverage).
func coseChain(protected, unprotected map[any]any) ([][]byte, error) {
	v, ok := protected[coseHeaderX5Chain]
	if !ok && unprotected != nil {
		v, ok = unprotected[coseHeaderX5Chain]
	}
	if !ok {
		return nil, fmt.Errorf("%w: x5chain header missing (GEN-5.2.3-01)", ErrChainEmpty)
	}
	switch t := v.(type) {
	case []byte:
		return [][]byte{t}, nil
	case []any:
		out := make([][]byte, 0, len(t))
		for i, e := range t {
			b, ok := e.([]byte)
			if !ok {
				return nil, fmt.Errorf("%w: x5chain[%d] is not a byte string", ErrMalformed, i)
			}
			out = append(out, b)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%w: x5chain is empty", ErrChainEmpty)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: x5chain has unexpected CBOR type", ErrMalformed)
	}
}

// cwtClaimsToJSON converts the CWT claims map to the JWT JSON claim form so
// both WRPRC serializations share one payload decoder. Text keys are the
// TS 119 475 Table 7-10 names verbatim; integer keys 6/4 map to iat/exp
// ([RFC 8392 §4]). Unknown integer keys are ignored.
func cwtClaimsToJSON(claims map[any]any) ([]byte, error) {
	out := make(map[string]any, len(claims))
	for k, v := range claims {
		var name string
		switch key := k.(type) {
		case string:
			name = key
		case int64:
			switch key {
			case 4:
				name = "exp"
			case 6:
				name = "iat"
			default:
				continue
			}
		default:
			return nil, fmt.Errorf("%w: CWT claim key of type %T", ErrMalformed, k)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%w: duplicate CWT claim %q", ErrMalformed, name)
		}
		conv, err := cborValueToJSON(v)
		if err != nil {
			return nil, err
		}
		out[name] = conv
	}
	return json.Marshal(out)
}

// cborValueToJSON rewrites nested CBOR maps to string-keyed maps so
// encoding/json can serialize them; non-text nested keys are rejected.
func cborValueToJSON(v any) (any, error) {
	switch t := v.(type) {
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, e := range t {
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("%w: non-text CBOR map key of type %T", ErrMalformed, k)
			}
			conv, err := cborValueToJSON(e)
			if err != nil {
				return nil, err
			}
			m[ks] = conv
		}
		return m, nil
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			conv, err := cborValueToJSON(e)
			if err != nil {
				return nil, err
			}
			out[i] = conv
		}
		return out, nil
	default:
		return v, nil
	}
}
