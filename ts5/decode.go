package ts5

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// addressKeys are rejected anywhere in a Registrar API payload: ARF TS5 v1.3
// [ARF TS5 v1.3 §3.2.1] excludes WalletRelyingParty.physicalAddress from responses (the
// ARF TS5 JSON schema spells the LegalEntity field postalAddress — reject both).
// Ingesting home/postal addresses would pull personal data into the
// verifier pipeline (no attribute values in errors) — fail closed.
var addressKeys = map[string]bool{"physicalAddress": true, "postalAddress": true}

func rejectAddressFields(payload []byte) error {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("%w: %v", ErrDecode, err)
	}
	return walkForAddress(doc)
}

func walkForAddress(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if addressKeys[k] {
				return fmt.Errorf("%w: field %q", ErrAddressPresent, k)
			}
			if err := walkForAddress(e); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range t {
			if err := walkForAddress(e); err != nil {
				return err
			}
		}
	}
	return nil
}

// DecodeSignedWRPArray decodes and validates the JWS payload of GET /wrp
// ([ARF TS5 v1.3 §3.2.2], OpenAPI SignedWRPArray: iss, iat, data required).
// The payload must already be signature-verified by the caller.
func DecodeSignedWRPArray(payload []byte) (*SignedWRPArray, error) {
	if err := rejectAddressFields(payload); err != nil {
		return nil, err
	}
	var env SignedWRPArray
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecode, err)
	}
	if err := checkEnvelope(env.Iss, env.Iat); err != nil {
		return nil, err
	}
	if env.Data == nil {
		return nil, fmt.Errorf("%w: data", ErrEnvelope)
	}
	return &env, nil
}

// DecodeSignedWRP decodes the JWS payload of GET /wrp/{identifier}
// ([ARF TS5 v1.3 §3.2.2], OpenAPI SignedWRP).
func DecodeSignedWRP(payload []byte) (*SignedWRP, error) {
	if err := rejectAddressFields(payload); err != nil {
		return nil, err
	}
	// Distinguish "data absent" from zero-valued object.
	var probe struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecode, err)
	}
	if len(probe.Data) == 0 {
		return nil, fmt.Errorf("%w: data", ErrEnvelope)
	}
	var env SignedWRP
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecode, err)
	}
	if err := checkEnvelope(env.Iss, env.Iat); err != nil {
		return nil, err
	}
	return &env, nil
}

// DecodeSignedIntendedUseCheckResult decodes the JWS payload of
// GET /wrp/check-intended-use ([ARF TS5 v1.3 §3.2.2], OpenAPI
// SignedIntendedUseCheckResult).
//
// Runs rejectAddressFields for symmetry with DecodeSignedWRP/
// DecodeSignedWRPArray: the {isRegistered, details} shape
// cannot carry an address today, but this guards against future schema
// drift the same way its siblings do.
func DecodeSignedIntendedUseCheckResult(payload []byte) (*SignedIntendedUseCheckResult, error) {
	if err := rejectAddressFields(payload); err != nil {
		return nil, err
	}
	var probe struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecode, err)
	}
	if len(probe.Data) == 0 {
		return nil, fmt.Errorf("%w: data", ErrEnvelope)
	}
	var env SignedIntendedUseCheckResult
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecode, err)
	}
	if err := checkEnvelope(env.Iss, env.Iat); err != nil {
		return nil, err
	}
	return &env, nil
}

func checkEnvelope(iss string, iat int64) error {
	if iss == "" {
		return fmt.Errorf("%w: iss", ErrEnvelope)
	}
	if iat <= 0 {
		return fmt.Errorf("%w: iat", ErrEnvelope)
	}
	return nil
}
