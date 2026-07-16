package ts5

import "errors"

// Sentinel errors. Services map these to err:registrar:* problem codes
// this library carries no HTTP semantics (framework-free).
var (
	ErrDecode         = errors.New("ts5: payload is not valid JSON")
	ErrEnvelope       = errors.New("ts5: signed payload envelope missing required field")
	ErrAddressPresent = errors.New("ts5: response contains a physical/postal address (TS5 v1.3 §3.2.1 excludes it)")
)
