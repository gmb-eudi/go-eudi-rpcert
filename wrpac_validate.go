package rpcert

import (
	trust "github.com/gmb-eudi/go-eudi-trust"
)

// ValidateAgainst chains the WRPAC to AccessCA trust anchors from the trust
// service (CIR (EU) 2025/848 Art. 7 — access-certificate
// providers operate under Member State supervision, their CAs are the
// AccessCA anchor set). Uses the package clock (clock.go).
func (w *WRPAC) ValidateAgainst(src trust.AnchorSource) error {
	if len(w.Chain) == 0 {
		return ErrChainEmpty
	}
	return chainToAnchors(w.Chain[0], w.Chain[1:], src, trust.AccessCA, timeNow())
}
