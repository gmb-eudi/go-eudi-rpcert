package rpcert

import (
	"context"
	"fmt"

	"github.com/gmb-eudi/go-eudi-rpcert/ts5"
)

// LinkageResult reports whether a client registers the operator as one of
// its intermediaries (ARF TS5 v1.3 §2.1 usesIntermediary). Provenance carries
// the registry + key trust basis for the verification report.
type LinkageResult struct {
	Linked     bool
	OperatorID string
	ClientID   string
	Provenance Provenance
}

// VerifyIntermediaryLinkage confirms, via the Registrar API, that the
// client's usesIntermediary array lists the operator by identifier. Per
// ARF TS5 v1.3 §2.1 (Note: "isIntermediary … available for verification only
// via the Registrar's API") this relationship is NOT in any certificate, so
// this API call is the authoritative check (ADR-0003 decision 3; supersedes
// WRPAC.IsIntermediaryCapable — WP-07 Decision 2). Fail closed:
// ErrNotLinked when the operator is absent, ErrWRPNotFound when the client
// is unknown.
func (c *RegistrarClient) VerifyIntermediaryLinkage(ctx context.Context, registryURI, clientIdentifier, operatorIdentifier string) (LinkageResult, error) {
	if clientIdentifier == "" || operatorIdentifier == "" {
		return LinkageResult{}, fmt.Errorf("%w: client and operator identifiers are required", ErrMalformed)
	}
	client, err := c.GetWRPByID(ctx, registryURI, clientIdentifier)
	if err != nil {
		return LinkageResult{}, err
	}
	res := LinkageResult{
		OperatorID: operatorIdentifier,
		ClientID:   clientIdentifier,
		Provenance: c.LastProvenance(),
	}
	if intermediaryListed(client.UsesIntermediary, operatorIdentifier) {
		res.Linked = true
		return res, nil
	}
	return res, fmt.Errorf("%w: operator %q", ErrNotLinked, operatorIdentifier)
}

// intermediaryListed reports whether any WalletRelyingParty in the list
// carries operatorID among its identifiers (ARF TS5 usesIntermediary is an
// array of WalletRelyingParty objects; each intermediary is matched by its
// registered identifier, TS 119 475 §5.1 linkage-by-identifier).
func intermediaryListed(intermediaries []ts5.WalletRelyingParty, operatorID string) bool {
	for i := range intermediaries {
		for _, id := range intermediaries[i].Identifiers {
			if id.Identifier == operatorID {
				return true
			}
		}
	}
	return false
}
