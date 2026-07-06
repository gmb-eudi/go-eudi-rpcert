package rpcert

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/gmb-eudi/go-eudi-rpcert/ts5"
)

// dateLayout — ETSI TS 119 475 / TS5 IntendedUse createdAt/revokedAt use
// ISO 8601-1 YYYY-MM-DD.
const dateLayout = "2006-01-02"

// IntendedUseQuery mirrors GET /wrp/check-intended-use (TS5 v1.3 OpenAPI):
// rpidentifier is mandatory; the other five are optional narrowing filters.
type IntendedUseQuery struct {
	RPIdentifier          string // rpidentifier (required)
	IntendedUseIdentifier string // intendeduseidentifier
	CredentialFormat      string // credentialformat
	ClaimPath             string // claimpath
	CredentialMeta        string // credentialmeta
	PolicyURL             string // policyurl
}

func (q IntendedUseQuery) values() url.Values {
	v := url.Values{}
	v.Set("rpidentifier", q.RPIdentifier)
	set := func(k, val string) {
		if val != "" {
			v.Set(k, val)
		}
	}
	set("intendeduseidentifier", q.IntendedUseIdentifier)
	set("credentialformat", q.CredentialFormat)
	set("claimpath", q.ClaimPath)
	set("credentialmeta", q.CredentialMeta)
	set("policyurl", q.PolicyURL)
	return v
}

// CheckIntendedUse calls GET /wrp/check-intended-use and returns the
// JWS-signed boolean result (TS5 v1.3 §3.2.2: "JWS-signed boolean TRUE or
// FALSE response, based on if the queried parameter set can be found in the
// Registrar's Intended use information"). Verification reuses the same
// fetch/verifyResponse wiring as GetWRP/GetWRPByID (T-07.7) — one trust
// decision path for every registrar endpoint (hard rule 4: alg selection
// stays inside eudicrypto.VerifyJWS via c.fetch).
func (c *RegistrarClient) CheckIntendedUse(ctx context.Context, registryURI string, q IntendedUseQuery) (bool, error) {
	if q.RPIdentifier == "" {
		return false, fmt.Errorf("%w: rpidentifier is required", ErrMalformed)
	}
	payload, err := c.fetch(ctx, registryURI, "/wrp/check-intended-use", q.values())
	if err != nil {
		return false, err
	}
	env, err := ts5.DecodeSignedIntendedUseCheckResult(payload)
	if err != nil {
		return false, err
	}
	return env.Data.IsRegistered, nil
}

// IntendedUseActive evaluates the intended-use lifecycle window
// (ETSI TS 119 475 / TS5 IntendedUse): active iff createdAt <= at and
// (revokedAt absent OR at < revokedAt-day-midnight). Revocation is effective
// from 00:00:00 UTC of revokedAt (WP-07 Decision 10 — fail-closed reading of
// "end date for the validity"): the entire revokedAt calendar day already
// counts as revoked. A revoked/not-yet-active use returns
// (false, ErrIntendedUseRevoked); malformed dates — including an empty
// createdAt — fail closed with ErrMalformed (never silently treated as
// active; RevokedAt stays optional and absent-means-not-revoked).
func IntendedUseActive(iu ts5.IntendedUse, at time.Time) (bool, error) {
	created, err := time.ParseInLocation(dateLayout, iu.CreatedAt, time.UTC)
	if err != nil {
		return false, fmt.Errorf("%w: createdAt", ErrMalformed)
	}
	if at.Before(created) {
		return false, fmt.Errorf("%w: not yet active", ErrIntendedUseRevoked)
	}
	if iu.RevokedAt != "" {
		revoked, err := time.ParseInLocation(dateLayout, iu.RevokedAt, time.UTC)
		if err != nil {
			return false, fmt.Errorf("%w: revokedAt", ErrMalformed)
		}
		if !at.Before(revoked) {
			return false, fmt.Errorf("%w: revoked", ErrIntendedUseRevoked)
		}
	}
	return true, nil
}

// IntendedUseStatus resolves the WRP via GET /wrp/{identifier}, locates the
// named intended use and evaluates its lifecycle. Returns nil when active,
// ErrIntendedUseRevoked when revoked/not-yet-active (->
// err:registrar:intended-use-revoked), ErrIntendedUseNotFound when the id is
// absent. Used by the portal's periodic monitoring (ADR-0003 decision 3).
func (c *RegistrarClient) IntendedUseStatus(ctx context.Context, registryURI, rpIdentifier, intendedUseID string) error {
	wrp, err := c.GetWRPByID(ctx, registryURI, rpIdentifier)
	if err != nil {
		return err
	}
	for _, iu := range wrp.IntendedUse {
		if iu.IntendedUseIdentifier != intendedUseID {
			continue
		}
		if _, err := IntendedUseActive(iu, c.clock()); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("%w: %q", ErrIntendedUseNotFound, intendedUseID)
}
