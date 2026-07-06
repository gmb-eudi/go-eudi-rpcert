package rpcert_test

import (
	"errors"

	trust "github.com/gmb-eudi/go-eudi-trust"
)

// errCacheExpired stands in for trust.ErrCacheExpired in propagation tests —
// assertions use errors.Is against the exact value the fake returns, so the
// fail-closed contract is proven regardless of WP-06's sentinel spelling.
var errCacheExpired = errors.New("trust: cache expired (fake)")

// fakeAnchors is the in-package fake for trust.AnchorSource (WP-06 target
// interface). Keyed by "<type>|<country>"; err short-circuits everything.
type fakeAnchors struct {
	anchors map[string][]trust.Anchor
	err     error
}

func (f *fakeAnchors) AnchorsFor(t trust.AnchorType, country string) ([]trust.Anchor, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.anchors[string(t)+"|"+country], nil
}

func anchorsFor(t trust.AnchorType, country string, a ...trust.Anchor) *fakeAnchors {
	return &fakeAnchors{anchors: map[string][]trust.Anchor{string(t) + "|" + country: a}}
}
