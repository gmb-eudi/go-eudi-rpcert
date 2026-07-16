package rpcert

import "net/http"

// Doer is the injected HTTP client (framework-free: no global
// http.DefaultClient). Services wire the platform-kit correlation-propagating
// client here; tests wire httptest.Server.Client().
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}
