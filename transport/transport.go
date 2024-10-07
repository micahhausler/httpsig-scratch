package transport

import (
	"net/http"
)

// NewTransportWithFallbackHeaders creates a new http.RoundTripper that wraps the given
// http.RoundTripper and adds the given headers to the request if they are not already set.
//
// This is useful if you want to ensure a signed header like `Content-Type` is set on all requests,
// including GETs.
func NewTransportWithFallbackHeaders(t http.RoundTripper, headers http.Header) http.RoundTripper {
	if t == nil {
		t = http.DefaultTransport
	}
	return &headerRoundTripper{transport: t, header: headers}
}

type headerRoundTripper struct {
	transport http.RoundTripper
	header    http.Header
}

func (h *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for key, values := range h.header {
		for _, value := range values {
			if _, ok := req.Header[key]; !ok {
				// TODO: clone the request, don't modify it
				req.Header.Add(key, value)
			}
		}
	}
	return h.transport.RoundTrip(req)
}
