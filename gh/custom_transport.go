package gh

import (
	"fmt"
	"net/http"

	"github.com/common-fate/httpsig/signer"
	"github.com/common-fate/httpsig/sigset"
)

type RequestSigner interface {
	SignRequest(*http.Request) (*http.Request, error)
}

func NewRequestSigner(transport signer.Transport) RequestSigner {
	return &requestSigner{transport}
}

type requestSigner struct {
	signer.Transport
}

func (t *requestSigner) SignRequest(req *http.Request) (*http.Request, error) {
	reqBodyClosed := false
	if req.Body != nil {
		defer func() {
			if !reqBodyClosed {
				req.Body.Close()
			}
		}()
	}

	// parse the existing signature set on the request
	set, err := sigset.Unmarshal(req)
	if err != nil {
		return nil, err
	}

	// derive the signature.
	ms, err := t.Sign(req)
	if err != nil {
		return nil, err
	}

	// as per the http.RoundTripper contract, roundtrippers
	// may not modify the request.
	req2 := cloneRequest(req)

	// add the signature to the set
	set.Add(ms)

	// include the signature in the cloned HTTP request.
	err = set.Include(req2)
	if err != nil {
		return nil, fmt.Errorf("including signature in HTTP request: %w", err)
	}

	// req.Body is assumed to be closed by the base RoundTripper.
	reqBodyClosed = true

	return req2, nil
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
