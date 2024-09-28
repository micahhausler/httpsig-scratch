package hmac

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/contentdigest"
	"github.com/common-fate/httpsig/signer"
	"github.com/common-fate/httpsig/verifier"
)

const Algo = "hmac-sha256" // Algo is the HMAC algorithm name

// HMAC is a signer and verifier for HMAC digests. It uses crypto/hmac with sha256,
// and implements the httpsig.Attributer interface
type HMAC struct {
	key   []byte
	attrs any
}

// NewHMAC creates a new HMAC with the provided key
func NewHMAC(key []byte) *HMAC {
	return NewHMACWithAttributes(key, nil)
}

// NewHMACWithAttributes creates a new HMAC with the provided key and attributes
func NewHMACWithAttributes(key []byte, attrs any) *HMAC {
	return &HMAC{key: key, attrs: attrs}
}

var _ signer.Algorithm = &HMAC{}
var _ verifier.Algorithm = &HMAC{}
var _ httpsig.Attributer = &HMAC{}

func (h *HMAC) Type() string {
	return Algo
}

func (h *HMAC) Attributes() any {
	return h.attrs
}

func (h *HMAC) Sign(ctx context.Context, base string) ([]byte, error) {
	if h.key == nil {
		return nil, errors.New("no key provided")
	}

	workingHMAC := hmac.New(sha256.New, h.key)
	_, err := workingHMAC.Write([]byte(base))
	if err != nil {
		return nil, err
	}
	dataHmac := workingHMAC.Sum(nil)
	resp := []byte{}
	hex.Encode(dataHmac, resp)
	return resp, nil
}

func (h *HMAC) Verify(ctx context.Context, base string, sig []byte) error {
	selfSig, err := h.Sign(ctx, base)
	if err != nil {
		return err
	}
	// constant time compare
	if !hmac.Equal(selfSig, sig) {
		return errors.New("signature mismatch")
	}
	return nil
}

func (h *HMAC) ContentDigest() contentdigest.Digester {
	return contentdigest.SHA256
}
