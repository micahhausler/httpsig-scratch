package rsa

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/common-fate/httpsig/contentdigest"
)

// NewRSAPKCS256Signer returns a signing algorithm based on
// the provided rsa private key.
func NewRSAPKCS256Signer(key *rsa.PrivateKey) *RSAPKCS256 {
	return &RSAPKCS256{PrivateKey: key}
}

// NewRSAPKCS256Verifier returns a verification algorithm based on
// the provided rsa public key.
func NewRSAPKCS256Verifier(key *rsa.PublicKey) *RSAPKCS256 {
	return &RSAPKCS256{PublicKey: key}
}

type RSAPKCS256 struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Attrs      any
}

// Attributes returns server-side attributes associated with the key.
func (a RSAPKCS256) Attributes() any {
	return a.Attrs
}

func (a RSAPKCS256) Type() string {
	return "rsa-v1_5-sha256"
}

func (a RSAPKCS256) ContentDigest() contentdigest.Digester {
	return contentdigest.SHA256
}

func (a RSAPKCS256) Sign(ctx context.Context, base string) ([]byte, error) {
	if a.PrivateKey == nil {
		return nil, errors.New("private key was nil")
	}
	digest := sha256.Sum256([]byte(base))
	return rsa.SignPKCS1v15(rand.Reader, a.PrivateKey, crypto.SHA256, digest[:])
}

func (a RSAPKCS256) Verify(ctx context.Context, base string, signature []byte) error {
	if len(signature) != 64 {
		return fmt.Errorf("expected 64 byte signature but got %v bytes", len(signature))
	}
	digest := sha256.Sum256([]byte(base))
	return rsa.VerifyPKCS1v15(a.PublicKey, crypto.SHA256, digest[:], signature)
}
