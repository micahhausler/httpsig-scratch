package tpm

import (
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/micahhausler/httpsig"
)

// A Signer is an httpsig.Signer whose private key lives in a TPM. The mutex
// serializes commands: a TPM transport handles one command at a time.
type Signer struct {
	mu    sync.Mutex
	tpm   transport.TPM
	key   tpm2.NamedHandle
	keyID string
}

var _ httpsig.Signer = &Signer{}

func (s *Signer) Algorithm() httpsig.Algorithm {
	return httpsig.ECDSAP256SHA256
}

// KeyID returns the hex TPM Name of the signing key, the same identifier the
// server derives from the enrolled public area.
func (s *Signer) KeyID() string {
	return s.keyID
}

func (s *Signer) Sign(base []byte) ([]byte, error) {
	digest := sha256.Sum256(base)

	s.mu.Lock()
	rsp, err := tpm2.Sign{
		KeyHandle: s.key,
		Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(s.tpm)
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("tpm sign failed: %w", err)
	}

	sig, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("failed to read tpm signature: %w", err)
	}
	return rawECDSASig(sig), nil
}
