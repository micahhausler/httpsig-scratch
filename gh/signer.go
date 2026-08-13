package gh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"

	"github.com/micahhausler/httpsig"
	"golang.org/x/crypto/ssh"
)

// GitHubSigner is an httpsig.Signer backed by an SSH private key. Its key ID
// is the hex SHA-512 of the SSH wire-format public key, the same ID the
// server-side directory derives from github.com/<user>.keys.
type GitHubSigner struct {
	httpsig.Signer
	keyID string
}

// NewGHSigner parses an SSH private key and returns a signer for it.
func NewGHSigner(keydata []byte) (*GitHubSigner, error) {
	kp, err := ssh.ParseRawPrivateKey(keydata)
	if err != nil {
		return nil, err
	}

	var alg httpsig.Algorithm
	var key any = kp
	switch k := kp.(type) {
	case *rsa.PrivateKey:
		alg = httpsig.RSAPSSSHA512
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			alg = httpsig.ECDSAP256SHA256
		case elliptic.P384():
			alg = httpsig.ECDSAP384SHA384
		default:
			return nil, fmt.Errorf("unsupported ecdsa curve: %s", k.Curve.Params().Name)
		}
	case *ed25519.PrivateKey:
		alg = httpsig.Ed25519
		key = *k
	default:
		return nil, fmt.Errorf("unsupported key type: %T", kp)
	}

	signer, err := httpsig.NewSigner(alg, key)
	if err != nil {
		return nil, err
	}

	sshSigner, err := ssh.ParsePrivateKey(keydata)
	if err != nil {
		return nil, err
	}
	keyHash := sha512.Sum512(sshSigner.PublicKey().Marshal())

	return &GitHubSigner{
		Signer: signer,
		keyID:  fmt.Sprintf("%x", keyHash),
	}, nil
}

// KeyID returns the hex SHA-512 of the SSH wire-format public key.
func (s *GitHubSigner) KeyID() string {
	return s.keyID
}
