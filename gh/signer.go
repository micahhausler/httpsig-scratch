package gh

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"log/slog"

	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/contentdigest"
	"github.com/common-fate/httpsig/signer"
	rsaAlgo "github.com/micahhausler/httpsig-scratch/rsa"
	"golang.org/x/crypto/ssh"
)

type GitHubSigner struct {
	algo  signer.Algorithm
	keyId string
}

func NewGHSigner(keydata []byte) (*GitHubSigner, error) {
	kp, err := ssh.ParseRawPrivateKey(keydata)
	if err != nil {
		return nil, err
	}

	var algo signer.Algorithm
	switch keyType := kp.(type) {
	case *rsa.PrivateKey:
		slog.Debug("using RSA key")
		algo = rsaAlgo.NewRSAPSS512Signer(kp.(*rsa.PrivateKey))
	case *ecdsa.PrivateKey:
		slog.Debug("using ECDSA key")
		algo = alg_ecdsa.NewP256Signer(kp.(*ecdsa.PrivateKey))
	default:
		return nil, fmt.Errorf("unsupported key type: %T", keyType)
	}

	signer, err := ssh.ParsePrivateKey(keydata)
	if err != nil {
		return nil, err
	}
	// TODO: Is this marshalling consistent
	keyHash := sha512.Sum512(signer.PublicKey().Marshal())

	return &GitHubSigner{
		algo:  algo,
		keyId: fmt.Sprintf("%x", keyHash),
	}, nil
}

// TODO: prefix username in front of keyhash?
func (s *GitHubSigner) KeyID() string {
	return s.keyId
}

func (s *GitHubSigner) Sign(ctx context.Context, stringToSign string) ([]byte, error) {
	return s.algo.Sign(ctx, stringToSign)
}

func (s *GitHubSigner) Type() string {
	return s.algo.Type()
}

func (s *GitHubSigner) ContentDigest() contentdigest.Digester {
	return s.algo.ContentDigest()
}

var _ signer.Algorithm = &GitHubSigner{}
