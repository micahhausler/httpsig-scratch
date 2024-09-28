package gh

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"

	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/contentdigest"
	"github.com/common-fate/httpsig/signer"
	rsaAlgo "github.com/micahhausler/httpsig-scratch/rsa"
	"golang.org/x/crypto/ssh"
)

// func convertSSHPrivateKeyToCryptoRSAPrivateKey(sshPrivKey ssh.Signer) (*rsa.PrivateKey, error) {
// 	// Check if the ssh.Signer is of type *ssh.CryptoPrivateKey
// 	if cryptoPrivKey, ok := sshPrivKey.(ssh.CryptoPrivateKey); ok {
// 		// Extract the underlying private key
// 		switch key := cryptoPrivKey.CryptoPrivateKey().(type) {
// 		case *rsa.PrivateKey:
// 			return key, nil
// 		default:
// 			return nil, fmt.Errorf("unsupported private key type")
// 		}
// 	}
// 	return nil, fmt.Errorf("not a crypto private key")
// }

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
		algo = rsaAlgo.NewRSAPSS512Signer(kp.(*rsa.PrivateKey))
	case *ecdsa.PrivateKey:
		algo = alg_ecdsa.NewP256Signer(kp.(*ecdsa.PrivateKey))
	default:
		return nil, fmt.Errorf("unsupported key type: %T", keyType)
	}

	signer, err := ssh.ParsePrivateKey(keydata)
	if err != nil {
		return nil, err
	}
	// TODO: Is this marshalling consistent with how GH does it?
	keyHash := sha512.Sum512(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	return &GitHubSigner{
		algo:  algo,
		keyId: string(keyHash[:]),
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
