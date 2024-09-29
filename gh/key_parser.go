package gh

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"log/slog"
	"os"

	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/verifier"
	"github.com/micahhausler/httpsig-scratch/attributes"
	rsaAlgo "github.com/micahhausler/httpsig-scratch/rsa"
	"golang.org/x/crypto/ssh"
)

func init() {
	jsonLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	}))
	slog.SetDefault(jsonLogger)
}

func ConvertSSHPublicKeyToRSAPublicKey(sshPubKey ssh.PublicKey) (*rsa.PublicKey, error) {
	// Check if the ssh.PublicKey is of type *ssh.CryptoPublicKey
	if cryptoPubKey, ok := sshPubKey.(ssh.CryptoPublicKey); ok {
		// Extract the underlying public key
		if rsaPubKey, ok := cryptoPubKey.CryptoPublicKey().(*rsa.PublicKey); ok {
			return rsaPubKey, nil
		}
	}
	return nil, fmt.Errorf("not an RSA public key")
}

func ConvertSSHPublicKeyToECDSAPublicKey(sshPubKey ssh.PublicKey) (*ecdsa.PublicKey, error) {
	// Check if the ssh.PublicKey is of type *ssh.CryptoPublicKey
	if cryptoPubKey, ok := sshPubKey.(ssh.CryptoPublicKey); ok {
		// Extract the underlying public key
		if ecdsaPubKey, ok := cryptoPubKey.CryptoPublicKey().(*ecdsa.PublicKey); ok {
			return ecdsaPubKey, nil
		}
	}
	return nil, fmt.Errorf("not an ECDSA public key")
}

// map of username to key hash to algorithm
type keysForUsers map[string]map[string][]verifier.Algorithm

func addKeys(k keysForUsers, username string, keys [][]byte) error {
	// TODO use a lock to make thread safe
	keyMap, ok := k[username]
	if !ok {
		keyMap = map[string][]verifier.Algorithm{}
	}

	for _, key := range keys {
		if len(key) == 0 {
			// skip empty lines
			continue
		}

		algos := []verifier.Algorithm{}

		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(key)
		if err != nil {
			slog.Debug("invalid ssh authorized key", "key", key, "username", username, "error", err)
			continue
		}
		kid := fmt.Sprintf("%x", sha512.Sum512(pubKey.Marshal()))
		if _, ok := keyMap[kid]; ok {
			slog.Debug("key id already exists", "username", username)
			continue
		}

		switch pubKey.Type() {
		case ssh.KeyAlgoRSA:
			rsaPk, err := ConvertSSHPublicKeyToRSAPublicKey(pubKey)
			if err != nil {
				slog.Debug("invalid rsa ssh key", "key", key, "username", username, "error", err)
				continue
			}
			algos = append(algos, rsaAlgo.RSAPSS512{
				PublicKey: rsaPk,
				Attrs:     attributes.User{Username: username},
			})
		case ssh.KeyAlgoECDSA256:
			ecdsaPk, err := ConvertSSHPublicKeyToECDSAPublicKey(pubKey)
			if err != nil {
				slog.Debug("invalid ecdsa ssh key", "key", key, "username", username, "error", err)
				continue
			}
			algos = append(algos, alg_ecdsa.P256{
				PublicKey: ecdsaPk,
				Attrs:     attributes.User{Username: username},
			})
		// TODO: handle ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521
		default:
			// TODO: handle ssh.KeyAlgoED25519
			slog.Debug("key type not implemented", "keyType", pubKey.Type(), "username", username)
			continue
		}

		slog.Debug("adding key for user", "username", username, "kid", kid, "type", pubKey.Type(), "key", string(key))
		keyMap[kid] = algos
	}

	if len(keyMap) == 0 {
		slog.Debug("no keys for user", "username", username)
		return nil
	}

	slog.Debug("adding keys for user", "username", username, "count", len(keyMap))
	k[username] = keyMap

	return nil
}
