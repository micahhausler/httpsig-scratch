package gh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"log/slog"
	"os"

	"github.com/micahhausler/httpsig"
	"golang.org/x/crypto/ssh"
)

func init() {
	jsonLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	}))
	slog.SetDefault(jsonLogger)
}

// keysForUsers maps username to key ID (hex SHA-512 of the SSH wire-format
// public key) to a verifier for that key.
type keysForUsers map[string]map[string]httpsig.Verifier

func addKeys(k keysForUsers, username string, keys [][]byte) error {
	keyMap, ok := k[username]
	if !ok {
		keyMap = map[string]httpsig.Verifier{}
	}

	for _, key := range keys {
		if len(key) == 0 {
			// skip empty lines
			continue
		}

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

		cryptoKey, ok := pubKey.(ssh.CryptoPublicKey)
		if !ok {
			slog.Debug("ssh key has no crypto.PublicKey", "keyType", pubKey.Type(), "username", username)
			continue
		}

		var alg httpsig.Algorithm
		switch pk := cryptoKey.CryptoPublicKey().(type) {
		case *rsa.PublicKey:
			alg = httpsig.RSAPSSSHA512
		case *ecdsa.PublicKey:
			switch pk.Curve {
			case elliptic.P256():
				alg = httpsig.ECDSAP256SHA256
			case elliptic.P384():
				alg = httpsig.ECDSAP384SHA384
			default:
				slog.Debug("unsupported ecdsa curve", "curve", pk.Curve.Params().Name, "username", username)
				continue
			}
		case ed25519.PublicKey:
			alg = httpsig.Ed25519
		default:
			slog.Debug("key type not implemented", "keyType", pubKey.Type(), "username", username)
			continue
		}

		verifier, err := httpsig.NewVerifier(alg, cryptoKey.CryptoPublicKey())
		if err != nil {
			slog.Debug("failed to create verifier", "keyType", pubKey.Type(), "username", username, "error", err)
			continue
		}

		slog.Debug("adding key for user", "username", username, "kid", kid, "type", pubKey.Type(), "key", string(key))
		keyMap[kid] = verifier
	}

	if len(keyMap) == 0 {
		slog.Debug("no keys for user", "username", username)
		return nil
	}

	slog.Debug("adding keys for user", "username", username, "count", len(keyMap))
	k[username] = keyMap

	return nil
}
