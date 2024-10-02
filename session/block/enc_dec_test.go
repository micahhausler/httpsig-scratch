package block

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("failed to read rand: %v", err)
	}
	cipher, err := aes.NewCipher(key)
	enc := NewBlockSessionEncrypterDecrypter(cipher)

	// test cases
	tests := []struct {
		name       string
		kid, alg   string
		publicKey  []byte
		attributes any
	}{
		{
			name:       "test1",
			kid:        "kid1",
			alg:        "alg1",
			publicKey:  []byte(`-----BEGIN PUBLIC KEY-----`),
			attributes: nil,
		},
	}

	// run test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEnc, err := enc.EncryptPublicKey(context.Background(), tt.kid, tt.alg, tt.publicKey, tt.attributes)
			if err != nil {
				t.Fatalf("failed to encrypt: %v", err)
			}

			gotKid, gotAlg, gotPubKey, _, err := enc.DecryptPublicKey(context.Background(), gotEnc)
			if err != nil {
				t.Fatalf("failed to decrypt: %v", err)
			}
			if gotKid != tt.kid {
				t.Fatalf("expected kid %s, got %s", tt.kid, gotKid)
			}
			if gotAlg != tt.alg {
				t.Fatalf("expected alg %s, got %s", tt.alg, gotAlg)
			}
			if string(gotPubKey) != string(tt.publicKey) {
				t.Fatalf("expected public key %s, got %s", tt.publicKey, gotPubKey)
			}

		})
	}
}
