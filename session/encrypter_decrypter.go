package session

import (
	"context"
	"encoding/json"
)

type Encrypter interface {
	EncryptPublicKey(ctx context.Context, keyID, alg string, publicKey []byte, Attributes any) ([]byte, error)
}

type Decrypter interface {
	DecryptPublicKey(ctx context.Context, content []byte) (keyID, alg string, publicKey []byte, attributes json.RawMessage, err error)
}

type EncrypterDecrypter interface {
	Encrypter
	Decrypter
}
