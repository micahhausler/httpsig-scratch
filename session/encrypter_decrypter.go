package session

import "context"

type Encrypter interface {
	EncryptPublicKey(ctx context.Context, keyID, alg string, publicKey []byte, Attributes any) ([]byte, error)
}

type Decrypter interface {
	DecryptPublicKey(ctx context.Context, content []byte) (keyID, alg string, publicKey []byte, attributes any, err error)
}

type EncrypterDecrypter interface {
	Encrypter
	Decrypter
}
