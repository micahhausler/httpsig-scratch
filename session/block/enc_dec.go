package block

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"

	"github.com/micahhausler/httpsig-scratch/session"
)

// SessionToken is an internal format that for serializing sesion token information for encryption
type SessionToken struct {
	KeyID      string `json:"key_id"`
	Alg        string `json:"alg"`
	PublicKey  []byte `json:"public_key"`
	Attributes any    `json:"attributes"`
}

type BlockEncrypterDecrypter struct {
	block cipher.Block
}

func NewBlockSessionEncrypterDecrypter(block cipher.Block) session.EncrypterDecrypter {
	return &BlockEncrypterDecrypter{block: block}
}

func (e *BlockEncrypterDecrypter) EncryptPublicKey(ctx context.Context, keyID, alg string, publicKey []byte, attributes any) ([]byte, error) {

	st := &SessionToken{
		KeyID:      keyID,
		Alg:        alg,
		PublicKey:  publicKey,
		Attributes: attributes,
	}
	plaintext, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(e.block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	resp := base64.StdEncoding.EncodeToString(ciphertext)
	return []byte(resp), nil
}

func (e *BlockEncrypterDecrypter) DecryptPublicKey(ctx context.Context, content []byte) (keyID, alg string, publicKey []byte, attributes any, err error) {
	ciphertext, err := base64.StdEncoding.DecodeString(string(content))
	if err != nil {
		return "", "", nil, nil, err
	}

	gcm, err := cipher.NewGCM(e.block)
	if err != nil {
		return "", "", nil, nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		return "", "", nil, nil, err
	}
	st := &SessionToken{}
	err = json.Unmarshal(plaintext, st)
	if err != nil {
		return "", "", nil, nil, err
	}
	return st.KeyID, st.Alg, st.PublicKey, st.Attributes, nil
}
