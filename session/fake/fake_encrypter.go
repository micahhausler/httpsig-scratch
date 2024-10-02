package fake

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
)

type SessionToken struct {
	KeyID      string `json:"key_id"`
	Alg        string `json:"alg"`
	PublicKey  []byte `json:"public_key"`
	Attributes any    `json:"attributes"`
}

type FakeEncrypterDecrypter struct{}

func (e *FakeEncrypterDecrypter) EncryptPublicKey(ctx context.Context, keyID, alg string, publicKey, attributes any) ([]byte, error) {
	var err error
	kPbytes := []byte{}
	switch alg {
	case "ed25519", "rsa-pss-sha512", "rsa-v1_5-sha256", "ecdsa-p256-sha256", "ecdsa-p384-sha384":
		kPbytes, err = x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return nil, err
		}
	case "hmac-sha256":
		kPbytes = publicKey.([]byte)
	}

	st := &SessionToken{
		KeyID:      keyID,
		Alg:        alg,
		PublicKey:  kPbytes,
		Attributes: attributes,
	}
	data, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	resp := base64.StdEncoding.EncodeToString(data)
	return []byte(resp), nil
}

func (d *FakeEncrypterDecrypter) DecryptPublicKey(ctx context.Context, content []byte) (keyID, alg string, publicKey, attributes any, err error) {
	decoded, err := base64.StdEncoding.DecodeString(string(content))
	if err != nil {
		return "", "", nil, nil, err
	}
	st := &SessionToken{}
	err = json.Unmarshal(decoded, st)
	if err != nil {
		return "", "", nil, nil, err
	}
	var kP any
	switch st.Alg {
	case "ed25519", "rsa-pss-sha512", "rsa-v1_5-sha256", "ecdsa-p256-sha256", "ecdsa-p384-sha384":
		kP, err = x509.ParsePKIXPublicKey(st.PublicKey)
		if err != nil {
			return "", "", nil, nil, err
		}
	case "hmac-sha256":
		kP = st.PublicKey
	}

	return st.KeyID, st.Alg, kP, st.Attributes, nil
}
