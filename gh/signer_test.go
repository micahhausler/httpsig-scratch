package gh

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/verifier"
	"golang.org/x/crypto/ssh"
)

func TestGitHubKeySigner(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		privateKey []byte
		verifier   verifier.Algorithm
		wantErr    bool
	}{
		{
			name: "valid ecdsa key",
			privateKey: func() []byte {
				block, _ := ssh.MarshalPrivateKey(priv, "")
				buf := bytes.Buffer{}
				pem.Encode(&buf, block)
				return buf.Bytes()
			}(),
			verifier: alg_ecdsa.NewP256Verifier(&priv.PublicKey),
			wantErr:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ghSigner, err := NewGHSigner(tc.privateKey)
			if err != nil {
				if !tc.wantErr {
					t.Error(err)
				}
				return
			}
			if tc.wantErr {
				t.Errorf("wanted error, got none")
				return
			}
			gotSig, err := ghSigner.Sign(context.Background(), "test")
			if err != nil {
				t.Error(err)
			}
			err = tc.verifier.Verify(context.Background(), "test", gotSig)
			if err != nil {
				t.Error(err)
			}
		})
	}
}
