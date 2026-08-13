package gh

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"github.com/micahhausler/httpsig"
	"golang.org/x/crypto/ssh"
)

func TestGitHubKeySigner(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := httpsig.NewVerifier(httpsig.ECDSAP256SHA256, &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		privateKey []byte
		verifier   httpsig.Verifier
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
			verifier: verifier,
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
			gotSig, err := ghSigner.Sign([]byte("test"))
			if err != nil {
				t.Error(err)
			}
			err = tc.verifier.Verify([]byte("test"), gotSig)
			if err != nil {
				t.Error(err)
			}
		})
	}
}
