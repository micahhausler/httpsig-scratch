package gh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"testing"

	"github.com/micahhausler/httpsig"
	"golang.org/x/crypto/ssh"
)

func TestAddKeys(t *testing.T) {

	rsaKp, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}
	rsaKP, err := ssh.NewPublicKey(&rsaKp.PublicKey)
	if err != nil {
		t.Fatalf("error creating ssh key: %v", err)
	}
	testRSASSHKey := ssh.MarshalAuthorizedKey(rsaKP)
	testRSASSHKeyHash := sha512.Sum512(rsaKP.Marshal())
	testRSASSHKeyHashString := fmt.Sprintf("%x", testRSASSHKeyHash)

	rsaVerifier, err := httpsig.NewVerifier(httpsig.RSAPSSSHA512, &rsaKp.PublicKey)
	if err != nil {
		t.Fatalf("error creating verifier: %v", err)
	}

	ecdsa256Kp, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}
	ecdsa256KP, err := ssh.NewPublicKey(&ecdsa256Kp.PublicKey)
	if err != nil {
		t.Fatalf("error creating ssh key: %v", err)
	}
	testECDSA256SSHKey := ssh.MarshalAuthorizedKey(ecdsa256KP)
	testECDSA256SSHKeyHash := sha512.Sum512(ecdsa256KP.Marshal())
	testECDSA256SSHKeyHashString := fmt.Sprintf("%x", testECDSA256SSHKeyHash)

	ecdsa384Kp, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}
	ecdsa384KP, err := ssh.NewPublicKey(&ecdsa384Kp.PublicKey)
	if err != nil {
		t.Fatalf("error creating ssh key: %v", err)
	}
	testECDSA384SSHKey := ssh.MarshalAuthorizedKey(ecdsa384KP)
	testECDSA384SSHKeyHash := sha512.Sum512(ecdsa384KP.Marshal())
	testECDSA384SSHKeyHashString := fmt.Sprintf("%x", testECDSA384SSHKeyHash)

	ed25519KP, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}
	testED25519SSHKey, err := ssh.NewPublicKey(ed25519KP)
	if err != nil {
		t.Fatalf("error creating ssh key: %v", err)
	}
	testED25519SSHKeyHash := sha512.Sum512(testED25519SSHKey.Marshal())
	testED25519SSHKeyHashString := fmt.Sprintf("%x", testED25519SSHKeyHash)

	cases := []struct {
		name            string
		k               keysForUsers
		username        string
		keys            [][]byte
		wantForUsername map[string]httpsig.Algorithm
		wantErr         bool
	}{
		{
			"rsa-ssh key",
			keysForUsers{},
			"testuser",
			[][]byte{testRSASSHKey},
			map[string]httpsig.Algorithm{
				testRSASSHKeyHashString: httpsig.RSAPSSSHA512,
			},
			false,
		},
		{
			"ecdsa p256 key",
			keysForUsers{},
			"testuser",
			[][]byte{testECDSA256SSHKey},
			map[string]httpsig.Algorithm{
				testECDSA256SSHKeyHashString: httpsig.ECDSAP256SHA256,
			},
			false,
		},
		{
			"ecdsa p384 key",
			keysForUsers{},
			"testuser",
			[][]byte{testECDSA384SSHKey},
			map[string]httpsig.Algorithm{
				testECDSA384SSHKeyHashString: httpsig.ECDSAP384SHA384,
			},
			false,
		},
		{
			"ed25519 key",
			keysForUsers{},
			"testuser",
			[][]byte{ssh.MarshalAuthorizedKey(testED25519SSHKey)},
			map[string]httpsig.Algorithm{
				testED25519SSHKeyHashString: httpsig.Ed25519,
			},
			false,
		},
		{
			"key exists",
			keysForUsers{"testuser": map[string]httpsig.Verifier{
				testRSASSHKeyHashString: rsaVerifier,
			}},
			"testuser",
			[][]byte{testRSASSHKey},
			map[string]httpsig.Algorithm{
				testRSASSHKeyHashString: httpsig.RSAPSSSHA512,
			},
			false,
		},
		{
			"invalid key",
			keysForUsers{"testuser": map[string]httpsig.Verifier{}},
			"testuser",
			[][]byte{[]byte(`ssh-rsa invalid`)},
			map[string]httpsig.Algorithm{},
			false,
		},
		{
			"invalid authorized key",
			keysForUsers{"testuser": map[string]httpsig.Verifier{}},
			"testuser",
			[][]byte{[]byte(`invalid`)},
			map[string]httpsig.Algorithm{},
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {

			err := addKeys(tc.k, tc.username, tc.keys)
			if err != nil {
				if !tc.wantErr {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if tc.wantErr {
				t.Error("expected error, got none")
				return
			}

			if len(tc.k[tc.username]) != len(tc.wantForUsername) {
				t.Errorf("expected %v keys, got %v", len(tc.wantForUsername), len(tc.k[tc.username]))
				t.Errorf("got: %#v", tc.k[tc.username])
				return
			}

			for kid, wantAlg := range tc.wantForUsername {
				got, ok := tc.k[tc.username][kid]
				if !ok {
					t.Errorf("expected key %s to be present", kid)
					continue
				}
				if got.Algorithm() != wantAlg {
					t.Errorf("expected key %s to have algorithm %s, got %s", kid, wantAlg, got.Algorithm())
				}
			}
		})
	}

}
