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

	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/alg_ed25519"
	"github.com/common-fate/httpsig/alg_rsa"
	"github.com/common-fate/httpsig/verifier"
	"golang.org/x/crypto/ssh"
)

func TestAddKeys(t *testing.T) {

	rsaKp, err := rsa.GenerateKey(rand.Reader, 64)
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
		wantForUsername map[string][]verifier.Algorithm
		wantErr         bool
	}{
		{
			"rsa-ssh key",
			keysForUsers{},
			"testuser",
			[][]byte{testRSASSHKey},
			map[string][]verifier.Algorithm{
				testRSASSHKeyHashString: {alg_rsa.NewRSAPSS512Verifier(&rsaKp.PublicKey)},
			},
			false,
		},
		{
			"ecdsa p256 key",
			keysForUsers{},
			"testuser",
			[][]byte{testECDSA256SSHKey},
			map[string][]verifier.Algorithm{
				testECDSA256SSHKeyHashString: {alg_ecdsa.NewP256Verifier(&ecdsa256Kp.PublicKey)},
			},
			false,
		},
		{
			"ecdsa p384 key",
			keysForUsers{},
			"testuser",
			[][]byte{testECDSA384SSHKey},
			map[string][]verifier.Algorithm{
				testECDSA384SSHKeyHashString: {alg_ecdsa.NewP384Verifier(&ecdsa384Kp.PublicKey)},
			},
			false,
		},
		{
			"ed25519 key",
			keysForUsers{},
			"testuser",
			[][]byte{ssh.MarshalAuthorizedKey(testED25519SSHKey)},
			map[string][]verifier.Algorithm{
				testED25519SSHKeyHashString: {alg_ed25519.Ed25519{PublicKey: ed25519KP}},
			},
			false,
		},
		{
			"key exists",
			keysForUsers{"testuser": map[string][]verifier.Algorithm{
				testRSASSHKeyHashString: {alg_rsa.NewRSAPKCS256Verifier(&rsaKp.PublicKey), alg_rsa.NewRSAPSS512Verifier(&rsaKp.PublicKey)},
			}},
			"testuser",
			[][]byte{testRSASSHKey},
			map[string][]verifier.Algorithm{
				testRSASSHKeyHashString: {alg_rsa.NewRSAPKCS256Verifier(&rsaKp.PublicKey), alg_rsa.NewRSAPSS512Verifier(&rsaKp.PublicKey)},
			},
			false,
		},
		{
			"invalid key",
			keysForUsers{"testuser": map[string][]verifier.Algorithm{}},
			"testuser",
			[][]byte{[]byte(`ssh-rsa invalid`)},
			map[string][]verifier.Algorithm{},
			false,
		},
		{
			"invalid authorized key",
			keysForUsers{"testuser": map[string][]verifier.Algorithm{}},
			"testuser",
			[][]byte{[]byte(`invalid`)},
			map[string][]verifier.Algorithm{},
			false,
		},
		// {
		// 	"not implemented",
		// 	keysForUsers{"testuser": map[string][]verifier.Algorithm{}},
		// 	"testuser",
		// 	[][]byte{[]byte(`ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCZiXXZwdWUD9GxHNHahq+AwJMcV9OiHreuthqadCxvXBrbX07wkwDlqcPMSnh4Q7b3e5yrtVqulb73QLblpsP4=`)},
		// 	map[string][]verifier.Algorithm{},
		// 	false,
		// },
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
			// check that desired key count is present

			if len(tc.k[tc.username]) != len(tc.wantForUsername) {
				t.Errorf("expected %v keys, got %v", len(tc.wantForUsername), len(tc.k[tc.username]))
				t.Errorf("got: %#v", tc.k[tc.username])
				return
			}

			for kid, algos := range tc.wantForUsername {
				if len(tc.k[tc.username][kid]) != len(algos) {
					t.Errorf("expected algo count for key %s to be %d to be, got %d", kid, len(algos), len(tc.k[tc.username][kid]))
					return
				}
			}
		})
	}

}
