package gh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"testing"

	"github.com/common-fate/httpsig/verifier"
	rsaAlgo "github.com/micahhausler/httpsig-scratch/rsa"
	"golang.org/x/crypto/ssh"
)

func TestAddKeys(t *testing.T) {

	kp, err := rsa.GenerateKey(rand.Reader, 64)
	if err != nil {
		panic(err)
	}
	kP, err := ssh.NewPublicKey(&kp.PublicKey)
	if err != nil {
		panic(err)
	}
	testKey := ssh.MarshalAuthorizedKey(kP)
	testKeyHash := sha512.Sum512(kP.Marshal())
	testKeyHashString := fmt.Sprintf("%x", testKeyHash)

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
			[][]byte{testKey},
			map[string][]verifier.Algorithm{
				testKeyHashString: {rsaAlgo.NewRSAPKCS256Verifier(&kp.PublicKey), rsaAlgo.NewRSAPSS512Verifier(&kp.PublicKey)},
			},
			false,
		},
		{
			"key exists",
			keysForUsers{"testuser": map[string][]verifier.Algorithm{
				testKeyHashString: {rsaAlgo.NewRSAPKCS256Verifier(&kp.PublicKey), rsaAlgo.NewRSAPSS512Verifier(&kp.PublicKey)},
			}},
			"testuser",
			[][]byte{testKey},
			map[string][]verifier.Algorithm{
				testKeyHashString: {rsaAlgo.NewRSAPKCS256Verifier(&kp.PublicKey), rsaAlgo.NewRSAPSS512Verifier(&kp.PublicKey)},
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
