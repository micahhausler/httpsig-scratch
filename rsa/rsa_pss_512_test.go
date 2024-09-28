package rsa

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestSignVerify(t *testing.T) {
	kp, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
		return
	}

	rsaSigner := NewRSAPSS512Signer(kp)

	testCases := []struct {
		name          string
		base          string
		wantSignErr   bool
		wantVerifyErr bool
	}{
		{
			name:          "test1",
			base:          "test1",
			wantSignErr:   false,
			wantVerifyErr: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := rsaSigner.Sign(context.Background(), tc.base)
			if err != nil {
				if !tc.wantSignErr {
					t.Error(err)
				}
				return
			}
			if tc.wantSignErr {
				t.Errorf("wanted error, got none")
				return
			}

			err = rsaSigner.Verify(context.Background(), tc.base, got)
			if err != nil {
				if !tc.wantVerifyErr {
					t.Error(err)
				}
				return
			}
			if tc.wantVerifyErr {
				t.Errorf("wanted error, got none")
				return
			}

		})
	}

}
