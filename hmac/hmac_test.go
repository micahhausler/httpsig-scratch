package hmac

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
)

func TestHMAC(t *testing.T) {
	testcases := []struct {
		name          string
		key           []byte
		baseFunc      func() string
		wantSignErr   error
		wantVerifyErr error
	}{
		{
			name: "valid generated key",
			key: func() []byte {
				key := make([]byte, 32)
				rand.Read(key)
				return key
			}(),
			baseFunc:      func() string { return `hmac'd data` },
			wantSignErr:   nil,
			wantVerifyErr: nil,
		},
		{
			name:        "empty key",
			key:         nil,
			baseFunc:    func() string { return `hmac base` },
			wantSignErr: errors.New("no key provided"),
		},
		{
			name: "varying base",
			key: func() []byte {
				key := make([]byte, 32)
				rand.Read(key)
				return key
			}(),
			baseFunc: func() string {
				// return different data each time
				key := make([]byte, 32)
				rand.Read(key)
				return string(key)
			},
			wantSignErr:   nil,
			wantVerifyErr: errors.New("signature mismatch"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			hmac := NewHMAC(tc.key)

			sig, err := hmac.Sign(context.Background(), tc.baseFunc())
			if err != nil {
				if tc.wantSignErr == nil {
					t.Fatalf("unexpected sign error: %v", err)
				}
				if err.Error() != tc.wantSignErr.Error() {
					t.Fatalf("sign error: got %v, want %v", err, tc.wantSignErr)
				}
				return
			}

			validateErr := hmac.Verify(context.Background(), tc.baseFunc(), sig)
			if validateErr != nil {
				if tc.wantVerifyErr == nil {
					t.Fatalf("unexpected verify error: %v", validateErr)
				}
				if validateErr.Error() != tc.wantVerifyErr.Error() {
					t.Fatalf("verify error: got %v, want %v", validateErr, tc.wantVerifyErr)
				}
				return
			}

		})
	}
}
