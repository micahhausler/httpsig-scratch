package tpm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestEnrollmentRoundTrip(t *testing.T) {
	device, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed to open simulator: %v", err)
	}
	defer device.Close()

	signer, enrollment, err := CreateAttestedKey(device, "testuser")
	if err != nil {
		t.Fatalf("failed to create attested key: %v", err)
	}

	verifier, keyID, err := VerifyEnrollment(enrollment)
	if err != nil {
		t.Fatalf("enrollment did not verify: %v", err)
	}
	if keyID != signer.KeyID() {
		t.Errorf("server-derived keyid %s does not match signer keyid %s", keyID, signer.KeyID())
	}

	// a TPM signature over an arbitrary base must verify with the enrolled key
	base := []byte("test signature base")
	sig, err := signer.Sign(base)
	if err != nil {
		t.Fatalf("tpm sign failed: %v", err)
	}
	if err := verifier.Verify(base, sig); err != nil {
		t.Errorf("tpm signature did not verify: %v", err)
	}
	if err := verifier.Verify([]byte("different base"), sig); err == nil {
		t.Error("signature verified against a different base")
	}
}

func TestEnrollmentTampering(t *testing.T) {
	device, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed to open simulator: %v", err)
	}
	defer device.Close()

	_, enrollment, err := CreateAttestedKey(device, "testuser")
	if err != nil {
		t.Fatalf("failed to create attested key: %v", err)
	}

	// second, uncertified key: its public area is valid but the AK never
	// certified it
	_, otherEnrollment, err := CreateAttestedKey(device, "mallory")
	if err != nil {
		t.Fatalf("failed to create second key: %v", err)
	}

	// a foreign AK public area: correct template, but a software-generated
	// key that never signed the attestation. An AK from the same TPM would
	// be identical to the real one (primaries are deterministic), so a
	// substituted AK is necessarily foreign.
	foreignKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate foreign key: %v", err)
	}
	foreignAK := akTemplate
	foreignAK.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: foreignKey.X.FillBytes(make([]byte, 32))},
		Y: tpm2.TPM2BECCParameter{Buffer: foreignKey.Y.FillBytes(make([]byte, 32))},
	})
	foreignAKPublic := tpm2.Marshal(tpm2.New2B(foreignAK))

	cases := []struct {
		name    string
		mutate  func(e *Enrollment)
		wantErr string
	}{
		{
			name:    "renamed user",
			mutate:  func(e *Enrollment) { e.Username = "mallory" },
			wantErr: "qualifying data",
		},
		{
			name:    "substituted signing key",
			mutate:  func(e *Enrollment) { e.KeyPublic = otherEnrollment.KeyPublic },
			wantErr: "different key",
		},
		{
			name:    "substituted ak",
			mutate:  func(e *Enrollment) { e.AKPublic = foreignAKPublic },
			wantErr: "signature does not verify",
		},
		{
			name:    "unrestricted ak",
			mutate:  func(e *Enrollment) { e.AKPublic = e.KeyPublic },
			wantErr: "restricted",
		},
		{
			name: "corrupted attestation",
			mutate: func(e *Enrollment) {
				e.CertifyAttest = append([]byte{}, e.CertifyAttest...)
				e.CertifyAttest[len(e.CertifyAttest)-1] ^= 0xff
			},
			wantErr: "signature does not verify",
		},
		{
			name: "corrupted signature",
			mutate: func(e *Enrollment) {
				e.CertifySignature = append([]byte{}, e.CertifySignature...)
				e.CertifySignature[0] ^= 0xff
			},
			wantErr: "signature does not verify",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := *enrollment
			tc.mutate(&tampered)
			_, _, err := VerifyEnrollment(&tampered)
			if err == nil {
				t.Fatal("tampered enrollment verified")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}
