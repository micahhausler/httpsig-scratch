package tpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/micahhausler/httpsig"
)

// VerifyEnrollment checks that an enrollment's application key was certified
// by its AK as resident in the same TPM with the expected properties, and
// returns an httpsig verifier for the key plus its keyid (the hex TPM Name).
//
// The AK itself is trusted on first use; anchoring it to an endorsement key
// certificate is out of scope here.
func VerifyEnrollment(e *Enrollment) (httpsig.Verifier, string, error) {
	akPub, err := publicContents(e.AKPublic)
	if err != nil {
		return nil, "", fmt.Errorf("bad ak_public: %w", err)
	}
	keyPub, err := publicContents(e.KeyPublic)
	if err != nil {
		return nil, "", fmt.Errorf("bad key_public: %w", err)
	}

	// The AK must be a restricted, TPM-resident signing key: a restricted
	// key only signs TPM-generated structures, so its signature over the
	// attestation below cannot have been forged from arbitrary data.
	akAttrs := akPub.ObjectAttributes
	if !akAttrs.Restricted || !akAttrs.SignEncrypt || !akAttrs.FixedTPM || !akAttrs.SensitiveDataOrigin {
		return nil, "", fmt.Errorf("ak is not a restricted TPM-resident signing key")
	}
	akKey, err := eccPubKey(akPub)
	if err != nil {
		return nil, "", fmt.Errorf("bad ak public key: %w", err)
	}

	// Verify the AK's signature over the attestation bytes.
	if len(e.CertifySignature) != 64 {
		return nil, "", fmt.Errorf("certify signature must be 64 bytes, got %d", len(e.CertifySignature))
	}
	digest := sha256.Sum256(e.CertifyAttest)
	r := new(big.Int).SetBytes(e.CertifySignature[:32])
	s := new(big.Int).SetBytes(e.CertifySignature[32:])
	if !ecdsa.Verify(akKey, digest[:], r, s) {
		return nil, "", fmt.Errorf("certify signature does not verify against ak")
	}

	// Parse the attestation and check it certifies exactly the enrolled key:
	// the attested Name is a digest of the key's whole public area, so the
	// properties checked below are covered by the AK's signature.
	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](e.CertifyAttest)
	if err != nil {
		return nil, "", fmt.Errorf("bad certify_attest: %w", err)
	}
	if attest.Magic != tpm2.TPMGeneratedValue {
		return nil, "", fmt.Errorf("attestation magic is not TPM_GENERATED")
	}
	certInfo, err := attest.Attested.Certify()
	if err != nil {
		return nil, "", fmt.Errorf("attestation is not a certify attestation: %w", err)
	}
	keyName, err := tpm2.ObjectName(keyPub)
	if err != nil {
		return nil, "", fmt.Errorf("failed to compute key name: %w", err)
	}
	if !bytes.Equal(certInfo.Name.Buffer, keyName.Buffer) {
		return nil, "", fmt.Errorf("attestation certifies a different key")
	}

	// The qualifying data binds the enrollment's claimed username into the
	// signed attestation.
	wantExtra := sha256.Sum256([]byte(e.Username))
	if !bytes.Equal(attest.ExtraData.Buffer, wantExtra[:]) {
		return nil, "", fmt.Errorf("attestation qualifying data does not match username")
	}

	// The application key must be TPM-generated and TPM-bound (its private
	// half never existed outside the TPM), and unrestricted so it may sign
	// HTTP signature bases.
	keyAttrs := keyPub.ObjectAttributes
	if !keyAttrs.FixedTPM || !keyAttrs.SensitiveDataOrigin || !keyAttrs.SignEncrypt {
		return nil, "", fmt.Errorf("signing key is not a TPM-resident signing key")
	}
	if keyAttrs.Restricted {
		return nil, "", fmt.Errorf("signing key must not be restricted")
	}

	pubKey, err := eccPubKey(keyPub)
	if err != nil {
		return nil, "", fmt.Errorf("bad signing public key: %w", err)
	}
	verifier, err := httpsig.NewVerifier(httpsig.ECDSAP256SHA256, pubKey)
	if err != nil {
		return nil, "", err
	}
	return verifier, fmt.Sprintf("%x", keyName.Buffer), nil
}

func publicContents(tpm2bPublic []byte) (*tpm2.TPMTPublic, error) {
	pub2B, err := tpm2.Unmarshal[tpm2.TPM2BPublic](tpm2bPublic)
	if err != nil {
		return nil, err
	}
	return pub2B.Contents()
}

func eccPubKey(pub *tpm2.TPMTPublic) (*ecdsa.PublicKey, error) {
	if pub.Type != tpm2.TPMAlgECC {
		return nil, fmt.Errorf("not an ECC key")
	}
	parms, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, err
	}
	if parms.CurveID != tpm2.TPMECCNistP256 {
		return nil, fmt.Errorf("not a P-256 key")
	}
	point, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}
	return tpm2.ECDSAPub(parms, point)
}
