package tpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
	"github.com/google/go-tpm/tpm2"
	"github.com/micahhausler/httpsig"
)

// secretLen is the size of the credential activation secret. 32 bytes is the
// longest digest the TPM will carry in a credential.
const secretLen = 32

// challenge is what the server must remember between the two rounds of an
// enrollment.
type challenge struct {
	identity Identity
	// akVerifier checks the certification signature in round two. Holding
	// the verifier rather than the public area means the AK the certify is
	// checked against is necessarily the one the activation was bound to.
	akVerifier httpsig.Verifier
	secret     []byte
	nonce      []byte
}

// newChallenge verifies that an endorsement key is trusted and that the
// attestation key is fit to attest, then wraps a fresh secret so that only the
// TPM holding that endorsement key can recover it, and only while that
// attestation key is loaded.
func newChallenge(identity Identity, ekPublic, akPublic []byte) (*challenge, *ChallengeResponse, error) {
	ekPub, err := publicContents(ekPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("bad ek_public: %w", err)
	}
	akPub, err := publicContents(akPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("bad ak_public: %w", err)
	}

	// The endorsement key must be a restricted decryption key fixed to its
	// TPM, or it is not an EK and activation would prove nothing.
	ekAttrs := ekPub.ObjectAttributes
	if !ekAttrs.Restricted || !ekAttrs.Decrypt || !ekAttrs.FixedTPM || !ekAttrs.SensitiveDataOrigin {
		return nil, nil, fmt.Errorf("endorsement key is not a restricted TPM-resident decryption key")
	}
	if ekPub.Type != tpm2.TPMAlgRSA {
		return nil, nil, fmt.Errorf("only RSA endorsement keys are supported")
	}
	rsaDetail, err := ekPub.Parameters.RSADetail()
	if err != nil {
		return nil, nil, fmt.Errorf("bad ek parameters: %w", err)
	}
	rsaUnique, err := ekPub.Unique.RSA()
	if err != nil {
		return nil, nil, fmt.Errorf("bad ek public key: %w", err)
	}
	ekKey, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		return nil, nil, fmt.Errorf("bad ek public key: %w", err)
	}

	// The attestation key must be restricted, so that its signature can only
	// ever cover structures the TPM generated.
	akAttrs := akPub.ObjectAttributes
	if !akAttrs.Restricted || !akAttrs.SignEncrypt || !akAttrs.FixedTPM || !akAttrs.SensitiveDataOrigin {
		return nil, nil, fmt.Errorf("attestation key is not a restricted TPM-resident signing key")
	}
	akKey, err := eccPubKey(akPub)
	if err != nil {
		return nil, nil, fmt.Errorf("bad ak public key: %w", err)
	}
	akVerifier, err := httpsig.NewVerifier(httpsig.ECDSAP256SHA256, akKey)
	if err != nil {
		return nil, nil, err
	}

	akName, err := tpm2.ObjectName(akPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute ak name: %w", err)
	}
	akDigest, err := nameDigest(*akName)
	if err != nil {
		return nil, nil, fmt.Errorf("bad ak name: %w", err)
	}

	secret := make([]byte, secretLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	// Credential protection binds the secret to the AK's name, so the TPM
	// will only release it while that exact object is loaded. Done in
	// software here: the server needs no TPM of its own.
	blob, encSecret, err := credactivation.Generate(
		&legacy.HashValue{Alg: legacy.AlgSHA256, Value: akDigest},
		ekKey,
		16, // AES-128 block size, per the reference EK template's symmetric alg
		secret,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate credential: %w", err)
	}

	// credactivation returns each blob with a two-byte length prefix, and the
	// command structures add their own, so the prefixes come off here.
	blob, err = stripU16Prefix(blob)
	if err != nil {
		return nil, nil, fmt.Errorf("bad credential blob: %w", err)
	}
	encSecret, err = stripU16Prefix(encSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("bad encrypted secret: %w", err)
	}

	return &challenge{
			identity:   identity,
			akVerifier: akVerifier,
			secret:     secret,
			nonce:      nonce,
		}, &ChallengeResponse{
			CredentialBlob:  blob,
			EncryptedSecret: encSecret,
			Nonce:           nonce,
		}, nil
}

// verifyEnrollment completes an enrollment against its challenge, returning a
// verifier for the application signing key and the key's TPM Name as its keyid.
//
// What has to hold: the client recovered the activation secret, which only the
// endorsement key's TPM could do; the attestation key that certified the
// signing key is the one that activation was bound to; the certification names
// this signing key and carries this challenge's nonce; and the signing key's
// attributes say the TPM generated it and will not let it leave.
func verifyEnrollment(c *challenge, req *EnrollRequest) (httpsig.Verifier, string, error) {
	if subtle.ConstantTimeCompare(c.secret, req.Secret) != 1 {
		return nil, "", fmt.Errorf("activation secret does not match")
	}

	keyPub, err := publicContents(req.KeyPublic)
	if err != nil {
		return nil, "", fmt.Errorf("bad key_public: %w", err)
	}

	if len(req.CertifySignature) != 64 {
		return nil, "", fmt.Errorf("certify signature must be 64 bytes, got %d", len(req.CertifySignature))
	}
	if err := c.akVerifier.Verify(req.CertifyAttest, req.CertifySignature); err != nil {
		return nil, "", fmt.Errorf("certify signature does not verify against ak: %w", err)
	}

	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](req.CertifyAttest)
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
	if !bytes.Equal(attest.ExtraData.Buffer, c.nonce) {
		return nil, "", fmt.Errorf("attestation is not bound to this challenge")
	}

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

func stripU16Prefix(b []byte) ([]byte, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("too short to hold a length prefix")
	}
	n := int(b[0])<<8 | int(b[1])
	if n != len(b)-2 {
		return nil, fmt.Errorf("length prefix says %d bytes, got %d", n, len(b)-2)
	}
	return b[2:], nil
}

func publicContents(tpmtPublic []byte) (*tpm2.TPMTPublic, error) {
	// Marshalled with tpm2.Marshal on a TPMTPublic, so there is no TPM2B
	// wrapper to strip.
	return tpm2.Unmarshal[tpm2.TPMTPublic](tpmtPublic)
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
