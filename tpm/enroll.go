package tpm

import (
	"crypto/sha256"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// akTemplate is a restricted ECC P-256 signing key: an attestation key, which
// can only sign structures the TPM itself produced, such as the TPM2_Certify
// attestation below. That restriction is what makes its signature evidence.
var akTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		SignEncrypt:         true,
		Restricted:          true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		Scheme: tpm2.TPMTECCScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
				&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
		},
		CurveID: tpm2.TPMECCNistP256,
	}),
}

// appKeyTemplate is an unrestricted ECC P-256 signing key for signing HTTP
// message signature bases. Identical to the AK template except Restricted:
// an unrestricted key may sign externally supplied digests.
var appKeyTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		SignEncrypt:         true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		Scheme: tpm2.TPMTECCScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
				&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
		},
		CurveID: tpm2.TPMECCNistP256,
	}),
}

// ChallengeRequest opens an enrollment. The endorsement key names the machine;
// the attestation key is what the server's challenge will be bound to.
type ChallengeRequest struct {
	// Claim is the client's assertion about which machine it is, such as an
	// EC2 instance ID. It is a lookup key for the server's EK trust source
	// and nothing more: a false claim yields a challenge encrypted to some
	// other machine's endorsement key, which this TPM cannot open.
	Claim string `json:"claim,omitempty"`
	// EKPublic is the endorsement key's TPMT_PUBLIC.
	EKPublic []byte `json:"ek_public"`
	// AKPublic is the attestation key's TPMT_PUBLIC.
	AKPublic []byte `json:"ak_public"`
}

// ChallengeResponse carries a secret that only the TPM holding the private
// endorsement key can recover, wrapped so that it can only be recovered while
// the named attestation key is loaded in that same TPM.
type ChallengeResponse struct {
	ChallengeID     string `json:"challenge_id,omitempty"`
	CredentialBlob  []byte `json:"credential_blob,omitempty"`
	EncryptedSecret []byte `json:"encrypted_secret,omitempty"`
	// Nonce must be the qualifying data of the certification in the
	// EnrollRequest, which ties that attestation to this challenge.
	Nonce []byte `json:"nonce,omitempty"`
	Error string `json:"error,omitempty"`
}

// EnrollRequest completes an enrollment.
type EnrollRequest struct {
	ChallengeID string `json:"challenge_id"`
	// Secret is the value recovered by TPM2_ActivateCredential, which is
	// proof that this client holds the endorsement key the server trusted.
	Secret []byte `json:"secret"`
	// KeyPublic is the application signing key's TPMT_PUBLIC.
	KeyPublic        []byte `json:"key_public"`
	CertifyAttest    []byte `json:"certify_attest"`
	CertifySignature []byte `json:"certify_signature"`
}

type EnrollResponse struct {
	KeyID    string   `json:"key_id,omitempty"`
	Identity Identity `json:"identity,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// An Enroller holds the TPM keys for one enrollment. The endorsement and
// attestation keys are needed across both rounds of the protocol, so they stay
// loaded until they are done with: a TPM has room for only a few transient
// objects at once, so each is released as soon as its part is over.
type Enroller struct {
	tpm transport.TPM
	ek  tpm2.AuthHandle
	ak  tpm2.NamedHandle

	ekLoaded bool
	akLoaded bool

	ekPublic []byte
	akPublic []byte
}

// NewEnroller creates the endorsement and attestation keys.
//
// The EK comes from the TCG reference template, which is what makes it
// comparable to the one a machine's operator published out of band: on EC2,
// this template reproduces ec2 get-instance-tpm-ek-pub byte for byte. Both
// keys are primaries, so they are derived from the TPM's seeds rather than
// generated, and both are the same on every run for a given TPM.
func NewEnroller(t transport.TPM) (*Enroller, error) {
	ekRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("failed to create endorsement key: %w", err)
	}

	akRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(akTemplate),
	}.Execute(t)
	if err != nil {
		flush(t, ekRsp.ObjectHandle)
		return nil, fmt.Errorf("failed to create attestation key: %w", err)
	}

	ekPub, err := ekRsp.OutPublic.Contents()
	if err != nil {
		flush(t, ekRsp.ObjectHandle, akRsp.ObjectHandle)
		return nil, err
	}
	akPub, err := akRsp.OutPublic.Contents()
	if err != nil {
		flush(t, ekRsp.ObjectHandle, akRsp.ObjectHandle)
		return nil, err
	}

	return &Enroller{
		tpm: t,
		// the endorsement hierarchy's reference template carries an
		// authPolicy of TPM2_PolicySecret(RH_ENDORSEMENT), so using the EK
		// requires a policy session rather than a password
		ek: tpm2.AuthHandle{
			Handle: ekRsp.ObjectHandle,
			Name:   ekRsp.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy),
		},
		ak: tpm2.NamedHandle{
			Handle: akRsp.ObjectHandle,
			Name:   akRsp.Name,
		},
		ekLoaded: true,
		akLoaded: true,
		ekPublic: tpm2.Marshal(ekPub),
		akPublic: tpm2.Marshal(akPub),
	}, nil
}

// ekPolicy satisfies the reference EK template's authPolicy.
func ekPolicy(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	_, err := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}.Execute(t)
	return err
}

// Challenge returns the request that opens an enrollment.
func (e *Enroller) Challenge(claim string) *ChallengeRequest {
	return &ChallengeRequest{
		Claim:    claim,
		EKPublic: e.ekPublic,
		AKPublic: e.akPublic,
	}
}

// Activate recovers the secret from the server's challenge.
//
// TPM2_ActivateCredential succeeds only when the private endorsement key can
// decrypt the seed and the named attestation key is loaded in the same TPM, so
// recovering this secret is what binds the AK to the machine the server
// trusted.
func (e *Enroller) Activate(rsp *ChallengeResponse) ([]byte, error) {
	acRsp, err := tpm2.ActivateCredential{
		ActivateHandle: e.ak,
		KeyHandle:      e.ek,
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: rsp.CredentialBlob},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: rsp.EncryptedSecret},
	}.Execute(e.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to activate credential: %w", err)
	}
	return acRsp.CertInfo.Buffer, nil
}

// CreateSigningKey creates the application signing key and certifies it with
// the attestation key, using the server's nonce as qualifying data so the
// attestation cannot be replayed into another enrollment.
//
// Unlike the EK and AK, this key is created under a storage root key rather
// than derived as a primary, so every enrollment gets a distinct key.
func (e *Enroller) CreateSigningKey(nonce []byte) (*Signer, *EnrollRequest, error) {
	// The endorsement key has no further part to play, and a TPM has room for
	// only a few loaded objects.
	if e.ekLoaded {
		flush(e.tpm, tpm2.TPMHandle(e.ek.Handle.HandleValue()))
		e.ekLoaded = false
	}

	srkRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(e.tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create storage root key: %w", err)
	}
	srk := tpm2.NamedHandle{Handle: srkRsp.ObjectHandle, Name: srkRsp.Name}

	createRsp, err := tpm2.Create{
		ParentHandle: srk,
		InPublic:     tpm2.New2B(appKeyTemplate),
	}.Execute(e.tpm)
	if err != nil {
		flush(e.tpm, srkRsp.ObjectHandle)
		return nil, nil, fmt.Errorf("failed to create signing key: %w", err)
	}

	loadRsp, err := tpm2.Load{
		ParentHandle: srk,
		InPrivate:    createRsp.OutPrivate,
		InPublic:     createRsp.OutPublic,
	}.Execute(e.tpm)
	// the storage root key is only needed to wrap and load the signing key
	flush(e.tpm, srkRsp.ObjectHandle)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load signing key: %w", err)
	}

	certRsp, err := tpm2.Certify{
		ObjectHandle: tpm2.NamedHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
		},
		SignHandle:     e.ak,
		QualifyingData: tpm2.TPM2BData{Buffer: nonce},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
	}.Execute(e.tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to certify signing key: %w", err)
	}

	attest, err := certRsp.CertifyInfo.Contents()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certify info: %w", err)
	}
	certSig, err := certRsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certify signature: %w", err)
	}

	keyPub, err := createRsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read signing key public area: %w", err)
	}

	signer := &Signer{
		tpm: e.tpm,
		key: tpm2.NamedHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
		},
		keyID: fmt.Sprintf("%x", loadRsp.Name.Buffer),
	}
	req := &EnrollRequest{
		// the bare TPMT_PUBLIC, matching how the EK and AK are sent
		KeyPublic:        tpm2.Marshal(keyPub),
		CertifyAttest:    tpm2.Marshal(attest),
		CertifySignature: rawECDSASig(certSig),
	}
	return signer, req, nil
}

// Close releases the endorsement and attestation keys, whichever are still
// loaded. The signing key from CreateSigningKey is left alone, since that is
// what signs requests.
func (e *Enroller) Close() {
	if e.ekLoaded {
		flush(e.tpm, tpm2.TPMHandle(e.ek.Handle.HandleValue()))
		e.ekLoaded = false
	}
	if e.akLoaded {
		flush(e.tpm, tpm2.TPMHandle(e.ak.Handle.HandleValue()))
		e.akLoaded = false
	}
}

func flush(t transport.TPM, handles ...tpm2.TPMHandle) {
	for _, h := range handles {
		tpm2.FlushContext{FlushHandle: h}.Execute(t)
	}
}

// akNameDigest returns the digest half of a TPM Name, without the leading
// two-byte hash algorithm identifier.
func nameDigest(name tpm2.TPM2BName) ([]byte, error) {
	if len(name.Buffer) != 2+sha256.Size {
		return nil, fmt.Errorf("expected a SHA-256 name, got %d bytes", len(name.Buffer))
	}
	return name.Buffer[2:], nil
}

// rawECDSASig converts a TPM ECDSA signature to r||s, each zero-padded to
// 32 bytes, the encoding RFC 9421 uses for ecdsa-p256-sha256.
func rawECDSASig(sig *tpm2.TPMSSignatureECC) []byte {
	out := make([]byte, 64)
	copy(out[32-len(sig.SignatureR.Buffer):32], sig.SignatureR.Buffer)
	copy(out[64-len(sig.SignatureS.Buffer):], sig.SignatureS.Buffer)
	return out
}
