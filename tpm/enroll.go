package tpm

import (
	"crypto/sha256"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// akTemplate is a restricted ECC P-256 signing key: an attestation key that
// can only sign TPM-generated structures such as TPM2_Certify attestations.
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

// An Enrollment carries a TPM application key and its certification to the
// server. []byte fields marshal as base64 in JSON.
type Enrollment struct {
	Username string `json:"username"`
	// AKPublic is the attestation key's TPM2B_PUBLIC area.
	AKPublic []byte `json:"ak_public"`
	// KeyPublic is the application signing key's TPM2B_PUBLIC area.
	KeyPublic []byte `json:"key_public"`
	// CertifyAttest is the TPMS_ATTEST produced by TPM2_Certify over the
	// application key, with sha256(username) as the qualifying data.
	CertifyAttest []byte `json:"certify_attest"`
	// CertifySignature is the AK's ECDSA signature over CertifyAttest,
	// r and s zero-padded to 32 bytes and concatenated.
	CertifySignature []byte `json:"certify_signature"`
}

type EnrollmentResponse struct {
	KeyID string `json:"key_id,omitempty"`
	Error string `json:"error,omitempty"`
}

// CreateAttestedKey creates an AK and an application signing key in the TPM,
// certifies the application key with the AK, and returns a Signer backed by
// the application key along with the Enrollment to register it.
//
// The AK is a primary key, deterministic for a given TPM: it identifies the
// TPM. The application key is freshly generated under a storage root key on
// every call: it identifies this enrollment.
func CreateAttestedKey(tpm transport.TPM, username string) (*Signer, *Enrollment, error) {
	srkRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create storage root key: %w", err)
	}

	createRsp, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: srkRsp.ObjectHandle,
			Name:   srkRsp.Name,
		},
		InPublic: tpm2.New2B(appKeyTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create signing key: %w", err)
	}

	loadRsp, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: srkRsp.ObjectHandle,
			Name:   srkRsp.Name,
		},
		InPrivate: createRsp.OutPrivate,
		InPublic:  createRsp.OutPublic,
	}.Execute(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load signing key: %w", err)
	}

	// the SRK's job is done; free its slot before creating the AK, keeping
	// at most two transient objects loaded at once
	if _, err := (tpm2.FlushContext{FlushHandle: srkRsp.ObjectHandle}).Execute(tpm); err != nil {
		return nil, nil, fmt.Errorf("failed to flush storage root key: %w", err)
	}

	akRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(akTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create attestation key: %w", err)
	}

	// binds the enrollment's claimed identity into the attestation
	qualifyingData := sha256.Sum256([]byte(username))

	certRsp, err := tpm2.Certify{
		ObjectHandle: tpm2.NamedHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
		},
		SignHandle: tpm2.NamedHandle{
			Handle: akRsp.ObjectHandle,
			Name:   akRsp.Name,
		},
		QualifyingData: tpm2.TPM2BData{Buffer: qualifyingData[:]},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
	}.Execute(tpm)
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

	// the AK's job is done; free its slot
	if _, err := (tpm2.FlushContext{FlushHandle: akRsp.ObjectHandle}).Execute(tpm); err != nil {
		return nil, nil, fmt.Errorf("failed to flush attestation key: %w", err)
	}

	enrollment := &Enrollment{
		Username:         username,
		AKPublic:         tpm2.Marshal(akRsp.OutPublic),
		KeyPublic:        tpm2.Marshal(createRsp.OutPublic),
		CertifyAttest:    tpm2.Marshal(attest),
		CertifySignature: rawECDSASig(certSig),
	}

	signer := &Signer{
		tpm: tpm,
		key: tpm2.NamedHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
		},
		keyID: fmt.Sprintf("%x", loadRsp.Name.Buffer),
	}
	return signer, enrollment, nil
}

// rawECDSASig converts a TPM ECDSA signature to r||s, each zero-padded to
// 32 bytes, the encoding RFC 9421 uses for ecdsa-p256-sha256.
func rawECDSASig(sig *tpm2.TPMSSignatureECC) []byte {
	out := make([]byte, 64)
	copy(out[32-len(sig.SignatureR.Buffer):32], sig.SignatureR.Buffer)
	copy(out[64-len(sig.SignatureS.Buffer):], sig.SignatureS.Buffer)
	return out
}
