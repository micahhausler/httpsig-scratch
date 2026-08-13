/*
Package tpm exercises HTTP message signatures with a TPM-resident key.

The client creates two keys in the TPM: a restricted attestation key (AK)
and an unrestricted application signing key. TPM2_Certify produces an
AK-signed statement that the application key lives in the same TPM with
properties fixed at creation (fixedTPM, sensitiveDataOrigin, sign, not
restricted): the private key was generated inside the TPM and can never
leave it.

The server admits a key to its directory only after verifying that
certification, and uses the key's TPM Name (a digest of its public area)
as the httpsig keyid, so the identifier a signature claims is exactly the
object that was attested.

The AK itself is trusted on first use. A production deployment anchors the
AK to the TPM's endorsement key certificate (on AWS, the NitroTPM EK cert)
via MakeCredential/ActivateCredential; this demo stops at the certify
chain.
*/
package tpm
