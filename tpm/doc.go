/*
Package tpm signs HTTP messages with a key that lives inside a TPM, and admits
such keys only after the TPM has attested to how they were made.

An enrollment establishes a chain, each link checked by the server:

	signing key -> attestation key -> endorsement key -> a machine

TPM2_Certify signs a statement about the signing key's public area with a
restricted attestation key (AK). A restricted key will only sign structures the
TPM itself produced, so that signature is evidence rather than an assertion. The
statement carries the signing key's attributes: fixedTPM and sensitiveDataOrigin
mean the TPM generated the private key and will not let it leave.

TPM2_MakeCredential and TPM2_ActivateCredential bind the AK to an endorsement
key (EK). The server wraps a secret so that it can only be recovered by the
holder of a particular EK's private half, and only while a particular AK is
loaded in that same TPM. Recovering that secret is therefore proof of both.

Which EK to believe is the application's decision, and the one part that is not
cryptography. See EKTrust: a pinned file works for any TPM, while on EC2 the
control plane publishes the endorsement key of every NitroTPM instance, so an
enrollment can be anchored to an instance ID.

The identity a verified request carries is that machine, not anything the client
named for itself. The keyid is the signing key's TPM Name, a digest of its whole
public area, so the identifier a signature claims is exactly the object that was
attested.

Out of scope: measured boot. Nothing here inspects PCRs, so an enrollment says
where a key lives, not what the machine booted.
*/
package tpm
