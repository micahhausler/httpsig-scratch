```
sequenceDiagram
    participant tpm as Client TPM
    participant client as Client
    participant appserv as Application Server
    participant trust as EK Trust (pin file or EC2 API)
    opt Enrollment Sequence
        client->>tpm: Create endorsement key and restricted attestation key
        tpm->>client: EK and AK public areas
        client->>appserv: EK public, AK public, claimed machine
        appserv->>trust: Which endorsement key belongs to this machine?
        trust->>appserv: Trusted EK public
        appserv->>appserv: Require the presented EK to equal the trusted one
        appserv->>appserv: MakeCredential: wrap a secret to the EK, bound to the AK name
        appserv->>client: Credential blob, encrypted secret, nonce
        client->>tpm: ActivateCredential with the EK and AK
        tpm->>client: Recovered secret, proving both keys are in this TPM
        client->>tpm: Create signing key, Certify it with the AK over the nonce
        tpm->>client: Signing key public area, attestation, AK signature
        client->>appserv: Recovered secret, signing key public, attestation
        appserv->>appserv: Verify the secret, the attestation chain, the nonce, and the key attributes
        appserv->>client: KeyID (the signing key's TPM Name) and machine identity
    end
    loop Application Request Sequence
        client->>tpm: Sign the signature base
        tpm->>client: Signature
        client->>appserv: Signed request
        appserv->>appserv: Look up the enrolled key and machine identity for the given KeyID, validate the request signature
        appserv->>client: Response to signed request
    end
```
