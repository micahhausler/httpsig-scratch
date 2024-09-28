package multialgo

import (
	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/signer"
	"github.com/common-fate/httpsig/verifier"
)

// SignerVerifierAttributer is an interface that combines the Attributer,
// signer.Algorithm, and verifier.Algorithm interfaces
type SignerVerifierAttributer interface {
	httpsig.Attributer
	signer.Algorithm
	verifier.Algorithm
}

// SignerVerifier is an interface that combines the signer and verifier Algorithm interfaces
type SignerVerifier interface {
	signer.Algorithm
	verifier.Algorithm
}
