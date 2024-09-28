package multialgo

import (
	"context"
	"errors"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/verifier"
)

// AttributerAlgo is an interface that combines the Attributer and Algorithm
type AttributerAlgo interface {
	httpsig.Attributer
	verifier.Algorithm
}

// multiAlgoAttributerDirectory
type multiAlgoAttributerDirectory struct {
	algos map[string]AttributerAlgo
}

// NewMultiAlgoAttributerDirectory returns a new in-memory MultiAlgoAttributerDirectory.
// The KeyDirectory is an in-memory implementation that can handle multiple
// Algorithm types. The GetKey() response supports httpsig.Attributer
func NewMultiAlgoAttributerDirectory(algos map[string]AttributerAlgo) verifier.KeyDirectory {
	return &multiAlgoAttributerDirectory{algos: algos}
}

var _ verifier.KeyDirectory = &multiAlgoDirectory{}

func (d multiAlgoAttributerDirectory) GetKey(ctx context.Context, kid string, alg string) (verifier.Algorithm, error) {
	algo, ok := d.algos[kid]
	if !ok {
		return nil, errors.New("key not found")
	}
	if algo.Type() != alg {
		return nil, errors.New("key found but wrong algorithm")
	}

	return algo, nil
}
