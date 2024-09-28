package multialgo

import (
	"context"
	"errors"

	"github.com/common-fate/httpsig/verifier"
)

type multiAlgoDirectory struct {
	algos map[string]verifier.Algorithm
}

// NewMultiAlgoDirectory returns a new in-memory KeyDirectory
// that supports multiple Algorithm types. The GetKey() method
// will return the Algorithm if it is found in the map, but does
// not support the httpsig.Attributer interface.
func NewMultiAlgoDirectory(algos map[string]verifier.Algorithm) verifier.KeyDirectory {
	return &multiAlgoDirectory{algos: algos}
}

var _ verifier.KeyDirectory = &multiAlgoDirectory{}

func (d multiAlgoDirectory) GetKey(ctx context.Context, kid string, alg string) (verifier.Algorithm, error) {
	algo, ok := d.algos[kid]
	if !ok {
		return nil, errors.New("key not found")
	}
	if algo.Type() != alg {
		return nil, errors.New("key found but wrong algorithm")
	}

	return algo, nil
}
