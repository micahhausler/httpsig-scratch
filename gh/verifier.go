package gh

import (
	"context"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/contentdigest"
	"github.com/common-fate/httpsig/verifier"
)

type ghAlgo struct {
	algos       []verifier.Algorithm
	validAlgoId int
}

var _ verifier.Algorithm = &ghAlgo{}

func (a *ghAlgo) Type() string {
	if a.validAlgoId < 0 || a.validAlgoId > len(a.algos)-1 {
		return a.algos[0].Type()
	}
	return a.algos[a.validAlgoId].Type()
}

func (a *ghAlgo) Attributes() any {
	if a.validAlgoId < 0 || a.validAlgoId > len(a.algos)-1 {
		return nil
	}
	if _, ok := a.algos[a.validAlgoId].(httpsig.Attributer); ok {
		return a.algos[a.validAlgoId].(httpsig.Attributer).Attributes()
	}
	return nil
}

func (a *ghAlgo) Verify(ctx context.Context, base string, signature []byte) error {
	var err error
	for i, algo := range a.algos {
		err = algo.Verify(ctx, base, signature)
		if err == nil {
			a.validAlgoId = i
			return nil
		}
	}
	return err
}

func (a *ghAlgo) ContentDigest() contentdigest.Digester {
	if a.validAlgoId < 0 || a.validAlgoId > len(a.algos)-1 {
		return a.algos[0].ContentDigest()
	}
	return a.algos[a.validAlgoId].ContentDigest()
}
