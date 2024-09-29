package gh

import (
	"context"
	"fmt"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/contentdigest"
	"github.com/common-fate/httpsig/verifier"
)

type ghAlgo struct {
	algos       []verifier.Algorithm
	validAlgoId int
}

var _ verifier.Algorithm = &ghAlgo{}

// TODO: Type() is called before Verify(), so we don't know the valid algo.
// We probably can simplify this to just be one algo per key, or suffix the keyID with the algo?
// Can we just get the algo from the request and force that?
// we might need the library to tell us what algo the client sent and then we tell it if the keyID supports that algo
func (a *ghAlgo) Type() string {
	if len(a.algos) == 0 {
		return ""
	}
	if a.validAlgoId < 0 || a.validAlgoId > len(a.algos)-1 {
		return a.algos[0].Type()
	}
	return a.algos[a.validAlgoId].Type()
}

func (a *ghAlgo) Attributes() any {
	if len(a.algos) == 0 {
		return nil
	}
	if a.validAlgoId < 0 || a.validAlgoId > len(a.algos)-1 {
		return nil
	}
	if _, ok := a.algos[a.validAlgoId].(httpsig.Attributer); ok {
		return a.algos[a.validAlgoId].(httpsig.Attributer).Attributes()
	}
	return nil
}

func (a *ghAlgo) Verify(ctx context.Context, base string, signature []byte) error {
	if len(a.algos) == 0 {
		return fmt.Errorf("no algorithms to verify")
	}
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
