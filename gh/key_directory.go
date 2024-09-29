package gh

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/common-fate/httpsig/verifier"
)

type GitHubKeyDirectory struct {
	keysForUsers keysForUsers
}

var _ verifier.KeyDirectory = &GitHubKeyDirectory{}

func NewGitHubKeyDirectory(usernames []string) (*GitHubKeyDirectory, error) {
	client := newGhClient()
	allKeys := map[string]map[string][]verifier.Algorithm{}

	for _, username := range usernames {
		keys, err := client.getUserKeys(username)
		if err != nil {
			return nil, err
		}
		addKeys(allKeys, username, keys)
	}

	return &GitHubKeyDirectory{
		keysForUsers: allKeys,
	}, nil
}

func (d *GitHubKeyDirectory) AddUserKeys(username string) error {
	client := newGhClient()
	keys, err := client.getUserKeys(username)
	if err != nil {
		return err
	}
	return addKeys(d.keysForUsers, username, keys)
}

func (d *GitHubKeyDirectory) GetKey(ctx context.Context, kid string, clientSpecifiedAlg string) (verifier.Algorithm, error) {
	users := []string{}
	algos := []verifier.Algorithm{}
	for user, keys := range d.keysForUsers {
		users = append(users, user)
		for key, keyAlgos := range keys {
			if key == kid {
				algos = append(algos, keyAlgos...)
			}
		}
	}
	if len(algos) == 0 {
		slog.Error("No keys found for request", "kid", kid, "alg", clientSpecifiedAlg)
		return nil, fmt.Errorf("no keys found for request")
	}

	// multiple users registered this key
	if len(users) > 1 {
		slog.Info("multiple users registered key", "users", users, "kid", kid)
	}
	return &ghAlgo{algos: algos, validAlgoId: -1}, nil
}
