package gh

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/common-fate/httpsig/verifier"
)

type DynamicGitHubKeyDirectory struct {
	keysForUsers keysForUsers
	client       *GitHubClient
	headerName   string
}

func NewDynamicGitHubKeyDirectory(headerName string) (*DynamicGitHubKeyDirectory, error) {
	return &DynamicGitHubKeyDirectory{
		keysForUsers: map[string]map[string][]verifier.Algorithm{},
		client:       NewGitHubClient(),
		headerName:   headerName,
	}, nil
}

// KeyFetcher is a middleware that adds the user's keys to the key directory
func (d *DynamicGitHubKeyDirectory) KeyFetcher(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := r.Header.Get(d.headerName)
		if username == "" {
			slog.Info("no username found in request")
			next.ServeHTTP(w, r)
			return
		}
		err := d.AddUserKeys(username)
		if err != nil {
			slog.Info("failed to add user keys", "error", err, "username", username)
		}
		next.ServeHTTP(w, r)
	})
}

func (d *DynamicGitHubKeyDirectory) AddUserKeys(username string) error {
	keys, err := d.client.GetUserKeys(username)
	if err != nil {
		return err
	}
	return addKeys(d.keysForUsers, username, keys)
}

func (d *DynamicGitHubKeyDirectory) GetKey(ctx context.Context, kid string, clientSpecifiedAlg string) (verifier.Algorithm, error) {
	users := []string{}
	algos := []verifier.Algorithm{}
	for user, keys := range d.keysForUsers {
		users = append(users, user)
		for key, keyAlgos := range keys {
			if key != kid {
				continue
			}
			for _, alg := range keyAlgos {
				if alg.Type() == clientSpecifiedAlg {
					algos = append(algos, keyAlgos...)
				}
			}
		}
	}
	if len(algos) == 0 {
		slog.Error("No keys found for request", "kid", kid, "alg", clientSpecifiedAlg)
		return nil, fmt.Errorf("no keys found for request")
	}

	// multiple users registered this key
	if len(users) > 1 {
		// TODO: create a new verifier.Algorithm that can handle multiple keys for the same id/alg
		// and try to verify with each one.
		slog.Info("multiple users registered key", "users", users, "kid", kid)
	}
	return &ghAlgo{algos: algos, validAlgoId: -1}, nil
}
