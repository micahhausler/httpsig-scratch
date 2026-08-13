package gh

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig-scratch/attributes"
	"github.com/micahhausler/httpsig/server"
)

// GitHubKeyDirectory resolves signatures against the SSH public keys of a
// fixed set of GitHub users, fetched once at construction.
type GitHubKeyDirectory struct {
	keysForUsers keysForUsers
}

var _ server.KeyDirectory[attributes.User] = &GitHubKeyDirectory{}

func NewGitHubKeyDirectory(usernames []string) (*GitHubKeyDirectory, error) {
	client := NewGitHubClient()
	allKeys := keysForUsers{}

	for _, username := range usernames {
		keys, err := client.GetUserKeys(username)
		if err != nil {
			return nil, err
		}
		addKeys(allKeys, username, keys)
	}

	return &GitHubKeyDirectory{
		keysForUsers: allKeys,
	}, nil
}

func (d *GitHubKeyDirectory) Key(req *http.Request, sig *httpsig.Signature) (httpsig.Verifier, attributes.User, error) {
	kid := sig.KeyID()
	for user, keys := range d.keysForUsers {
		if verifier, ok := keys[kid]; ok {
			return verifier, attributes.User{Username: user}, nil
		}
	}
	slog.Error("No keys found for request", "kid", kid)
	return nil, attributes.User{}, fmt.Errorf("no keys found for request")
}
