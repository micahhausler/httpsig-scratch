package gh

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig-scratch/attributes"
	"github.com/micahhausler/httpsig/server"
)

// DynamicGitHubKeyDirectory resolves signatures against GitHub users' SSH
// public keys, fetching a user's keys on first sight of the username in a
// request header. The header value is unverified input; all it triggers is a
// fetch of that user's public keys.
type DynamicGitHubKeyDirectory struct {
	mu           sync.RWMutex
	keysForUsers keysForUsers
	client       *GitHubClient
	headerName   string
}

var _ server.KeyDirectory[attributes.User] = &DynamicGitHubKeyDirectory{}

func NewDynamicGitHubKeyDirectory(headerName string) (*DynamicGitHubKeyDirectory, error) {
	return &DynamicGitHubKeyDirectory{
		keysForUsers: keysForUsers{},
		client:       NewGitHubClient(),
		headerName:   headerName,
	}, nil
}

func (d *DynamicGitHubKeyDirectory) AddUserKeys(username string) error {
	keys, err := d.client.GetUserKeys(username)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return addKeys(d.keysForUsers, username, keys)
}

func (d *DynamicGitHubKeyDirectory) Key(req *http.Request, sig *httpsig.Signature) (httpsig.Verifier, attributes.User, error) {
	username := req.Header.Get(d.headerName)
	if username == "" {
		return nil, attributes.User{}, fmt.Errorf("no username found in request header %q", d.headerName)
	}

	d.mu.RLock()
	keys, ok := d.keysForUsers[username]
	d.mu.RUnlock()
	if !ok {
		if err := d.AddUserKeys(username); err != nil {
			slog.Info("failed to add user keys", "error", err, "username", username)
			return nil, attributes.User{}, err
		}
		d.mu.RLock()
		keys = d.keysForUsers[username]
		d.mu.RUnlock()
	}

	verifier, ok := keys[sig.KeyID()]
	if !ok {
		slog.Error("No keys found for request", "kid", sig.KeyID(), "username", username)
		return nil, attributes.User{}, fmt.Errorf("no keys found for request")
	}
	return verifier, attributes.User{Username: username}, nil
}
