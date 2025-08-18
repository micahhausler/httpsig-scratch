package gh

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

func init() {
	jsonLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	}))
	slog.SetDefault(jsonLogger)
}

type GitHubClient struct {
	cli http.Client
}

func NewGitHubClient() *GitHubClient {
	return &GitHubClient{
		cli: http.Client{},
	}
}

// GetUserKeys fetches the public keys for a given GitHub user
func (c *GitHubClient) GetUserKeys(username string) ([][]byte, error) {
	// TODO: input sanitization
	uri := "https://github.com/" + username + ".keys"

	ghResp, err := c.cli.Get(uri)
	if err != nil {
		return nil, err
	}

	defer ghResp.Body.Close()

	buf := bytes.Buffer{}
	_, err = buf.ReadFrom(ghResp.Body)
	if err != nil {
		return nil, err
	}

	if ghResp.StatusCode != http.StatusOK {
		slog.Error("failed to fetch keys", "status", ghResp.Status, "response", buf.String())
		return nil, fmt.Errorf("failed to fetch keys: %s", ghResp.Status)
	}

	return bytes.Split(buf.Bytes(), []byte("\n")), nil
}
