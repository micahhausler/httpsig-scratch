package gh

import (
	"bytes"
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

type ghClient struct {
	cli http.Client
}

func newGhClient() *ghClient {
	return &ghClient{
		cli: http.Client{},
	}
}

// getUserKeys fetches the public keys for a given GitHub user
func (c *ghClient) getUserKeys(username string) ([][]byte, error) {
	// TODO: input sanitization
	uri := "https://api.github.com/users/" + username + ".keys"

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
	return bytes.Split(buf.Bytes(), []byte("\n")), nil
}
