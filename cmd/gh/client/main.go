package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/common-fate/httpsig"
	"github.com/micahhausler/httpsig-scratch/gh"
)

func init() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)
}

type headerRoundTripper struct {
	transport http.RoundTripper
	header    http.Header
}

func (h *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for key, values := range h.header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	return h.transport.RoundTrip(req)
}

func main() {
	keyFile := flag.String("key", "", "path to private key")
	host := flag.String("host", "localhost", "host to connect to")
	port := flag.Int("port", 9091, "port to connect to")
	flag.Parse()
	addr := fmt.Sprintf("http://%s:%d", *host, *port)

	keyData, err := os.ReadFile(*keyFile)
	if err != nil {
		slog.Error("failed to read key file", "error", err)
		os.Exit(1)
	}

	algorithm, err := gh.NewGHSigner(keyData)
	if err != nil {
		slog.Error("failed to create signer", "error", err)
		os.Exit(1)
	}

	client := httpsig.NewClient(httpsig.ClientOpts{
		KeyID: algorithm.KeyID(),
		Tag:   "foo",
		Alg:   algorithm,
		CoveredComponents: []string{
			"@method", "@target-uri", "content-type", "content-length", "content-digest",
			"x-custom-header",
		},
		OnDeriveSigningString: func(ctx context.Context, stringToSign string) {
			slog.Debug("signing string", "string", stringToSign)
		},
	})

	headers := http.Header{
		"X-Custom-Header": []string{"CustomValue"},
	}
	existingTransport := client.Transport
	if existingTransport == nil {
		existingTransport = http.DefaultTransport
	}
	client.Transport = &headerRoundTripper{
		transport: existingTransport,
		header:    headers,
	}

	res, err := client.Post(addr, "application/json", nil)
	if err != nil {
		slog.Error("failed to send request", "error", err)
		os.Exit(1)
	}

	resBytes, err := httputil.DumpResponse(res, true)
	if err != nil {
		slog.Error("failed to dump response", "error", err)
		os.Exit(1)
	}

	fmt.Println(string(resBytes))
}