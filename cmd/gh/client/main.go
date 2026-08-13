package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	"github.com/micahhausler/httpsig-scratch/cmd"
	"github.com/micahhausler/httpsig-scratch/gh"
	"github.com/micahhausler/httpsig-scratch/transport"
	"github.com/micahhausler/httpsig/client"
	"github.com/micahhausler/httpsig/sigconfig"
)

func main() {
	keyFile := flag.String("key", "", "path to private key")
	host := flag.String("host", "localhost", "host to connect to")
	port := flag.Int("port", 9091, "port to connect to")
	logLevel := cmd.LevelFlag(slog.LevelInfo)
	flag.Var(&logLevel, "log-level", "log level")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.Level(logLevel),
		AddSource: slog.Level(logLevel) == slog.LevelDebug,
	})))

	addr := fmt.Sprintf("http://%s:%d", *host, *port)

	keyData, err := os.ReadFile(*keyFile)
	if err != nil {
		slog.Error("failed to read key file", "error", err)
		os.Exit(1)
	}

	signer, err := gh.NewGHSigner(keyData)
	if err != nil {
		slog.Error("failed to create signer", "error", err)
		os.Exit(1)
	}

	profile := sigconfig.SigningProfile{
		Coverage: sigconfig.Coverage{
			Components: []string{
				`"@method"`,
				`"@target-uri"`,
				`"content-type"`,
			},
		},
		KeyID:      signer.KeyID(),
		Tag:        "foo",
		TTL:        sigconfig.Duration(5 * time.Minute),
		Nonce:      true,
		IncludeAlg: true,
	}
	rt, err := client.NewTransport(nil, signer, profile)
	if err != nil {
		slog.Error("failed to create signing transport", "error", err)
		os.Exit(1)
	}

	httpClient := &http.Client{
		Transport: transport.NewTransportWithFallbackHeaders(rt, http.Header{
			"Content-Type": []string{"application/json"},
		}),
	}

	{
		res, err := httpClient.Post(addr, "application/json", nil)
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
	{
		res, err := httpClient.Get(addr)
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

}
