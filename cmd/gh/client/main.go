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
	"github.com/micahhausler/httpsig-scratch/cmd"
	"github.com/micahhausler/httpsig-scratch/gh"
	"github.com/micahhausler/httpsig-scratch/transport"
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

	algorithm, err := gh.NewGHSigner(keyData)
	if err != nil {
		slog.Error("failed to create signer", "error", err)
		os.Exit(1)
	}

	client := httpsig.NewClient(httpsig.ClientOpts{
		KeyID: algorithm.KeyID(),
		Tag:   "foo",
		Alg:   algorithm,
		OnDeriveSigningString: func(ctx context.Context, stringToSign string) {
			slog.Debug("signing string", "string", stringToSign)
		},
	})

	client.Transport = transport.NewTransportWithFallbackHeaders(client.Transport, http.Header{
		"Content-Type": []string{"application/json"},
	})

	{
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
	{
		res, err := client.Get(addr)
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
