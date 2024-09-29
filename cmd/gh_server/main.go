package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/inmemory"
	"github.com/micahhausler/httpsig-scratch/gh"
	flag "github.com/spf13/pflag"
)

func init() {
	jsonLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	}))
	slog.SetDefault(jsonLogger)
}

func main() {
	port := flag.Int("port", 9091, "port to listen on")
	usernames := flag.StringSlice("usernames", []string{"micahhausler"}, "usernames to allow")
	flag.Parse()
	addr := fmt.Sprintf("localhost:%d", *port)

	keyDir, err := gh.NewGitHubKeyDirectory(*usernames)
	if err != nil {
		slog.Error("failed to create key directory", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()

	verifier := httpsig.Middleware(httpsig.MiddlewareOpts{
		NonceStorage: inmemory.NewNonceStorage(),
		KeyDirectory: keyDir,
		Tag:          "foo",
		Scheme:       "http",
		Authority:    addr,
		OnValidationError: func(ctx context.Context, err error) {
			slog.Error("validation error", "error", err)
		},

		OnDeriveSigningString: func(ctx context.Context, stringToSign string) {
			slog.Debug("string to sign", "string", stringToSign)
		},
	})

	mux.Handle("/", verifier(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawAttribute := httpsig.AttributesFromContext(r.Context())
		if rawAttribute == nil {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Signature verified, no attributes found")
			defer slog.Info("no attributes found")
			return
		}

		attr, ok := rawAttribute.(exampleAttributes)
		if !ok {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Signature verified, but attributes are not of type exampleAttributes")
			defer slog.Error("Attributes are not of type exampleAttributes")
			return
		}
		defer slog.Info("request", "username", attr.Username)
		fmt.Fprintf(w, "hello, %s!", attr.Username)
	})))

	slog.Info("starting server", "address", addr)
	err = http.ListenAndServe(addr, mux)
	if err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}
}

type exampleAttributes struct {
	Username string
	UID      string
}
