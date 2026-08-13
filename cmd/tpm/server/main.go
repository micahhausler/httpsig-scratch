package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/micahhausler/httpsig-scratch/attributes"
	"github.com/micahhausler/httpsig-scratch/cmd"
	"github.com/micahhausler/httpsig-scratch/tpm"
	"github.com/micahhausler/httpsig/server"
	"github.com/micahhausler/httpsig/sigconfig"
	flag "github.com/spf13/pflag"
)

func main() {
	port := flag.Int("port", 9092, "port to listen on")
	logLevel := cmd.LevelFlag(slog.LevelInfo)
	flag.Var(&logLevel, "log-level", "log level")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.Level(logLevel),
		AddSource: slog.Level(logLevel) == slog.LevelDebug,
	})))

	addr := fmt.Sprintf("localhost:%d", *port)

	keyDir := tpm.NewDirectory()

	policy := sigconfig.VerifyPolicy{
		Coverage: sigconfig.Coverage{
			Components: []string{`"@method"`, `"@target-uri"`, `"content-type"`},
		},
		Tag:       "foo",
		Scheme:    "http",
		Authority: addr,
	}

	mw, err := server.New(keyDir, policy, server.WithErrorHandler[attributes.User](
		func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("validation error", "error", err)
			w.WriteHeader(http.StatusUnauthorized)
		}))
	if err != nil {
		slog.Error("failed to create middleware", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle("/enroll", keyDir.EnrollHandler())
	mux.Handle("/", mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := server.FromRequest[attributes.User](r)
		if !ok {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Signature verified, no identity found")
			slog.Info("no identity found")
			return
		}
		defer slog.Info("request", "username", v.Identity.Username, "key_id", v.Signature.KeyID())
		fmt.Fprintf(w, "hello, %s! (signed by TPM key %s...)", v.Identity.Username, v.Signature.KeyID()[:16])
	})))

	slog.Info("starting server", "address", addr)
	err = http.ListenAndServe(addr, mux)
	if err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}
}
