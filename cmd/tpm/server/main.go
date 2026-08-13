package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/micahhausler/httpsig-scratch/cmd"
	"github.com/micahhausler/httpsig-scratch/tpm"
	"github.com/micahhausler/httpsig-scratch/tpm/ec2ek"
	"github.com/micahhausler/httpsig/server"
	"github.com/micahhausler/httpsig/sigconfig"
	flag "github.com/spf13/pflag"
)

func main() {
	port := flag.Int("port", 9092, "port to listen on")
	ekTrust := flag.String("ek-trust", tpm.SourcePinned,
		fmt.Sprintf("how to decide which TPMs to trust: %q, %q, or %q",
			tpm.SourcePinned, tpm.SourceEC2, tpm.SourceTOFU))
	ekFile := flag.String("ek-file", "", "path to a JSON list of trusted endorsement keys, for --ek-trust=pinned")
	logLevel := cmd.LevelFlag(slog.LevelInfo)
	flag.Var(&logLevel, "log-level", "log level")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.Level(logLevel),
		AddSource: slog.Level(logLevel) == slog.LevelDebug,
	})))

	addr := fmt.Sprintf("localhost:%d", *port)

	trust, err := newTrust(context.Background(), *ekTrust, *ekFile)
	if err != nil {
		slog.Error("failed to configure endorsement key trust", "error", err, "ek-trust", *ekTrust)
		os.Exit(1)
	}
	keyDir := tpm.NewDirectory(trust)

	policy := sigconfig.VerifyPolicy{
		Coverage: sigconfig.Coverage{
			Components: []string{`"@method"`, `"@target-uri"`, `"content-type"`},
		},
		Tag:       "foo",
		Scheme:    "http",
		Authority: addr,
	}

	mw, err := server.New(keyDir, policy, server.WithErrorHandler[tpm.Identity](
		func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("validation error", "error", err)
			w.WriteHeader(http.StatusUnauthorized)
		}))
	if err != nil {
		slog.Error("failed to create middleware", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle("/enroll/challenge", keyDir.ChallengeHandler())
	mux.Handle("/enroll", keyDir.EnrollHandler())
	mux.Handle("/", mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := server.FromRequest[tpm.Identity](r)
		if !ok {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Signature verified, no identity found")
			slog.Info("no identity found")
			return
		}
		defer slog.Info("request",
			"identity", v.Identity.Label,
			"source", v.Identity.Source,
			"key_id", v.Signature.KeyID())
		fmt.Fprintf(w, "hello, %s! (signed by TPM key %s..., trusted via %s)",
			v.Identity.Label, v.Signature.KeyID()[:16], v.Identity.Source)
	})))

	slog.Info("starting server", "address", addr, "ek-trust", *ekTrust)
	err = http.ListenAndServe(addr, mux)
	if err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}
}

func newTrust(ctx context.Context, mode, ekFile string) (tpm.EKTrust, error) {
	switch mode {
	case tpm.SourcePinned:
		if ekFile == "" {
			return nil, fmt.Errorf("--ek-file is required for --ek-trust=%s", tpm.SourcePinned)
		}
		return tpm.LoadPinnedTrust(ekFile)
	case tpm.SourceEC2:
		return ec2ek.New(ctx)
	case tpm.SourceTOFU:
		slog.Warn("accepting any endorsement key, including a software TPM's; for local testing only")
		return tpm.TOFUTrust{}, nil
	default:
		return nil, fmt.Errorf("unknown trust mode %q", mode)
	}
}
