package main

import (
	"crypto/aes"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/micahhausler/httpsig-scratch/attributes"
	"github.com/micahhausler/httpsig-scratch/cmd"
	"github.com/micahhausler/httpsig-scratch/session"
	"github.com/micahhausler/httpsig-scratch/session/block"
	"github.com/micahhausler/httpsig/server"
	"github.com/micahhausler/httpsig/sigconfig"
	flag "github.com/spf13/pflag"
)

func main() {
	port := flag.Int("port", 9091, "port to listen on")
	sessionTokenEncryptionKeyFile := flag.String("session-token-encryption-key", "", "path to session token encryption key")
	logLevel := cmd.LevelFlag(slog.LevelInfo)
	flag.Var(&logLevel, "log-level", "log level")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.Level(logLevel),
		AddSource: slog.Level(logLevel) == slog.LevelDebug,
	})))
	addr := fmt.Sprintf("localhost:%d", *port)

	aesKey, err := os.ReadFile(*sessionTokenEncryptionKeyFile)
	if err != nil {
		slog.Error("failed to read session token encryption key file", "error", err)
		os.Exit(1)
	}
	if len(aesKey) < 32 {
		slog.Error("session token encryption key is too short")
		os.Exit(1)
	}
	if len(aesKey) > 32 {
		slog.Warn("session token encryption key is too long, using first 32 bytes")
	}
	cipher, err := aes.NewCipher(aesKey[:32])
	if err != nil {
		slog.Error("failed to create AES cipher", "error", err)
		os.Exit(1)
	}
	sessionTokenEncrypterDecrypter := block.NewBlockSessionEncrypterDecrypter(cipher)

	// TODO: create a session token handler on an alternate port?
	// Just using an alternate unauthenticated path for now
	encService := session.NewEncryptionService(sessionTokenEncrypterDecrypter)

	// The decryption service is the key directory: it decrypts the session
	// token from the request's x-session-token header during key resolution,
	// so no separate token-decrypting middleware is needed.
	decService := session.NewDecryptionService(sessionTokenEncrypterDecrypter, "x-session-token")

	policy := sigconfig.VerifyPolicy{
		Coverage: sigconfig.Coverage{
			Components:    []string{`"@method"`, `"@target-uri"`, `"content-type"`, `"x-session-token"`},
			ContentDigest: sigconfig.DigestAlways,
		},
		Tag:       "foo",
		Scheme:    "http",
		Authority: addr,
		MaxAge:    sigconfig.Duration(15 * time.Minute),
		Tolerance: sigconfig.Duration(time.Minute),
	}

	mw, err := server.New(decService, policy, server.WithErrorHandler[attributes.User](
		func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("validation error", "error", err)
			w.WriteHeader(http.StatusUnauthorized)
		}))
	if err != nil {
		slog.Error("failed to create middleware", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle("/session-token", encService.SessionTokenHandler())
	mux.Handle("/hmac-credentials", encService.NewCredentialHandler())
	mux.Handle("/", mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := server.FromRequest[attributes.User](r)
		if !ok {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Signature verified, no identity found")
			slog.Info("no identity found")
			return
		}
		slog.Info("request", "username", v.Identity.Username)
		fmt.Fprintf(w, "hello, %s!", v.Identity.Username)
	})))

	slog.Info("starting server", "address", addr)
	err = http.ListenAndServe(addr, mux)
	if err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}
}
