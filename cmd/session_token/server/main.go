package main

import (
	"context"
	"crypto/aes"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/inmemory"
	"github.com/common-fate/httpsig/sigparams"
	"github.com/common-fate/httpsig/verifier"
	"github.com/micahhausler/httpsig-scratch/cmd"
	"github.com/micahhausler/httpsig-scratch/session"
	"github.com/micahhausler/httpsig-scratch/session/block"
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

	var keyDir verifier.KeyDirectory
	decService := session.NewDecryptionService(sessionTokenEncrypterDecrypter, "x-session-token")
	keyDir = decService

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
		Validation: &sigparams.ValidateOpts{
			ForbidClientSideAlg: false,
			BeforeDuration:      time.Minute * 5,
			AfterDuration:       time.Minute * 15,
			RequiredCoveredComponents: map[string]bool{
				"@method":         true,
				"@target-uri":     true,
				"content-type":    true,
				"content-length":  true,
				"content-digest":  true,
				"x-session-token": true,
			},
		},

		OnDeriveSigningString: func(ctx context.Context, stringToSign string) {
			slog.Debug("string to sign", "string", stringToSign)
		},
	})

	sessionTokenDecryptingMiddleware := decService.GetSessionTokenDecryptingMiddleware()

	mux.Handle("/session-token", encService.SessionTokenHandler())
	mux.Handle("/hmac-credentials", encService.NewCredentialHandler())
	mux.Handle("/",
		sessionTokenDecryptingMiddleware(
			verifier(
				http.Handler(
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						rawAttribute := httpsig.AttributesFromContext(r.Context())
						if rawAttribute == nil {
							w.WriteHeader(http.StatusOK)
							fmt.Fprintf(w, "Signature verified, no attributes found")
							slog.Info("no attributes found")
							return
						}

						attr, ok := rawAttribute.(map[string]interface{})
						if !ok {
							w.WriteHeader(http.StatusOK)
							fmt.Fprintf(w, "Signature verified, but attributes are not of type session.User")
							slog.Error("Attributes are not of type session.User",
								"type", fmt.Sprintf("%T", rawAttribute),
								"attributes", rawAttribute,
							)
							return
						}
						slog.Info("request", "username", attr["username"])
						fmt.Fprintf(w, "hello, %s!", attr["username"])
					})),
			)),
	)

	slog.Info("starting server", "address", addr)
	err = http.ListenAndServe(addr, mux)
	if err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}
}
