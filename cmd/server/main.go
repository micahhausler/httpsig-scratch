package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/inmemory"
	"github.com/micahhausler/httpsig-scratch/gh"
	"github.com/micahhausler/httpsig-scratch/hmac"
	"github.com/micahhausler/httpsig-scratch/multialgo"
	rsaAlgo "github.com/micahhausler/httpsig-scratch/rsa"
	flag "github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
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
	ecdsaKeyFile := flag.String("ecdsa-pubkey", "", "path to ecdsa public key")
	rsaKeyFile := flag.String("rsa-pubkey", "", "path to rsa public key")
	flag.Parse()
	addr := fmt.Sprintf("localhost:%d", *port)

	ecdsaData, err := os.ReadFile(*ecdsaKeyFile)
	if err != nil {
		slog.Error("failed to read public key file", "error", err)
		os.Exit(1)
	}
	sshEPub, _, _, _, err := ssh.ParseAuthorizedKey(ecdsaData)
	if err != nil {
		slog.Error("failed to parse public key", "error", err)
		os.Exit(1)
	}
	ePub, err := gh.ConvertSSHPublicKeyToECDSAPublicKey(sshEPub)
	if err != nil {
		slog.Error("failed to convert SSH pub key file", "error", err)
		os.Exit(1)
	}

	keyMap := map[string]multialgo.AttributerAlgo{
		"alice": alg_ecdsa.P256{
			PublicKey: ePub,
			Attrs: exampleAttributes{
				Username: "alice",
				UID:      "1234",
			},
		},
		"bob": hmac.NewHMACWithAttributes(
			// fake, generated from `head -c 32 /dev/urandom |base64`
			[]byte(`G+k5G/ECWBcga6MhEUDHyiFW7P3XsEdx66UQnVFqouc=`),
			exampleAttributes{
				Username: "bob",
				UID:      "5678",
			},
		),
	}

	if *rsaKeyFile != "" {
		rsaData, err := os.ReadFile(*rsaKeyFile)
		if err != nil {
			slog.Error("failed to read public key file", "error", err)
			os.Exit(1)
		}
		sshRsaPub, _, _, _, err := ssh.ParseAuthorizedKey(rsaData)
		if err != nil {
			slog.Error("failed to parse public key", "error", err)
			os.Exit(1)
		}
		rsaPub, err := gh.ConvertSSHPublicKeyToRSAPublicKey(sshRsaPub)
		if err != nil {
			slog.Error("failed to convert SSH pub key file", "error", err)
			os.Exit(1)
		}
		keyMap["eve"] = rsaAlgo.RSAPSS512{PublicKey: rsaPub, Attrs: exampleAttributes{
			Username: "eve",
			UID:      "911",
		}}
	}

	keyDir := multialgo.NewMultiAlgoAttributerDirectory(keyMap)

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
