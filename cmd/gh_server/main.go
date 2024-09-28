package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/inmemory"
	"github.com/micahhausler/httpsig-scratch/hmac"
	"github.com/micahhausler/httpsig-scratch/multialgo"
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
	flag.Parse()
	addr := fmt.Sprintf("localhost:%d", *port)

	keyString := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----
`

	block, _ := pem.Decode([]byte(keyString))

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		slog.Error("failed to parse public key", "error", err)
		os.Exit(1)
	}
	ecKey := key.(*ecdsa.PublicKey)

	keyDir := multialgo.NewMultiAlgoAttributerDirectory(map[string]multialgo.AttributerAlgo{
		"alice": alg_ecdsa.P256{
			PublicKey: ecKey,
			Attrs: exampleAttributes{
				Username: "alice",
				UID:      "1234",
			},
		},
		"micah": hmac.NewHMACWithAttributes(
			// fake, generated from `head -c 32 /dev/urandom |base64`
			[]byte(`G+k5G/ECWBcga6MhEUDHyiFW7P3XsEdx66UQnVFqouc=`),
			exampleAttributes{
				Username: "micah",
				UID:      "5678",
			},
		),
	})

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
