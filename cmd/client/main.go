package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"

	"fmt"
	"log/slog"
	"net/http/httputil"
	"os"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/signer"
	"github.com/micahhausler/httpsig-scratch/hmac"
	rsaAlgo "github.com/micahhausler/httpsig-scratch/rsa"
	flag "github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
)

func main() {
	kid := flag.String("key-id", "alice", "key id to use. Use `alice` (ecdsa), `bob` (hmac), or `eve` (rsa)")
	keyPath := flag.String("key", "", "path to SSH private key (ecdsa for alice, rsa for eve)")
	host := flag.String("host", "localhost", "host to connect to")
	port := flag.Int("port", 9091, "port to connect to")
	flag.Parse()
	addr := fmt.Sprintf("http://%s:%d", *host, *port)

	var algorithm signer.Algorithm

	switch *kid {
	case "alice":
		data, err := os.ReadFile(*keyPath)
		if err != nil {
			slog.Error("failed to read private key file", "error", err, "path", *keyPath)
			os.Exit(1)
		}
		kp, err := ssh.ParseRawPrivateKey(data)
		if err != nil {
			slog.Error("failed to parse ssh private key", "error", err)
			os.Exit(1)
		}
		key, ok := kp.(*ecdsa.PrivateKey)
		if !ok {
			slog.Error("not an ecdsa private key")
			os.Exit(1)
		}
		slog.Info("Using ecdsa P256 signer", "key-id", "alice")
		algorithm = alg_ecdsa.NewP256Signer(key)
	case "bob":
		// fake, generated from `head -c 32 /dev/urandom |base64`
		slog.Info("Using HMAC SHA-256 signer", "key-id", "bob")
		algorithm = hmac.NewHMAC([]byte(`G+k5G/ECWBcga6MhEUDHyiFW7P3XsEdx66UQnVFqouc=`))
	case "eve":
		data, err := os.ReadFile(*keyPath)
		if err != nil {
			slog.Error("failed to read private key file", "error", err, "path", *keyPath)
			os.Exit(1)
		}
		kp, err := ssh.ParseRawPrivateKey(data)
		if err != nil {
			slog.Error("failed to parse ssh private key", "error", err)
			os.Exit(1)
		}
		_, ok := kp.(*rsa.PrivateKey)
		if !ok {
			slog.Error("not an ecdsa private key")
			os.Exit(1)
		}
		slog.Info("Using ecdsa P256 signer", "key-id", "eve")
		algorithm = rsaAlgo.NewRSAPSS512Signer(kp.(*rsa.PrivateKey))
	default:
		slog.Error("unsupported key id", "kid", *kid)
		os.Exit(1)
	}

	client := httpsig.NewClient(httpsig.ClientOpts{
		KeyID: *kid,
		Tag:   "foo",
		Alg:   algorithm,
		OnDeriveSigningString: func(ctx context.Context, stringToSign string) {
			slog.Debug("signing string", "string", stringToSign)
		},
	})

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
