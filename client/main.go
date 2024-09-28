package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net/http/httputil"
	"os"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/signer"
	"github.com/micahhausler/httpsig-scratch/hmac"
)

func main() {
	alg := flag.String("alg", "ecdsa-p256", "algorithm to use. Must be `ecdsa-p256` or `hmac-sha256`")
	kid := flag.String("kid", "alice", "key id to use")
	// fake, generated from `head -c 32 /dev/urandom |base64`
	secret := flag.String("secret", `G+k5G/ECWBcga6MhEUDHyiFW7P3XsEdx66UQnVFqouc=`, "secret to use")
	host := flag.String("host", "localhost", "host to connect to")
	port := flag.Int("port", 9091, "port to connect to")
	flag.Parse()
	addr := fmt.Sprintf("http://%s:%d", *host, *port)

	var algorithm signer.Algorithm

	switch *alg {
	case "ecdsa-p256":
		// fake test key only
		keyString := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END EC PRIVATE KEY-----
`

		block, _ := pem.Decode([]byte(keyString))

		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			slog.Error("failed to parse private key", "error", err)
			os.Exit(1)
		}
		algorithm = alg_ecdsa.NewP256Signer(key)
	case "hmac-sha256":
		algorithm = hmac.NewHMAC([]byte(*secret))
	default:
		slog.Error("unsupported algorithm", "algorithm", *alg)
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
