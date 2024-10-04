package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/alg_hmac"
	"github.com/common-fate/httpsig/alg_rsa"
	"github.com/common-fate/httpsig/signer"
	"github.com/micahhausler/httpsig-scratch/session"
	flag "github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
)

func init() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		// AddSource: true,
	}))
	slog.SetDefault(logger)
}

type headerRoundTripper struct {
	transport http.RoundTripper
	header    http.Header
}

func (h *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for key, values := range h.header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	return h.transport.RoundTrip(req)
}

func main() {
	keyAlgo := flag.String("key-algo", "", "key algo to use. Use either `ecdsa-p256-sha256`, `hmac-sha256`, or `rsa-pss-sha512`")
	keyPath := flag.String("key", "", "path to signing key")
	host := flag.String("host", "localhost", "host to connect to")
	port := flag.Int("port", 9091, "port to connect to")
	flag.Parse()
	addr := fmt.Sprintf("http://%s:%d", *host, *port)

	var (
		algorithm signer.Algorithm
		username  string
		keyBytes  []byte
	)
	switch *keyAlgo {
	case "ecdsa-p256-sha256":
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
		algorithm = alg_ecdsa.NewP256Signer(key)
		derBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			slog.Error("failed to marshal public key", "error", err)
			os.Exit(1)
		}
		keyBytes = pem.EncodeToMemory(&pem.Block{Type: "ECDSA PUBLIC KEY", Bytes: derBytes})
		username = "alice"
		slog.Info("Using ecdsa P384 signer", "key-algo", *keyAlgo, "username", username)
	case "hmac-sha256":
		var err error
		keyBytes, err = os.ReadFile(*keyPath)
		if err != nil {
			slog.Error("failed to read private key file", "error", err, "path", *keyPath)
			os.Exit(1)
		}
		algorithm = alg_hmac.NewHMAC(keyBytes)
		username = "bob"
		slog.Info("Using HMAC SHA-256 signer", "key-algo", *keyAlgo, "username", username)
	case "rsa-pss-sha512":
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
		key, ok := kp.(*rsa.PrivateKey)
		if !ok {
			slog.Error("not an rsa private key")
			os.Exit(1)
		}
		algorithm = alg_rsa.NewRSAPSS512Signer(key)

		derBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			slog.Error("failed to marshal public key", "error", err)
			os.Exit(1)
		}
		keyBytes = pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: derBytes})
		username = "charlie"
		slog.Info("Using RSAPSS512 signer", "key-algo", *keyAlgo, "username", username)
	default:
		slog.Error("unsupported key algo", "key-algo", *keyAlgo)
		os.Exit(1)
	}

	encRequest := &session.EncryptionRequest{
		KeyID:     "kid-123", // everyone uses the same keyID here, use different ids in real life
		Alg:       algorithm.Type(),
		PublicKey: string(keyBytes),
		UserInfo: session.User{
			Username: username,
		},
	}
	buf := &bytes.Buffer{}

	slog.Info("Creating session token for key", "request", encRequest)
	// ignore encoding err for now
	json.NewEncoder(buf).Encode(encRequest)
	sessionTokenResp, err := http.Post(addr+"/session-token", "application/json", buf)
	if err != nil {
		slog.Error("failed to get session token", "error", err)
		os.Exit(1)
	}
	resp := &session.EncryptionResponse{}
	err = json.NewDecoder(sessionTokenResp.Body).Decode(resp)
	if err != nil {
		slog.Error("failed to decode response", "error", err)
		os.Exit(1)
	}
	sessionTokenResp.Body.Close()
	if resp.Error != "" {
		slog.Error("error getting session token", "error", resp.Error)
		os.Exit(1)
	}
	slog.Info("Got encrypted session token from server")

	client := httpsig.NewClient(httpsig.ClientOpts{
		KeyID: "kid-123", // everyone uses the same keyID here, use different ids in real life
		Tag:   "foo",
		Alg:   algorithm,
		CoveredComponents: []string{
			"@method", "@target-uri", "content-type", "content-length", "content-digest", "x-session-token",
		},
		OnDeriveSigningString: func(ctx context.Context, stringToSign string) {
			slog.Debug("signing string", "string", stringToSign)
		},
	})

	headers := http.Header{
		"x-session-token": []string{string(resp.SessionToken)},
	}
	existingTransport := client.Transport
	if existingTransport == nil {
		existingTransport = http.DefaultTransport
	}
	client.Transport = &headerRoundTripper{
		transport: existingTransport,
		header:    headers,
	}

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
	fmt.Println()
}
