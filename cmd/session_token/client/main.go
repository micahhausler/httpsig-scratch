package main

import (
	"bytes"
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
	"time"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig-scratch/attributes"
	"github.com/micahhausler/httpsig-scratch/cmd"
	"github.com/micahhausler/httpsig-scratch/session"
	"github.com/micahhausler/httpsig-scratch/transport"
	"github.com/micahhausler/httpsig/client"
	"github.com/micahhausler/httpsig/sigconfig"
	flag "github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
)

func main() {
	keyAlgo := flag.String("key-algo", "", "key algo to use. Use either `ecdsa-p256-sha256`, `hmac-sha256`, or `rsa-pss-sha512`")
	keyPath := flag.String("key", "", "path to signing key. Only used for public keys")
	host := flag.String("host", "localhost", "host to connect to")
	port := flag.Int("port", 9091, "port to connect to")
	logLevel := cmd.LevelFlag(slog.LevelInfo)
	flag.Var(&logLevel, "log-level", "log level")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.Level(logLevel),
		AddSource: slog.Level(logLevel) == slog.LevelDebug,
	})))
	addr := fmt.Sprintf("http://%s:%d", *host, *port)

	var (
		alg          httpsig.Algorithm = httpsig.Algorithm(*keyAlgo)
		signer       httpsig.Signer
		username     string
		keyBytes     []byte
		keyID        string = "kid-123" // everyone uses the same keyID here, use different ids in real life
		sessionToken string
		err          error
	)
	switch alg {
	case httpsig.ECDSAP256SHA256:
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
		signer, err = httpsig.NewSigner(alg, key)
		if err != nil {
			slog.Error("failed to create signer", "error", err)
			os.Exit(1)
		}
		derBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			slog.Error("failed to marshal public key", "error", err)
			os.Exit(1)
		}
		keyBytes = pem.EncodeToMemory(&pem.Block{Type: "ECDSA PUBLIC KEY", Bytes: derBytes})
		username = "alice"
		slog.Info("Using ecdsa P256 signer", "key-algo", *keyAlgo, "username", username)
	case httpsig.HMACSHA256:
		username = "bob"
		// For HMAC creds, we ask the server for a key and keyid
		credRequest := &session.CredentialRequest{UserInfo: attributes.User{Username: username}}
		slog.Info("Getting HMAC credentials", "request", credRequest)
		buf := &bytes.Buffer{}
		json.NewEncoder(buf).Encode(credRequest)
		sessionTokenResp, err := http.Post(addr+"/hmac-credentials", "application/json", buf)
		if err != nil {
			slog.Error("failed to get credentials", "error", err)
			os.Exit(1)
		}
		resp := &session.CredentialResponse{}
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

		keyID = resp.KeyID
		keyBytes = []byte(resp.SecretKey)
		sessionToken = string(resp.SessionToken)
		signer, err = httpsig.NewSigner(alg, keyBytes)
		if err != nil {
			slog.Error("failed to create signer", "error", err)
			os.Exit(1)
		}

		slog.Info("Using HMAC SHA-256 signer", "key-algo", *keyAlgo, "username", username)
	case httpsig.RSAPSSSHA512:
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
		signer, err = httpsig.NewSigner(alg, key)
		if err != nil {
			slog.Error("failed to create signer", "error", err)
			os.Exit(1)
		}

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

	// For non HMAC keys, we need to get a session token from the server
	// by registering the public key
	if alg != httpsig.HMACSHA256 {
		encRequest := &session.EncryptionRequest{
			KeyID:     keyID,
			Alg:       string(alg),
			PublicKey: string(keyBytes),
			UserInfo: attributes.User{
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
		sessionToken = string(resp.SessionToken)
	}

	profile := sigconfig.SigningProfile{
		Coverage: sigconfig.Coverage{
			Components: []string{
				`"@method"`,
				`"@target-uri"`,
				`"content-type"`,
				`"x-session-token"`,
			},
			ContentDigest: sigconfig.DigestAlways,
		},
		KeyID:      keyID,
		Tag:        "foo",
		TTL:        sigconfig.Duration(5 * time.Minute),
		Nonce:      true,
		IncludeAlg: true,
	}
	rt, err := client.NewTransport(nil, signer, profile)
	if err != nil {
		slog.Error("failed to create signing transport", "error", err)
		os.Exit(1)
	}

	// fallback headers are added before signing so they are covered
	httpClient := &http.Client{
		Transport: transport.NewTransportWithFallbackHeaders(rt, http.Header{
			"Content-Type":    []string{"application/json"},
			"X-Session-Token": []string{sessionToken},
		}),
	}

	res, err := httpClient.Post(addr, "application/json", nil)
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
