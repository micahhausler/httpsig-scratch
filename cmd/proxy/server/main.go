package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/inmemory"
	"github.com/common-fate/httpsig/sigset"
	"github.com/micahhausler/httpsig-scratch/attributes"
	"github.com/micahhausler/httpsig-scratch/gh"
	flag "github.com/spf13/pflag"
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
	backend := flag.String("backend", "http://127.0.0.1:9999", "backend URL to proxy to")
	serverCert := flag.String("server-cert", "mount/server-cert.pem", "path to server certificate")
	serverKey := flag.String("server-key", "mount/server-key.pem", "path to server key")
	clientCert := flag.String("client-cert", "mount/client.pem", "path to client certificate to connect to backed")
	clientKey := flag.String("client-key", "mount/client.key", "path to client key to connect to backend")
	usernames := flag.StringSlice("usernames", []string{"micahhausler"}, "usernames to allow")

	flag.Parse()

	addr := fmt.Sprintf("127.0.0.1:%d", *port)

	proxyURL, err := url.Parse(*backend)
	if err != nil {
		slog.Error("failed to parse backend URL", "error", err)
		os.Exit(1)
	}

	fileNames := []string{*serverCert, *serverKey, *clientCert, *clientKey}
	for _, fileName := range fileNames {
		if _, err := os.Stat(fileName); err != nil {
			slog.Error("file does not exist", "file", fileName)
			os.Exit(1)
		}
	}

	clientCertPair, err := tls.LoadX509KeyPair(*clientCert, *clientKey)
	if err != nil {
		slog.Error("failed to load client key pair", "error", err)
		os.Exit(1)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCertPair}, // Client cert
		// Demo only, to connect to the K8s API
		// TODO: load k8s API TLS cert
		InsecureSkipVerify: true,
	}
	proxy := httputil.NewSingleHostReverseProxy(proxyURL)
	proxy.Transport = &http.Transport{TLSClientConfig: tlsConfig}

	keyDir, err := gh.NewGitHubKeyDirectory(*usernames)
	if err != nil {
		slog.Error("failed to create key directory", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	verifier := httpsig.Middleware(httpsig.MiddlewareOpts{
		NonceStorage: inmemory.NewNonceStorage(),
		KeyDirectory: keyDir,
		Tag:          "foo",
		Scheme:       "https",
		Authority:    addr,
		OnValidationError: func(ctx context.Context, err error) {
			slog.Error("validation error", "error", err)
		},
		OnDeriveSigningString: func(ctx context.Context, stringToSign string) {
			slog.Debug("string to sign", "string", stringToSign)
		},
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Handling request", "client", r.RemoteAddr, "url", r.URL.String(), "headers", r.Header)

		// TODO: strip any "X-Remote-" headers
		// If the request doesn't have a signature, don't validate it and just proxy it
		if _, err := sigset.Unmarshal(r); err != nil {
			slog.Info("no signature found, proxying request", "client", r.RemoteAddr, "url", r.URL)
			proxy.ServeHTTP(w, r)
			return
		}

		handler := verifier(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawAttribute := httpsig.AttributesFromContext(r.Context())
			if rawAttribute == nil {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, "Signature verified, no attributes found")
				defer slog.Info("no attributes found")
				return
			}

			attr, ok := rawAttribute.(attributes.User)
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, "Signature verified, but no username found")
				defer slog.Error("Attributes are not of type user")
				return
			}
			r.Header.Set("X-Remote-User", attr.Username)
			r.Header.Set("X-Remote-Group", `github:users`)
			slog.Debug("Proxying request", "client", r.RemoteAddr, "url", r.URL.String(), "headers", r.Header, "username", attr.Username)
			proxy.ServeHTTP(w, r)
		}))
		handler.ServeHTTP(w, r)
	})

	slog.Info("starting server", "address", addr)
	err = http.ListenAndServeTLS(addr, *serverCert, *serverKey, mux)
	if err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}
}
