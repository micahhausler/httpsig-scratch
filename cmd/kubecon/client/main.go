package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aoliveti/curling"
	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig-scratch/cmd"
	"github.com/micahhausler/httpsig-scratch/gh"
)

func main() {
	keyFile := flag.String("key", "", "path to private key")
	host := flag.String("host", "localhost", "host to connect to")
	port := flag.Int("port", 8080, "port to connect to")
	username := flag.String("username", "", "GitHub username to connect as")
	logLevel := cmd.LevelFlag(slog.LevelInfo)
	flag.Var(&logLevel, "log-level", "log level")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.Level(logLevel),
		AddSource: slog.Level(logLevel) == slog.LevelDebug,
	})))

	addr := fmt.Sprintf("http://%s:%d", *host, *port)

	keyData, err := os.ReadFile(*keyFile)
	if err != nil {
		slog.Error("failed to read key file", "error", err)
		os.Exit(1)
	}

	signer, err := gh.NewGHSigner(keyData)
	if err != nil {
		slog.Error("failed to create signer", "error", err)
		os.Exit(1)
	}

	req, err := http.NewRequest(http.MethodPost, addr, nil)
	if err != nil {
		slog.Error("Failed to create request", "error", err.Error())
		os.Exit(1)
	}
	req.Header.Add("X-GitHub-Username", *username)
	req.Header.Add("Content-Type", "application/json")

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		slog.Error("Failed to generate nonce", "error", err.Error())
		os.Exit(1)
	}

	err = httpsig.Sign(req, signer, httpsig.SignOptions{
		Components: []httpsig.Component{
			{Name: "@method"},
			{Name: "@target-uri"},
			{Name: "content-type"},
			{Name: "x-github-username"},
		},
		KeyID:      signer.KeyID(),
		Tag:        "foo",
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		Expires:    time.Now().Add(5 * time.Minute),
		IncludeAlg: true,
	})
	if err != nil {
		slog.Error("Failed to sign request", "error", err.Error())
		os.Exit(1)
	}

	command, err := curling.NewFromRequest(req)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(command)

}
