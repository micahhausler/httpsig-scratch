package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/micahhausler/httpsig-scratch/cmd"
	"github.com/micahhausler/httpsig-scratch/tpm"
	fallback "github.com/micahhausler/httpsig-scratch/transport"
	"github.com/micahhausler/httpsig/client"
	"github.com/micahhausler/httpsig/sigconfig"
)

func main() {
	tpmPath := flag.String("tpm-path", "", "path to a TPM device, like /dev/tpmrm0. Empty runs an embedded software TPM")
	host := flag.String("host", "localhost", "host to connect to")
	port := flag.Int("port", 9092, "port to connect to")
	username := flag.String("username", "dave", "username to enroll as")
	logLevel := cmd.LevelFlag(slog.LevelInfo)
	flag.Var(&logLevel, "log-level", "log level")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.Level(logLevel),
		AddSource: slog.Level(logLevel) == slog.LevelDebug,
	})))

	addr := fmt.Sprintf("http://%s:%d", *host, *port)

	var (
		device transport.TPMCloser
		err    error
	)
	if *tpmPath != "" {
		slog.Info("using TPM device", "path", *tpmPath)
		device, err = linuxtpm.Open(*tpmPath)
	} else {
		slog.Info("using embedded software TPM")
		device, err = simulator.OpenSimulator()
	}
	if err != nil {
		slog.Error("failed to open TPM", "error", err)
		os.Exit(1)
	}
	defer device.Close()

	signer, enrollment, err := tpm.CreateAttestedKey(device, *username)
	if err != nil {
		slog.Error("failed to create attested key", "error", err)
		os.Exit(1)
	}
	slog.Info("created TPM signing key", "key_id", signer.KeyID())

	// enroll the attested key with the server
	buf := &bytes.Buffer{}
	json.NewEncoder(buf).Encode(enrollment)
	enrollResp, err := http.Post(addr+"/enroll", "application/json", buf)
	if err != nil {
		slog.Error("failed to enroll key", "error", err)
		os.Exit(1)
	}
	resp := &tpm.EnrollmentResponse{}
	err = json.NewDecoder(enrollResp.Body).Decode(resp)
	enrollResp.Body.Close()
	if err != nil {
		slog.Error("failed to decode enrollment response", "error", err)
		os.Exit(1)
	}
	if resp.Error != "" {
		slog.Error("enrollment rejected", "error", resp.Error)
		os.Exit(1)
	}
	slog.Info("enrolled key with server", "key_id", resp.KeyID)

	profile := sigconfig.SigningProfile{
		Coverage: sigconfig.Coverage{
			Components: []string{`"@method"`, `"@target-uri"`, `"content-type"`},
		},
		KeyID:      signer.KeyID(),
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
	httpClient := &http.Client{
		Transport: fallback.NewTransportWithFallbackHeaders(rt, http.Header{
			"Content-Type": []string{"application/json"},
		}),
	}

	{
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
	}
	{
		res, err := httpClient.Get(addr)
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
}
