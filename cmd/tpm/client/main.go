package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

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
	claim := flag.String("claim", "", "which machine this is, such as an EC2 instance ID. Read from IMDS when empty")
	printEK := flag.Bool("print-ek", false, "print this TPM's endorsement key as a pin file for the server's --ek-file, then exit")
	logLevel := cmd.LevelFlag(slog.LevelInfo)
	flag.Var(&logLevel, "log-level", "log level")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level:     slog.Level(logLevel),
		AddSource: slog.Level(logLevel) == slog.LevelDebug,
	})))

	addr := fmt.Sprintf("http://%s:%d", *host, *port)

	if *tpmPath != "" {
		slog.Info("using TPM device", "path", *tpmPath)
	} else if simulatorSupported {
		slog.Info("using embedded software TPM")
	}
	device, err := openTPM(*tpmPath)
	if err != nil {
		slog.Error("failed to open TPM", "error", err)
		os.Exit(1)
	}
	defer device.Close()

	if *claim == "" {
		if id, err := instanceID(); err == nil {
			*claim = id
			slog.Info("read instance ID from IMDS", "claim", *claim)
		} else {
			slog.Debug("no instance ID from IMDS", "error", err)
		}
	}

	// The endorsement and attestation keys stay loaded across both rounds of
	// the enrollment.
	enroller, err := tpm.NewEnroller(device)
	if err != nil {
		slog.Error("failed to create TPM keys", "error", err)
		os.Exit(1)
	}
	defer enroller.Close()

	// Pinning is how a machine that is not an EC2 instance gets an identity:
	// its operator publishes this out of band and the server reads it back.
	if *printEK {
		label := *claim
		if label == "" {
			if h, err := os.Hostname(); err == nil {
				label = h
			} else {
				label = "this-machine"
			}
		}
		out, err := json.MarshalIndent([]tpm.PinnedKey{{
			Label:    label,
			EKPublic: base64.StdEncoding.EncodeToString(enroller.Challenge("").EKPublic),
		}}, "", "  ")
		if err != nil {
			slog.Error("failed to encode the endorsement key", "error", err)
			os.Exit(1)
		}
		fmt.Println(string(out))
		return
	}

	// Round one: the server decides whether it trusts this TPM, and answers
	// with a secret only this TPM can recover.
	challenge := &tpm.ChallengeResponse{}
	if err := post(addr+"/enroll/challenge", enroller.Challenge(*claim), challenge); err != nil {
		slog.Error("failed to request a challenge", "error", err)
		os.Exit(1)
	}
	if challenge.Error != "" {
		slog.Error("server refused to issue a challenge", "error", challenge.Error)
		os.Exit(1)
	}

	secret, err := enroller.Activate(challenge)
	if err != nil {
		slog.Error("failed to activate the credential", "error", err)
		os.Exit(1)
	}
	slog.Info("recovered the activation secret, proving this TPM holds the endorsement key")

	// Round two: create the signing key and certify it against the nonce the
	// server just issued.
	signer, enrollReq, err := enroller.CreateSigningKey(challenge.Nonce)
	if err != nil {
		slog.Error("failed to create the signing key", "error", err)
		os.Exit(1)
	}
	enrollReq.ChallengeID = challenge.ChallengeID
	enrollReq.Secret = secret

	enrolled := &tpm.EnrollResponse{}
	if err := post(addr+"/enroll", enrollReq, enrolled); err != nil {
		slog.Error("failed to enroll", "error", err)
		os.Exit(1)
	}
	if enrolled.Error != "" {
		slog.Error("enrollment rejected", "error", enrolled.Error)
		os.Exit(1)
	}
	slog.Info("enrolled TPM key",
		"key_id", enrolled.KeyID,
		"identity", enrolled.Identity.Label,
		"source", enrolled.Identity.Source)

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

	for _, req := range []func() (*http.Response, error){
		func() (*http.Response, error) { return httpClient.Post(addr, "application/json", nil) },
		func() (*http.Response, error) { return httpClient.Get(addr) },
	} {
		res, err := req()
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

// post sends v as JSON and decodes the response into out.
func post(url string, v, out any) error {
	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(v); err != nil {
		return err
	}
	rsp, err := http.Post(url, "application/json", buf)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	return json.NewDecoder(rsp.Body).Decode(out)
}

// instanceID reads this instance's ID from IMDSv2. Done with plain HTTP so the
// client needs no AWS SDK; the value is only a claim the server verifies for
// itself.
func instanceID() (string, error) {
	const base = "http://169.254.169.254"
	c := &http.Client{Timeout: 2 * time.Second}

	tokReq, err := http.NewRequest(http.MethodPut, base+"/latest/api/token", nil)
	if err != nil {
		return "", err
	}
	tokReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	tokRsp, err := c.Do(tokReq)
	if err != nil {
		return "", err
	}
	defer tokRsp.Body.Close()
	token, err := io.ReadAll(tokRsp.Body)
	if err != nil {
		return "", err
	}

	idReq, err := http.NewRequest(http.MethodGet, base+"/latest/meta-data/instance-id", nil)
	if err != nil {
		return "", err
	}
	idReq.Header.Set("X-aws-ec2-metadata-token", string(token))
	idRsp, err := c.Do(idReq)
	if err != nil {
		return "", err
	}
	defer idRsp.Body.Close()
	if idRsp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDS returned %s", idRsp.Status)
	}
	id, err := io.ReadAll(idRsp.Body)
	if err != nil {
		return "", err
	}
	return string(id), nil
}
