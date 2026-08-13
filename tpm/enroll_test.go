package tpm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/micahhausler/httpsig/client"
	"github.com/micahhausler/httpsig/server"
	"github.com/micahhausler/httpsig/sigconfig"
)

// postJSON sends v as JSON to url and decodes the reply into out.
func postJSON(url string, v, out any) error {
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

// enrollOverHTTP runs the whole two-round protocol against a Directory's own
// handlers, which is the path the real client and server take.
func enrollOverHTTP(t *testing.T, device transport.TPM, dir *Directory, claim string) (*Signer, *EnrollResponse, error) {
	t.Helper()

	mux := http.NewServeMux()
	mux.Handle("/enroll/challenge", dir.ChallengeHandler())
	mux.Handle("/enroll", dir.EnrollHandler())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	enroller, err := NewEnroller(device)
	if err != nil {
		t.Fatalf("failed to create enroller: %v", err)
	}
	defer enroller.Close()

	challenge := &ChallengeResponse{}
	if err := postJSON(srv.URL+"/enroll/challenge", enroller.Challenge(claim), challenge); err != nil {
		t.Fatalf("challenge request failed: %v", err)
	}
	if challenge.Error != "" {
		return nil, nil, &protocolError{stage: "challenge", msg: challenge.Error}
	}

	secret, err := enroller.Activate(challenge)
	if err != nil {
		t.Fatalf("activation failed: %v", err)
	}

	signer, req, err := enroller.CreateSigningKey(challenge.Nonce)
	if err != nil {
		t.Fatalf("failed to create signing key: %v", err)
	}
	req.ChallengeID = challenge.ChallengeID
	req.Secret = secret

	rsp := &EnrollResponse{}
	if err := postJSON(srv.URL+"/enroll", req, rsp); err != nil {
		t.Fatalf("enroll request failed: %v", err)
	}
	if rsp.Error != "" {
		return nil, nil, &protocolError{stage: "enroll", msg: rsp.Error}
	}
	return signer, rsp, nil
}

type protocolError struct {
	stage string
	msg   string
}

func (e *protocolError) Error() string { return e.stage + ": " + e.msg }

func TestEnrollmentRoundTrip(t *testing.T) {
	device, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed to open simulator: %v", err)
	}
	defer device.Close()

	dir := NewDirectory(TOFUTrust{})
	signer, rsp, err := enrollOverHTTP(t, device, dir, "")
	if err != nil {
		t.Fatalf("enrollment rejected: %v", err)
	}

	if rsp.KeyID != signer.KeyID() {
		t.Errorf("server keyid %s does not match signer keyid %s", rsp.KeyID, signer.KeyID())
	}
	if rsp.Identity.Source != SourceTOFU {
		t.Errorf("expected source %q, got %q", SourceTOFU, rsp.Identity.Source)
	}

	// The enrolled key has to carry a real request through the verifying
	// middleware, and the identity the handler sees has to be the one the
	// enrollment established.
	policy := sigconfig.VerifyPolicy{
		Coverage: sigconfig.Coverage{Components: []string{`"@method"`, `"@target-uri"`}},
	}
	mw, err := server.New(dir, policy)
	if err != nil {
		t.Fatalf("failed to build middleware: %v", err)
	}
	var seen Identity
	protected := httptest.NewServer(mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := server.FromRequest[Identity](r)
		if !ok {
			t.Error("handler ran without a verified identity")
			return
		}
		seen = v.Identity
	})))
	defer protected.Close()

	rt, err := client.NewTransport(nil, signer, sigconfig.SigningProfile{
		Coverage: sigconfig.Coverage{Components: []string{`"@method"`, `"@target-uri"`}},
		KeyID:    signer.KeyID(),
	})
	if err != nil {
		t.Fatalf("failed to build signing transport: %v", err)
	}

	res, err := (&http.Client{Transport: rt}).Get(protected.URL)
	if err != nil {
		t.Fatalf("signed request failed: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("signed request got %s, want 200", res.Status)
	}
	if seen.Label != rsp.Identity.Label || seen.Source != SourceTOFU {
		t.Errorf("handler saw %s/%s, want %s/%s", seen.Label, seen.Source, rsp.Identity.Label, SourceTOFU)
	}

	// an unsigned request must not reach the handler
	unsigned, err := http.Get(protected.URL)
	if err != nil {
		t.Fatalf("unsigned request failed: %v", err)
	}
	unsigned.Body.Close()
	if unsigned.StatusCode != http.StatusUnauthorized {
		t.Errorf("unsigned request got %s, want 401", unsigned.Status)
	}
}

func TestEnrollmentPinnedTrust(t *testing.T) {
	device, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed to open simulator: %v", err)
	}
	defer device.Close()

	// read this TPM's endorsement key the way an operator would, to pin it
	enroller, err := NewEnroller(device)
	if err != nil {
		t.Fatalf("failed to create enroller: %v", err)
	}
	ekPublic := enroller.Challenge("").EKPublic
	enroller.Close()

	pinned := &PinnedTrust{keys: []PinnedKey{{
		Label:    "test-machine",
		EKPublic: base64.StdEncoding.EncodeToString(ekPublic),
	}}}

	_, rsp, err := enrollOverHTTP(t, device, NewDirectory(pinned), "")
	if err != nil {
		t.Fatalf("enrollment rejected: %v", err)
	}
	if rsp.Identity.Label != "test-machine" || rsp.Identity.Source != SourcePinned {
		t.Errorf("expected test-machine/%s, got %s/%s", SourcePinned, rsp.Identity.Label, rsp.Identity.Source)
	}

	// a directory pinned to some other machine's EK must refuse
	other := &PinnedTrust{keys: []PinnedKey{{
		Label:    "other-machine",
		EKPublic: base64.StdEncoding.EncodeToString([]byte("not an endorsement key")),
	}}}
	if _, _, err := enrollOverHTTP(t, device, NewDirectory(other), ""); err == nil {
		t.Error("enrollment succeeded against an unpinned endorsement key")
	} else if !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("expected a trust failure, got: %v", err)
	}
}

// A stolen or invented activation secret must not admit a key: it is the only
// thing proving the client holds the endorsement key.
func TestEnrollmentWrongSecret(t *testing.T) {
	device, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed to open simulator: %v", err)
	}
	defer device.Close()

	dir := NewDirectory(TOFUTrust{})
	enroller, err := NewEnroller(device)
	if err != nil {
		t.Fatalf("failed to create enroller: %v", err)
	}
	defer enroller.Close()

	req := httptest.NewRequest(http.MethodPost, "/enroll/challenge", nil)
	challenge, err := dir.Challenge(req, enroller.Challenge(""))
	if err != nil {
		t.Fatalf("challenge failed: %v", err)
	}

	_, enrollReq, err := enroller.CreateSigningKey(challenge.Nonce)
	if err != nil {
		t.Fatalf("failed to create signing key: %v", err)
	}
	enrollReq.ChallengeID = challenge.ChallengeID
	enrollReq.Secret = make([]byte, secretLen) // never recovered from the TPM

	if _, _, err := dir.Enroll(enrollReq); err == nil {
		t.Error("enrollment succeeded with a fabricated activation secret")
	} else if !strings.Contains(err.Error(), "secret does not match") {
		t.Errorf("expected a secret mismatch, got: %v", err)
	}
}

// An attestation from one challenge must not satisfy another, and a challenge
// must not be reusable.
func TestEnrollmentChallengeIsSingleUse(t *testing.T) {
	device, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed to open simulator: %v", err)
	}
	defer device.Close()

	dir := NewDirectory(TOFUTrust{})
	enroller, err := NewEnroller(device)
	if err != nil {
		t.Fatalf("failed to create enroller: %v", err)
	}

	httpReq := httptest.NewRequest(http.MethodPost, "/enroll/challenge", nil)
	first, err := dir.Challenge(httpReq, enroller.Challenge(""))
	if err != nil {
		t.Fatalf("challenge failed: %v", err)
	}
	secret, err := enroller.Activate(first)
	if err != nil {
		t.Fatalf("activation failed: %v", err)
	}
	_, enrollReq, err := enroller.CreateSigningKey(first.Nonce)
	if err != nil {
		t.Fatalf("failed to create signing key: %v", err)
	}
	enrollReq.ChallengeID = first.ChallengeID
	enrollReq.Secret = secret

	if _, _, err := dir.Enroll(enrollReq); err != nil {
		t.Fatalf("first enrollment rejected: %v", err)
	}
	if _, _, err := dir.Enroll(enrollReq); err == nil {
		t.Error("the same challenge was accepted twice")
	} else if !strings.Contains(err.Error(), "unknown or expired") {
		t.Errorf("expected an unknown challenge, got: %v", err)
	}

	// Replay the first attestation against a fresh challenge, with that
	// challenge's own activation secret, which is the strongest form of the
	// attack: only the nonce in the attestation is stale. A second Enroller
	// re-derives the same endorsement and attestation keys, since both are
	// primaries; the first is closed to leave the TPM room to load them.
	enroller.Close()
	replayer, err := NewEnroller(device)
	if err != nil {
		t.Fatalf("failed to create second enroller: %v", err)
	}
	defer replayer.Close()

	second, err := dir.Challenge(httpReq, replayer.Challenge(""))
	if err != nil {
		t.Fatalf("second challenge failed: %v", err)
	}
	secondSecret, err := replayer.Activate(second)
	if err != nil {
		t.Fatalf("second activation failed: %v", err)
	}
	replay := *enrollReq
	replay.ChallengeID = second.ChallengeID
	replay.Secret = secondSecret
	if _, _, err := dir.Enroll(&replay); err == nil {
		t.Error("a stale attestation was accepted against a fresh challenge")
	} else if !strings.Contains(err.Error(), "not bound to this challenge") {
		t.Errorf("expected a nonce mismatch, got: %v", err)
	}
}

// The attestation key must be restricted, or its signature over an attestation
// proves nothing about what it signed.
func TestChallengeRejectsUnrestrictedAK(t *testing.T) {
	device, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed to open simulator: %v", err)
	}
	defer device.Close()

	enroller, err := NewEnroller(device)
	if err != nil {
		t.Fatalf("failed to create enroller: %v", err)
	}
	defer enroller.Close()

	cr := enroller.Challenge("")
	// swap in an unrestricted signing key's public area as the AK
	unrestricted := tpm2.Marshal(&appKeyTemplate)
	cr.AKPublic = unrestricted

	dir := NewDirectory(TOFUTrust{})
	req := httptest.NewRequest(http.MethodPost, "/enroll/challenge", nil)
	if _, err := dir.Challenge(req, cr); err == nil {
		t.Error("a challenge was issued for an unrestricted attestation key")
	} else if !strings.Contains(err.Error(), "restricted") {
		t.Errorf("expected a restriction failure, got: %v", err)
	}
}

func TestPinnedTrustRejectsEmptyFile(t *testing.T) {
	path := t.TempDir() + "/ek.json"
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPinnedTrust(path); err == nil {
		t.Error("an empty pin file was accepted")
	}
}

func TestTOFUTrustIsStablePerKey(t *testing.T) {
	a, err := TOFUTrust{}.Trust(context.Background(), "", []byte("ek-one"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := TOFUTrust{}.Trust(context.Background(), "", []byte("ek-one"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := TOFUTrust{}.Trust(context.Background(), "", []byte("ek-two"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Label != again.Label {
		t.Errorf("same key produced different labels: %s and %s", a.Label, again.Label)
	}
	if a.Label == b.Label {
		t.Error("different keys produced the same label")
	}
}
