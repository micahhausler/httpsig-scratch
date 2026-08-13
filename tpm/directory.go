package tpm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig-scratch/attributes"
	"github.com/micahhausler/httpsig/server"
)

// A Directory holds verifiers for TPM keys whose enrollments passed
// VerifyEnrollment, keyed by the key's TPM Name.
type Directory struct {
	mu   sync.RWMutex
	keys map[string]entry
}

type entry struct {
	verifier httpsig.Verifier
	user     attributes.User
}

var _ server.KeyDirectory[attributes.User] = &Directory{}

func NewDirectory() *Directory {
	return &Directory{keys: map[string]entry{}}
}

// Enroll verifies an enrollment and admits the key, returning its keyid.
func (d *Directory) Enroll(e *Enrollment) (string, error) {
	verifier, keyID, err := VerifyEnrollment(e)
	if err != nil {
		return "", err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.keys[keyID] = entry{
		verifier: verifier,
		user:     attributes.User{Username: e.Username},
	}
	return keyID, nil
}

func (d *Directory) Key(req *http.Request, sig *httpsig.Signature) (httpsig.Verifier, attributes.User, error) {
	d.mu.RLock()
	e, ok := d.keys[sig.KeyID()]
	d.mu.RUnlock()
	if !ok {
		return nil, attributes.User{}, fmt.Errorf("no enrolled key for keyid")
	}
	return e.verifier, e.user, nil
}

// EnrollHandler returns an HTTP handler that accepts an Enrollment as JSON.
// Authentication of the enrollment itself (who may enroll, whether the AK is
// anchored to an EK certificate) is out of scope here.
func (d *Directory) EnrollHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			enc.Encode(EnrollmentResponse{Error: "invalid method"})
			return
		}

		enrollment := &Enrollment{}
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(enrollment); err != nil {
			slog.Error("failed to decode enrollment", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			enc.Encode(EnrollmentResponse{Error: "invalid request"})
			return
		}
		if enrollment.Username == "" {
			w.WriteHeader(http.StatusBadRequest)
			enc.Encode(EnrollmentResponse{Error: "username is required"})
			return
		}

		keyID, err := d.Enroll(enrollment)
		if err != nil {
			slog.Error("failed to verify enrollment", "error", err, "username", enrollment.Username)
			w.WriteHeader(http.StatusBadRequest)
			enc.Encode(EnrollmentResponse{Error: fmt.Sprintf("enrollment rejected: %v", err)})
			return
		}

		slog.Info("enrolled TPM key", "username", enrollment.Username, "key_id", keyID)
		enc.Encode(EnrollmentResponse{KeyID: keyID})
	})
}
