package tpm

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig/server"
)

// challengeTTL bounds how long an opened enrollment may sit unfinished. It also
// bounds the memory a peer can occupy by starting enrollments it never
// completes.
const challengeTTL = 2 * time.Minute

// A Directory admits TPM signing keys whose enrollment proved they live in a
// machine its EKTrust recognises, and resolves request signatures against them.
type Directory struct {
	trust EKTrust
	now   func() time.Time

	mu         sync.RWMutex
	keys       map[string]entry
	challenges map[string]*pending
}

type entry struct {
	verifier httpsig.Verifier
	identity Identity
}

type pending struct {
	challenge *challenge
	expires   time.Time
}

var _ server.KeyDirectory[Identity] = &Directory{}

func NewDirectory(trust EKTrust) *Directory {
	return &Directory{
		trust:      trust,
		now:        time.Now,
		keys:       map[string]entry{},
		challenges: map[string]*pending{},
	}
}

// Key resolves a request signature to an enrolled TPM key. The identity it
// returns is the machine the key was traced to, which is not something the
// request itself asserts.
func (d *Directory) Key(req *http.Request, sig *httpsig.Signature) (httpsig.Verifier, Identity, error) {
	d.mu.RLock()
	e, ok := d.keys[sig.KeyID()]
	d.mu.RUnlock()
	if !ok {
		return nil, Identity{}, fmt.Errorf("no enrolled key for keyid")
	}
	return e.verifier, e.identity, nil
}

// Challenge opens an enrollment: it decides whether the endorsement key belongs
// to a machine this server trusts, and returns a secret only that machine's TPM
// can recover.
func (d *Directory) Challenge(req *http.Request, cr *ChallengeRequest) (*ChallengeResponse, error) {
	identity, err := d.trust.Trust(req.Context(), cr.Claim, cr.EKPublic)
	if err != nil {
		return nil, fmt.Errorf("endorsement key not trusted: %w", err)
	}

	c, rsp, err := newChallenge(identity, cr.EKPublic, cr.AKPublic)
	if err != nil {
		return nil, err
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idBytes)

	d.mu.Lock()
	d.expireLocked()
	d.challenges[id] = &pending{challenge: c, expires: d.now().Add(challengeTTL)}
	d.mu.Unlock()

	rsp.ChallengeID = id
	return rsp, nil
}

// Enroll completes an enrollment and admits the signing key.
func (d *Directory) Enroll(req *EnrollRequest) (string, Identity, error) {
	// Single use: a challenge is consumed whether or not it goes on to
	// verify, so a recovered secret cannot be replayed.
	d.mu.Lock()
	d.expireLocked()
	p, ok := d.challenges[req.ChallengeID]
	delete(d.challenges, req.ChallengeID)
	d.mu.Unlock()
	if !ok {
		return "", Identity{}, fmt.Errorf("unknown or expired challenge")
	}

	verifier, keyID, err := verifyEnrollment(p.challenge, req)
	if err != nil {
		return "", Identity{}, err
	}

	d.mu.Lock()
	d.keys[keyID] = entry{verifier: verifier, identity: p.challenge.identity}
	d.mu.Unlock()

	return keyID, p.challenge.identity, nil
}

func (d *Directory) expireLocked() {
	now := d.now()
	for id, p := range d.challenges {
		if now.After(p.expires) {
			delete(d.challenges, id)
		}
	}
}

// ChallengeHandler serves the first round of an enrollment.
func (d *Directory) ChallengeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			enc.Encode(ChallengeResponse{Error: "invalid method"})
			return
		}

		cr := &ChallengeRequest{}
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(cr); err != nil {
			slog.Error("failed to decode challenge request", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			enc.Encode(ChallengeResponse{Error: "invalid request"})
			return
		}

		rsp, err := d.Challenge(r, cr)
		if err != nil {
			slog.Error("refused to issue challenge", "error", err, "claim", cr.Claim)
			w.WriteHeader(http.StatusBadRequest)
			enc.Encode(ChallengeResponse{Error: err.Error()})
			return
		}
		slog.Info("issued enrollment challenge", "claim", cr.Claim, "challenge_id", rsp.ChallengeID)
		enc.Encode(rsp)
	})
}

// EnrollHandler serves the second round of an enrollment.
//
// Neither endpoint authenticates its caller. It does not need to: a client can
// only complete an enrollment for a machine whose endorsement key the server
// already trusts, and only by proving it holds that key.
func (d *Directory) EnrollHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			enc.Encode(EnrollResponse{Error: "invalid method"})
			return
		}

		er := &EnrollRequest{}
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(er); err != nil {
			slog.Error("failed to decode enrollment", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			enc.Encode(EnrollResponse{Error: "invalid request"})
			return
		}

		keyID, identity, err := d.Enroll(er)
		if err != nil {
			slog.Error("enrollment rejected", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			enc.Encode(EnrollResponse{Error: err.Error()})
			return
		}

		slog.Info("enrolled TPM key", "identity", identity.Label, "source", identity.Source, "key_id", keyID)
		enc.Encode(EnrollResponse{KeyID: keyID, Identity: identity})
	})
}
