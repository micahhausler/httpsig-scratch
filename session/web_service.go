package session

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig-scratch/attributes"
	"github.com/micahhausler/httpsig/server"
)

type EncryptionRequest struct {
	UserInfo  attributes.User `json:"user_info"`
	KeyID     string          `json:"key_id"`
	Alg       string          `json:"alg"`
	PublicKey string          `json:"public_key"`
}

type EncryptionResponse struct {
	SessionToken []byte `json:"session_token,omitempty"`
	Error        string `json:"error,omitempty"`
}

type EncryptionService struct {
	encrypter Encrypter
}

func NewEncryptionService(encrypter Encrypter) *EncryptionService {
	return &EncryptionService{encrypter: encrypter}
}

// SessionTokenHandler returns an HTTP Handler that creates a session token for an EncryptionRequest.
// Authenication should be handled outside this handler.
//
// To inject attributes into a session token, add it to the request's context,
// and specify the context key in the SessionTokenHandler method.
func (e *EncryptionService) SessionTokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := &EncryptionResponse{}
		enc := json.NewEncoder(w)

		if r.Method != http.MethodPost {
			slog.Error("invalid method", "method", r.Method)
			resp.Error = "invalid method"
			enc.Encode(resp)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		request := &EncryptionRequest{}
		defer r.Body.Close()
		err := json.NewDecoder(r.Body).Decode(request)
		if err != nil {
			slog.Error("failed to decode request", "error", err)
			resp.Error = "invalid request"
			enc.Encode(resp)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if request.KeyID == "" || request.Alg == "" || request.PublicKey == "" {
			resp.Error = "invalid request"
			enc.Encode(resp)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		sessionToken, err := e.encrypter.EncryptPublicKey(
			r.Context(),
			request.KeyID,
			request.Alg,
			[]byte(request.PublicKey),
			request.UserInfo,
		)
		if err != nil {
			slog.Error("failed to encrypt public key", "error", err)
			resp.Error = "internal server error"
			enc.Encode(resp)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		resp.SessionToken = sessionToken
		err = enc.Encode(resp)
		if err != nil {
			slog.Error("failed to encode response", "error", err)
			w.Write([]byte(`{"error":"internal server error"}`))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		slog.Info("Created session token", "method", r.Method, "url", r.URL.String(), "remote_addr", r.RemoteAddr)
	})
}

func NewDecryptionService(decrypter Decrypter, sessionTokenName string) *DecryptionService {
	if sessionTokenName == "" {
		sessionTokenName = "x-session-token"
	}
	return &DecryptionService{
		decrypter:        decrypter,
		SessionTokenName: sessionTokenName,
	}
}

type DecryptionService struct {
	decrypter        Decrypter
	SessionTokenName string
}

var _ server.KeyDirectory[attributes.User] = &DecryptionService{}

// Key decrypts the session token carried in the request's SessionTokenName
// header, and returns a verifier for the public key sealed in the token along
// with the user identity sealed in the token.
func (s *DecryptionService) Key(req *http.Request, sig *httpsig.Signature) (httpsig.Verifier, attributes.User, error) {
	var user attributes.User
	sessionToken := req.Header.Get(s.SessionTokenName)
	if sessionToken == "" {
		return nil, user, fmt.Errorf("no session token in request header %q", s.SessionTokenName)
	}

	keyID, alg, publicKey, attrs, err := s.decrypter.DecryptPublicKey(req.Context(), []byte(sessionToken))
	if err != nil {
		return nil, user, err
	}
	if keyID != sig.KeyID() {
		return nil, user, fmt.Errorf("invalid key id")
	}
	if err := json.Unmarshal(attrs, &user); err != nil {
		return nil, user, fmt.Errorf("failed to unmarshal session token attributes: %w", err)
	}

	var key crypto.PublicKey
	switch httpsig.Algorithm(alg) {
	case httpsig.HMACSHA256:
		// for HMAC, the "public key" sealed in the token is the shared secret
		key = publicKey
	default:
		block, _ := pem.Decode(publicKey)
		if block == nil {
			return nil, user, fmt.Errorf("failed to decode PEM block containing public key")
		}
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, user, fmt.Errorf("failed to parse DER encoded public key: %w", err)
		}
	}

	verifier, err := httpsig.NewVerifier(httpsig.Algorithm(alg), key)
	if err != nil {
		return nil, user, err
	}
	return verifier, user, nil
}
