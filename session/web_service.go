package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/alg_hmac"
	"github.com/common-fate/httpsig/alg_rsa"
	"github.com/common-fate/httpsig/verifier"
)

type User struct {
	Username string `json:"username"`
}

type EncryptionRequest struct {
	UserInfo  User   `json:"user_info"`
	KeyID     string `json:"key_id"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
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

type sessionTokenContextKey struct{}

type DecryptionService struct {
	decrypter        Decrypter
	SessionTokenName string
}

func (d *DecryptionService) Attributes(ctx context.Context) any {
	tok := ctx.Value(sessionTokenContextKey{})
	tokBytes, ok := tok.([]byte)
	if !ok {
		slog.Error("invalid session token", "session_token", tok, "type", fmt.Sprintf("%T", tok))
		return nil
	}

	_, _, _, attributes, err := d.decrypter.DecryptPublicKey(ctx, tokBytes)
	if err != nil {
		slog.Error("failed to decrypt session token", "error", err)
		return nil
	}
	return attributes
}

func (d *DecryptionService) GetSessionTokenDecryptingMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), sessionTokenContextKey{}, r.Header.Get(d.SessionTokenName))
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}

func (s *DecryptionService) GetKey(ctx context.Context, kid string, clientSpecifiedAlg string) (verifier.Algorithm, error) {
	sessionTokenRaw := ctx.Value(sessionTokenContextKey{})
	var sessionTokenBytes []byte
	switch v := sessionTokenRaw.(type) {
	case string:
		sessionTokenBytes = []byte(v)
	case []byte:
		sessionTokenBytes = v
	default:
		slog.Error("invalid session token", "session_token", sessionTokenRaw, "type", fmt.Sprintf("%T", sessionTokenRaw))
		return nil, fmt.Errorf("invalid session token")
	}

	keyID, alg, publicKey, attributes, err := s.decrypter.DecryptPublicKey(ctx, sessionTokenBytes)
	if err != nil {
		return nil, err
	}
	if keyID != kid {
		return nil, fmt.Errorf("invalid key id")
	}
	if alg != clientSpecifiedAlg {
		return nil, fmt.Errorf("invalid algorithm")
	}

	switch alg {
	case "rsa-pss-sha512":
		block, _ := pem.Decode(publicKey)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block containing public key")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DER encoded public key: %w", err)
		}

		kP, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid RSA public key")
		}
		return &alg_rsa.RSAPSS512{
			PublicKey: kP,
			Attrs:     attributes,
		}, nil
	case "rsa-v1_5-sha256":
		block, _ := pem.Decode(publicKey)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block containing public key")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DER encoded public key: %w", err)
		}

		kP, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid RSA public key")
		}
		return &alg_rsa.RSAPKCS256{
			PublicKey: kP,
			Attrs:     attributes,
		}, nil
	case "ecdsa-p256-sha256":
		block, _ := pem.Decode(publicKey)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block containing public key")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DER encoded public key: %w", err)
		}

		kP, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid ECDSA public key")
		}
		return &alg_ecdsa.P256{
			PublicKey: kP,
			Attrs:     attributes,
		}, nil
	case "hmac-sha256":
		return alg_hmac.NewHMACWithAttributes(publicKey, attributes), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm")
	}
}
