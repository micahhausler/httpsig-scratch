package session

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
)

func createCredentials() (string, string, error) {
	len := 16
	kidBits := make([]byte, len)
	_, err := rand.Read(kidBits)
	if err != nil {
		return "", "", err
	}
	kid := make([]byte, len)
	for i := 0; i < len; i++ {
		// Map the random byte to the charset range
		kid[i] = byte(int('0') + int(kidBits[i])%(int('z')-int('0')+1))
	}

	secretKeyBytes := make([]byte, 32)
	_, err = rand.Read(secretKeyBytes)
	if err != nil {
		return "", "", err
	}
	return string(kid), base64.StdEncoding.EncodeToString(secretKeyBytes), nil
}

type CredentialRequest struct {
	UserInfo User `json:"user_info"`
}

type CredentialResponse struct {
	KeyID        string `json:"key_id,omitempty"`
	SecretKey    string `json:"secret_key,omitempty"`
	SessionToken []byte `json:"session_token,omitempty"`
	Error        string `json:"error,omitempty"`
}

// NewCredentialHandler returns an HTTP Handler that creates a session token for an EncryptionRequest.
// Authenication should be handled outside this handler.
//
// To inject attributes into a session token, add it to the request's context,
// and specify the context key in the SessionTokenHandler method.
func (e *EncryptionService) NewCredentialHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := &CredentialResponse{}
		enc := json.NewEncoder(w)

		if r.Method != http.MethodPost {
			slog.Error("invalid method", "method", r.Method)
			resp.Error = "invalid method"
			enc.Encode(resp)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		request := &CredentialRequest{}
		defer r.Body.Close()
		err := json.NewDecoder(r.Body).Decode(request)
		if err != nil {
			slog.Error("failed to decode request", "error", err)
			resp.Error = "invalid request"
			enc.Encode(resp)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		kid, secretKey, err := createCredentials()
		if err != nil {
			slog.Error("failed to create credentials", "error", err)
			resp.Error = "failed to create credentials"
			enc.Encode(resp)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp.KeyID = kid
		resp.SecretKey = secretKey

		sessionToken, err := e.encrypter.EncryptPublicKey(
			r.Context(),
			kid,
			"hmac-sha256",
			[]byte(secretKey),
			request.UserInfo,
		)
		if err != nil {
			slog.Error("failed to encrypt token key", "error", err)
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
		slog.Info("Created HMAC credentials", "method", r.Method, "url", r.URL.String(), "remote_addr", r.RemoteAddr, "user", request.UserInfo.Username)
	})
}
