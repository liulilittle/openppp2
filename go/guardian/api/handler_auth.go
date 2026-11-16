package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"

	"ppp/guardian/auth"
)

type loginRequest struct {
	Password string `json:"password"`
}

// authState returns a consistent snapshot of the mutable auth settings.
func (s *Server) authState() (enabled bool, secret string) {
	s.authMu.RLock()
	defer s.authMu.RUnlock()
	return s.authCfg.AuthEnabled, s.jwtSecret
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if wait, blocked := s.limiter.Check(ip); blocked {
		tooManyAttempts(w, wait)
		return
	}
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	enabled, secret := s.authState()
	if enabled {
		if secret == "" {
			Error(w, http.StatusServiceUnavailable, "authentication is not configured")
			return
		}
		if req.Password == "" || subtle.ConstantTimeCompare([]byte(req.Password), []byte(secret)) != 1 {
			s.limiter.Fail(ip)
			Error(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		s.limiter.Reset(ip)
	}
	token, expiry, err := s.issueToken()
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	Success(w, map[string]any{"token": token, "expiresAt": expiry})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	oldToken := bearerToken(r.Header.Get("Authorization"))
	if oldToken == "" || !s.tokenStore.Validate(oldToken) {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	_, secret := s.authState()
	if _, err := auth.ValidateToken(oldToken, secret); err != nil {
		Error(w, http.StatusUnauthorized, err.Error())
		return
	}
	s.tokenStore.Remove(oldToken)
	token, expiry, err := s.issueToken()
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	Success(w, map[string]any{"token": token, "expiresAt": expiry})
}

func (s *Server) issueToken() (string, any, error) {
	_, secret := s.authState()
	if secret == "" {
		return "", nil, errors.New("authentication secret is not configured")
	}
	token, err := auth.GenerateToken(secret, s.authCfg.TokenExpiryHours)
	if err != nil {
		return "", nil, err
	}
	claims, err := auth.ValidateToken(token, secret)
	if err != nil {
		return "", nil, err
	}
	s.tokenStore.Add(token, claims.ExpiresAt)
	return token, claims.ExpiresAt, nil
}

type changePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if wait, blocked := s.limiter.Check(ip); blocked {
		tooManyAttempts(w, wait)
		return
	}
	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NewPassword == "" {
		Error(w, http.StatusBadRequest, "new password is required")
		return
	}
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if s.authCfg.AuthEnabled && s.jwtSecret == "" {
		Error(w, http.StatusServiceUnavailable, "authentication is not configured")
		return
	}
	if s.authCfg.AuthEnabled && (req.OldPassword == "" || subtle.ConstantTimeCompare([]byte(req.OldPassword), []byte(s.jwtSecret)) != 1) {
		s.limiter.Fail(ip)
		Error(w, http.StatusUnauthorized, "invalid current password")
		return
	}
	s.limiter.Reset(ip)
	authEnabled := s.authCfg.AuthEnabled || req.NewPassword != ""
	if s.authCfg.OnAuthChanged != nil {
		if err := s.authCfg.OnAuthChanged(authEnabled, req.NewPassword); err != nil {
			Error(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	s.jwtSecret = req.NewPassword
	s.authCfg.JWTSecret = req.NewPassword
	s.authCfg.AuthEnabled = authEnabled
	s.tokenStore.Clear()
	Success(w, map[string]any{"ok": true, "message": "password updated, all tokens invalidated"})
}
