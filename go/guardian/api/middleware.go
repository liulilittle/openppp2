package api

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxRequestBodyBytes caps every request body (JSON and profile uploads).
const maxRequestBodyBytes = 1 << 20

// maxProfileBodyBytes is the larger cap for profile uploads.
const maxProfileBodyBytes = 4 << 20

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		if !s.hostAllowed(r.Host) {
			Error(w, http.StatusForbidden, "forbidden host")
			return
		}
		// No CORS headers are ever emitted: only same-origin browsers may use
		// the API. Foreign-origin state-changing requests and preflights are
		// rejected outright.
		if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r.Host) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				Error(w, http.StatusForbidden, "cross-origin request forbidden")
				return
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Body != nil {
			limit := int64(maxRequestBodyBytes)
			if strings.HasPrefix(r.URL.Path, "/api/v1/profiles/") {
				limit = maxProfileBodyBytes
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}

		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			s.logger.Info("request completed",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"duration", time.Since(start),
			)
		}()

		if enabled, _ := s.authState(); enabled && requiresAuth(r.URL.Path) {
			token := bearerToken(r.Header.Get("Authorization"))
			if token == "" || !s.tokenStore.Validate(token) {
				Error(sw, http.StatusUnauthorized, "unauthorized")
				return
			}
		}

		next.ServeHTTP(sw, r)
	})
}

func requiresAuth(path string) bool {
	if strings.HasPrefix(path, "/api/v1/auth/") {
		return false
	}
	if path == "/api/v1/status" {
		return false
	}
	if strings.HasPrefix(path, "/api/v1/ws/") || strings.HasPrefix(path, "/api/v1/sse/") {
		return false
	}
	if !strings.HasPrefix(path, "/api/") {
		return false
	}
	return true
}

func bearerToken(header string) string {
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}

// sameOrigin reports whether the Origin header's host matches the request Host.
func sameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

// hostAllowed defends against DNS rebinding when the listener is loopback-only.
// For non-loopback listeners the Host header cannot be validated and is accepted.
func (s *Server) hostAllowed(reqHost string) bool {
	listenHost, _, err := net.SplitHostPort(s.listenAddr)
	if err != nil {
		listenHost = s.listenAddr
	}
	if !isLoopbackHost(listenHost) {
		return true
	}
	host := reqHost
	if h, _, err := net.SplitHostPort(reqHost); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return isLoopbackHost(host) || strings.EqualFold(host, strings.Trim(listenHost, "[]"))
}

func isLoopbackHost(h string) bool {
	h = strings.Trim(h, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
