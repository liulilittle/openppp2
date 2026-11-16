package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newSecurityServer(listen string) *Server {
	return NewServer(listen, nil, nil, nil, &GuardianServerConfig{JWTSecret: "secret"}, nil)
}

func doRequest(s *Server, method, path, host, origin, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = host
	req.RemoteAddr = "192.0.2.10:5555"
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	res := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(res, req)
	return res
}

func TestCORSSameOriginAllowedWithoutWildcard(t *testing.T) {
	s := newSecurityServer("127.0.0.1:18080")
	res := doRequest(s, http.MethodPost, "/api/v1/auth/login", "127.0.0.1:18080", "http://127.0.0.1:18080", `{"password":""}`)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", res.Code, res.Body.String())
	}
	if got := res.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want empty", got)
	}
}

func TestCORSForeignOriginRejectedForStateChange(t *testing.T) {
	s := newSecurityServer("127.0.0.1:18080")
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		res := doRequest(s, method, "/api/v1/auth/login", "127.0.0.1:18080", "https://evil.example", `{}`)
		if res.Code != http.StatusForbidden {
			t.Fatalf("%s status = %d, want 403", method, res.Code)
		}
		if res.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("%s leaked CORS header", method)
		}
	}
	res := doRequest(s, http.MethodPost, "/api/v1/auth/login", "127.0.0.1:18080", "null", `{}`)
	if res.Code != http.StatusForbidden {
		t.Fatalf("null origin status = %d, want 403", res.Code)
	}
}

func TestCORSPreflightHasNoAllowHeaders(t *testing.T) {
	s := newSecurityServer("127.0.0.1:18080")
	res := doRequest(s, http.MethodOptions, "/api/v1/instances", "127.0.0.1:18080", "https://evil.example", "")
	if res.Header().Get("Access-Control-Allow-Origin") != "" || res.Header().Get("Access-Control-Allow-Methods") != "" {
		t.Fatalf("preflight carried CORS allow headers: %v", res.Header())
	}
}

func TestHostCheckOnLoopbackListener(t *testing.T) {
	s := newSecurityServer("127.0.0.1:18080")
	for _, host := range []string{"127.0.0.1:18080", "localhost:18080", "[::1]:18080", "localhost"} {
		if res := doRequest(s, http.MethodPost, "/api/v1/auth/login", host, "", `{}`); res.Code != http.StatusOK {
			t.Fatalf("host %q status = %d, want 200", host, res.Code)
		}
	}
	for _, host := range []string{"evil.example:18080", "attacker.test", "10.0.0.5:18080"} {
		if res := doRequest(s, http.MethodPost, "/api/v1/auth/login", host, "", `{}`); res.Code != http.StatusForbidden {
			t.Fatalf("host %q status = %d, want 403", host, res.Code)
		}
	}
}

func TestHostCheckSkippedForNonLoopbackListener(t *testing.T) {
	s := newSecurityServer("0.0.0.0:18080")
	if res := doRequest(s, http.MethodPost, "/api/v1/auth/login", "guardian.lan:18080", "", `{}`); res.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.Code)
	}
}

func TestRequestBodyLimit(t *testing.T) {
	s := newSecurityServer("127.0.0.1:18080")
	big := `{"password":"` + strings.Repeat("a", maxRequestBodyBytes+10) + `"}`
	if res := doRequest(s, http.MethodPost, "/api/v1/auth/login", "127.0.0.1:18080", "", big); res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.Code)
	}
}

func TestLoginRateLimitAndBackoff(t *testing.T) {
	s := NewServer("127.0.0.1:18080", nil, nil, nil, &GuardianServerConfig{AuthEnabled: true, JWTSecret: "secret"}, nil)
	now := time.Now()
	s.limiter.now = func() time.Time { return now }

	for i := 0; i < limiterFreeFailures; i++ {
		if res := doRequest(s, http.MethodPost, "/api/v1/auth/login", "127.0.0.1:18080", "", `{"password":"bad"}`); res.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i, res.Code)
		}
	}
	// The next failure triggers the first backoff; afterwards even the right password is blocked.
	doRequest(s, http.MethodPost, "/api/v1/auth/login", "127.0.0.1:18080", "", `{"password":"bad"}`)
	res := doRequest(s, http.MethodPost, "/api/v1/auth/login", "127.0.0.1:18080", "", `{"password":"secret"}`)
	if res.Code != http.StatusTooManyRequests || res.Header().Get("Retry-After") == "" {
		t.Fatalf("status = %d retry-after=%q, want 429 with Retry-After", res.Code, res.Header().Get("Retry-After"))
	}
	// Password change endpoint shares the limiter.
	if res := doRequest(s, http.MethodPut, "/api/v1/auth/password", "127.0.0.1:18080", "", `{"newPassword":"x"}`); res.Code != http.StatusTooManyRequests {
		t.Fatalf("password status = %d, want 429", res.Code)
	}
	// Other IPs are unaffected, and the block expires.
	if _, blocked := s.limiter.Check("198.51.100.1"); blocked {
		t.Fatal("unrelated IP blocked")
	}
	now = now.Add(10 * time.Second)
	if res := doRequest(s, http.MethodPost, "/api/v1/auth/login", "127.0.0.1:18080", "", `{"password":"secret"}`); res.Code != http.StatusOK {
		t.Fatalf("after backoff status = %d, want 200", res.Code)
	}
}

func TestLimiterBackoffGrowsAndMapIsBounded(t *testing.T) {
	l := newAuthLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	for i := 0; i < limiterFreeFailures+4; i++ {
		l.Fail("ip")
	}
	prev, _ := l.Check("ip")
	l.Fail("ip")
	if next, _ := l.Check("ip"); next <= prev {
		t.Fatalf("backoff did not grow: %v -> %v", prev, next)
	}
	for i := 0; i < limiterMaxEntries*2; i++ {
		now = now.Add(time.Millisecond)
		l.Fail("ip-" + strconv.Itoa(i))
	}
	if len(l.entries) > limiterMaxEntries {
		t.Fatalf("entries = %d, want <= %d", len(l.entries), limiterMaxEntries)
	}
}
