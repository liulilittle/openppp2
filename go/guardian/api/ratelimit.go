package api

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	limiterFreeFailures = 5
	limiterBaseDelay    = time.Second
	limiterMaxDelay     = 5 * time.Minute
	limiterIdleTTL      = 15 * time.Minute
	limiterMaxEntries   = 4096
)

type limiterEntry struct {
	failures     int
	blockedUntil time.Time
	lastSeen     time.Time
}

// authLimiter is a small in-memory per-IP failure limiter with exponential
// backoff. The map is bounded by limiterMaxEntries.
type authLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]*limiterEntry
}

func newAuthLimiter() *authLimiter {
	return &authLimiter{now: time.Now, entries: make(map[string]*limiterEntry)}
}

// Check reports whether ip is currently blocked and for how long.
func (l *authLimiter) Check(ip string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ip]
	if !ok {
		return 0, false
	}
	if wait := e.blockedUntil.Sub(l.now()); wait > 0 {
		return wait, true
	}
	return 0, false
}

// Fail records a failed attempt and applies backoff after limiterFreeFailures.
func (l *authLimiter) Fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e, ok := l.entries[ip]
	if !ok {
		if len(l.entries) >= limiterMaxEntries {
			l.evictLocked(now)
		}
		e = &limiterEntry{}
		l.entries[ip] = e
	}
	e.lastSeen = now
	e.failures++
	if e.failures > limiterFreeFailures {
		delay := limiterBaseDelay
		for i := limiterFreeFailures + 1; i < e.failures && delay < limiterMaxDelay; i++ {
			delay *= 2
		}
		if delay > limiterMaxDelay {
			delay = limiterMaxDelay
		}
		e.blockedUntil = now.Add(delay)
	}
}

// Reset clears the failure state for ip after a successful attempt.
func (l *authLimiter) Reset(ip string) {
	l.mu.Lock()
	delete(l.entries, ip)
	l.mu.Unlock()
}

// evictLocked drops idle entries; if the map is still full it drops the oldest.
func (l *authLimiter) evictLocked(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for k, e := range l.entries {
		if now.Sub(e.lastSeen) > limiterIdleTTL && !e.blockedUntil.After(now) {
			delete(l.entries, k)
			continue
		}
		if oldestKey == "" || e.lastSeen.Before(oldest) {
			oldestKey, oldest = k, e.lastSeen
		}
	}
	if len(l.entries) >= limiterMaxEntries && oldestKey != "" {
		delete(l.entries, oldestKey)
	}
}

// clientIP uses the TCP peer address; forwarded headers are not trusted.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func tooManyAttempts(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	Error(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
}
