package instance

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

type HealthChecker struct {
	cfg    HealthCheckConfig
	stopCh chan struct{}
	doneCh chan struct{}
}

func (m *Manager) StartHealthCheck(name string) {
	m.mu.RLock()
	inst, ok := m.instances[name]
	m.mu.RUnlock()
	if !ok || !inst.cfg.HealthCheck.Enabled {
		return
	}

	m.StopHealthCheck(name)

	hc := &HealthChecker{
		cfg:    inst.cfg.HealthCheck,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}

	inst.mu.Lock()
	inst.healthCheck = hc
	inst.mu.Unlock()

	go hc.run(m, name)
}

func (m *Manager) StopHealthCheck(name string) {
	m.mu.RLock()
	inst, ok := m.instances[name]
	m.mu.RUnlock()
	if !ok {
		return
	}

	inst.mu.Lock()
	hc := inst.healthCheck
	inst.healthCheck = nil
	inst.mu.Unlock()

	stopHealthChecker(hc)
}

func stopHealthChecker(hc *HealthChecker) {
	if hc == nil {
		return
	}
	close(hc.stopCh)
	<-hc.doneCh
}

func (hc *HealthChecker) run(m *Manager, name string) {
	defer close(hc.doneCh)
	interval := time.Duration(hc.cfg.IntervalMs) * time.Millisecond
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-hc.stopCh:
			return
		case <-ticker.C:
			if !hc.check() {
				m.publishEvent(Event{
					Type:    "unhealthy",
					Name:    name,
					At:      time.Now(),
					Message: "Health check failed",
				})
			}
		}
	}
}

func (hc *HealthChecker) check() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if hc.cfg.TCPPort > 0 {
		return hc.tcpCheck(ctx)
	}
	if hc.cfg.HTTPEndpoint != "" {
		return hc.httpCheck(ctx)
	}
	return true
}

func (hc *HealthChecker) tcpCheck(ctx context.Context) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", hc.cfg.TCPPort)
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (hc *HealthChecker) httpCheck(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hc.cfg.HTTPEndpoint, nil)
	if err != nil {
		return false
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return false
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}
