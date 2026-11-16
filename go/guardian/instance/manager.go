package instance

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type StatusResponse struct {
	Name         string            `json:"name"`
	Running      bool              `json:"running"`
	PID          int               `json:"pid,omitempty"`
	StartedAt    *time.Time        `json:"startedAt,omitempty"`
	StoppedAt    *time.Time        `json:"stoppedAt,omitempty"`
	Binary       string            `json:"binary"`
	WorkDir      string            `json:"workDir"`
	ConfigPath   string            `json:"configPath"`
	Args         []string          `json:"args"`
	LastExit     *ExitState        `json:"lastExit,omitempty"`
	AutoRestart  bool              `json:"autoRestart"`
	RestartCount int               `json:"restartCount"`
	RuntimeStats map[string]string `json:"runtimeStats,omitempty"`
}

type ExitState struct {
	Code    int       `json:"code"`
	Error   string    `json:"error,omitempty"`
	At      time.Time `json:"at"`
	Success bool      `json:"success"`
}

type LogEntry struct {
	At     time.Time `json:"at"`
	Stream string    `json:"stream"`
	Text   string    `json:"text"`
}

type Event struct {
	Type    string    `json:"type"`
	Name    string    `json:"name"`
	At      time.Time `json:"at"`
	Message string    `json:"message,omitempty"`
}

type Config struct {
	Name        string
	Binary      string
	WorkDir     string
	ConfigPath  string
	Args        []string
	Env         map[string]string
	StopSignal  string
	StopWaitMs  int
	AutoRestart AutoRestartConfig
	HealthCheck HealthCheckConfig
	LogLines    int
	TUIEnabled  bool
}

type AutoRestartConfig struct {
	Enabled      bool
	MaxRetries   int
	RetryDelayMs int
	ResetAfterMs int
}

type HealthCheckConfig struct {
	Enabled      bool
	IntervalMs   int
	TCPPort      int
	HTTPEndpoint string
}

const (
	maxLogLines         = 100000
	minHealthIntervalMs = 1000
)

type Manager struct {
	mu               sync.RWMutex
	instances        map[string]*instance
	eventSubscribers map[chan Event]struct{}
	shuttingDown     bool
}

func normalizeConfig(name string, cfg Config) Config {
	cfg.Name = name
	if cfg.WorkDir == "" {
		cfg.WorkDir = "."
	}
	if cfg.StopSignal == "" {
		cfg.StopSignal = "interrupt"
	}
	if cfg.StopWaitMs <= 0 {
		cfg.StopWaitMs = 5000
	}
	if cfg.LogLines <= 0 {
		cfg.LogLines = 2000
	}
	if cfg.LogLines > maxLogLines {
		cfg.LogLines = maxLogLines
	}
	if cfg.HealthCheck.IntervalMs > 0 && cfg.HealthCheck.IntervalMs < minHealthIntervalMs {
		cfg.HealthCheck.IntervalMs = minHealthIntervalMs
	}
	if cfg.Args == nil {
		cfg.Args = []string{}
	}
	if cfg.Env == nil {
		cfg.Env = map[string]string{}
	}
	cfg.Args = append([]string(nil), cfg.Args...)
	clonedEnv := make(map[string]string, len(cfg.Env))
	for k, v := range cfg.Env {
		clonedEnv[k] = v
	}
	cfg.Env = clonedEnv
	return cfg
}

func NewManager() *Manager {
	return &Manager{
		instances:        make(map[string]*instance),
		eventSubscribers: make(map[chan Event]struct{}),
	}
}

func (m *Manager) Add(name string, cfg Config) error {
	if name == "" {
		return errors.New("instance name is required")
	}
	if cfg.Binary == "" {
		return errors.New("instance binary is required")
	}
	cfg = normalizeConfig(name, cfg)

	m.mu.Lock()
	if _, exists := m.instances[name]; exists {
		m.mu.Unlock()
		return fmt.Errorf("instance %s already exists", name)
	}
	m.instances[name] = &instance{
		cfg:            cfg,
		logs:           newRingBuffer(cfg.LogLines),
		logSubscribers: make(map[chan LogEntry]struct{}),
		runtimeStats:   make(map[string]string),
	}
	m.mu.Unlock()

	m.publishEvent(Event{Type: "added", Name: name, At: time.Now()})
	return nil
}

func (m *Manager) Update(name string, cfg Config) error {
	if name == "" {
		return errors.New("instance name is required")
	}
	if cfg.Binary == "" {
		return errors.New("instance binary is required")
	}

	inst, err := m.getInstance(name)
	if err != nil {
		return err
	}

	wasRunning := instRunning(inst)
	if wasRunning {
		if err := m.stopInstance(inst); err != nil {
			return fmt.Errorf("stop instance %s before update: %w", name, err)
		}
	}

	nextCfg := normalizeConfig(name, cfg)
	inst.mu.Lock()
	inst.cfg = nextCfg
	inst.mu.Unlock()

	inst.logMu.Lock()
	inst.logs = newRingBuffer(nextCfg.LogLines)
	inst.logMu.Unlock()

	if wasRunning {
		if err := m.startInstance(inst, true); err != nil {
			return fmt.Errorf("restart instance %s after update: %w", name, err)
		}
	}

	m.publishEvent(Event{Type: "updated", Name: name, At: time.Now()})
	return nil
}

func (m *Manager) Remove(name string) error {
	inst, err := m.getInstance(name)
	if err != nil {
		return err
	}
	if instRunning(inst) {
		if err := m.stopInstance(inst); err != nil {
			return fmt.Errorf("stop instance %s before remove: %w", name, err)
		}
	}

	m.mu.Lock()
	delete(m.instances, name)
	m.mu.Unlock()

	m.publishEvent(Event{Type: "removed", Name: name, At: time.Now()})
	return nil
}

func (m *Manager) Start(name string) error {
	inst, err := m.getInstance(name)
	if err != nil {
		return err
	}
	return m.startInstance(inst, false)
}

func (m *Manager) Stop(name string) error {
	inst, err := m.getInstance(name)
	if err != nil {
		return err
	}
	return m.stopInstance(inst)
}

func (m *Manager) Restart(name string) error {
	inst, err := m.getInstance(name)
	if err != nil {
		return err
	}
	if err := m.stopInstance(inst); err != nil {
		return err
	}
	return m.startInstance(inst, true)
}

func (m *Manager) Status(name string) (*StatusResponse, error) {
	inst, err := m.getInstance(name)
	if err != nil {
		return nil, err
	}
	return snapshotStatus(name, inst), nil
}

func (m *Manager) List() []*StatusResponse {
	m.mu.RLock()
	list := make([]*StatusResponse, 0, len(m.instances))
	for name, inst := range m.instances {
		list = append(list, snapshotStatus(name, inst))
	}
	m.mu.RUnlock()
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

func (m *Manager) ListConfigs() []Config {
	m.mu.RLock()
	list := make([]Config, 0, len(m.instances))
	for name, inst := range m.instances {
		inst.mu.RLock()
		cfg := normalizeConfig(name, inst.cfg)
		inst.mu.RUnlock()
		list = append(list, cfg)
	}
	m.mu.RUnlock()
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

func (m *Manager) Logs(name string, stream string, n int) []LogEntry {
	inst, err := m.getInstance(name)
	if err != nil {
		return nil
	}
	inst.logMu.RLock()
	defer inst.logMu.RUnlock()
	return inst.logs.list(n, stream)
}

func (m *Manager) LogSubscribe(name string) (<-chan LogEntry, func(), error) {
	inst, err := m.getInstance(name)
	if err != nil {
		return nil, nil, err
	}
	ch := make(chan LogEntry, 100)
	inst.logMu.Lock()
	inst.logSubscribers[ch] = struct{}{}
	inst.logMu.Unlock()

	unsubscribe := func() {
		inst.logMu.Lock()
		if _, ok := inst.logSubscribers[ch]; ok {
			delete(inst.logSubscribers, ch)
			close(ch)
		}
		inst.logMu.Unlock()
	}
	return ch, unsubscribe, nil
}

func (m *Manager) EventSubscribe() (<-chan Event, func()) {
	ch := make(chan Event, 100)
	m.mu.Lock()
	m.eventSubscribers[ch] = struct{}{}
	m.mu.Unlock()

	unsubscribe := func() {
		m.mu.Lock()
		if _, ok := m.eventSubscribers[ch]; ok {
			delete(m.eventSubscribers, ch)
			close(ch)
		}
		m.mu.Unlock()
	}
	return ch, unsubscribe
}

func (m *Manager) Shutdown() {
	m.mu.Lock()
	m.shuttingDown = true
	instances := make([]*instance, 0, len(m.instances))
	for _, inst := range m.instances {
		instances = append(instances, inst)
	}
	for ch := range m.eventSubscribers {
		close(ch)
		delete(m.eventSubscribers, ch)
	}
	m.mu.Unlock()

	for _, inst := range instances {
		inst.mu.Lock()
		inst.shutdown = true
		inst.mu.Unlock()
		_ = m.stopInstance(inst)
		inst.logMu.Lock()
		for ch := range inst.logSubscribers {
			close(ch)
			delete(inst.logSubscribers, ch)
		}
		inst.logMu.Unlock()
	}
}

func (m *Manager) getInstance(name string) (*instance, error) {
	m.mu.RLock()
	inst, ok := m.instances[name]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("instance %s not found", name)
	}
	return inst, nil
}

func (m *Manager) startInstance(inst *instance, isRestart bool) error {
	inst.mu.Lock()
	if inst.running {
		inst.mu.Unlock()
		return nil
	}
	inst.manualStop = false
	binary := inst.cfg.Binary
	if !strings.Contains(binary, "/") && !strings.Contains(binary, "\\") {
		if abs, err := filepath.Abs(binary); err == nil {
			binary = abs
		}
	}
	cmd := exec.Command(binary, inst.cfg.Args...)
	cmd.Dir = inst.cfg.WorkDir
	cmd.Env = mergeEnv(inst.cfg.Env)
	cmd.SysProcAttr = procAttrForPTY(0)

	var ptyMaster *os.File
	master, slave, err := openPty()
	if err != nil {
		inst.mu.Unlock()
		return err
	}
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	ptyMaster = master
	defer func() { slave.Close() }()

	if err := cmd.Start(); err != nil {
		_ = master.Close()
		inst.mu.Unlock()
		return err
	}
	now := time.Now()
	inst.cmd = cmd
	inst.running = true
	inst.pid = cmd.Process.Pid
	inst.startedAt = &now
	inst.stoppedAt = nil
	if !isRestart && shouldResetRestartWindow(inst) {
		inst.restartCount = 0
	}
	inst.restartWindowAt = now
	inst.mu.Unlock()

	// Inject startup log entry so user sees at least one line
	mode := "PTY"
	if inst.cfg.TUIEnabled {
		mode = "TUI"
	}
	startupEntry := LogEntry{
		At: now, Stream: "guardian",
		Text: fmt.Sprintf("Instance '%s' started (PID: %d, mode: %s)", inst.cfg.Name, inst.pid, mode),
	}
	inst.logMu.Lock()
	inst.logs.add(startupEntry)
	inst.logMu.Unlock()

	m.StartHealthCheck(inst.cfg.Name)
	m.publishEvent(Event{Type: eventType(isRestart, "restarted", "started"), Name: inst.cfg.Name, At: now})
	if ptyMaster != nil {
		go m.capturePty(inst, ptyMaster)
		go m.waitForExit(inst)
	}
	return nil
}

func (m *Manager) stopInstance(inst *instance) error {
	inst.mu.Lock()
	if !inst.running || inst.cmd == nil || inst.cmd.Process == nil {
		inst.mu.Unlock()
		return nil
	}
	inst.manualStop = true
	cmd := inst.cmd
	stopSignal := inst.cfg.StopSignal
	waitMs := inst.cfg.StopWaitMs
	inst.mu.Unlock()

	sig := signalFromName(stopSignal)
	if sig != 0 {
		_ = killProcessGroup(cmd.Process.Pid, sig) // signal entire process group
	}

	deadline := time.Now().Add(time.Duration(waitMs) * time.Millisecond)
	for time.Now().Before(deadline) {
		inst.mu.RLock()
		running := inst.running
		inst.mu.RUnlock()
		if !running {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	inst.mu.RLock()
	stillRunning := inst.running
	process := cmd.Process
	inst.mu.RUnlock()
	if stillRunning && process != nil {
		_ = forceKillProcessGroup(process.Pid) // force kill process group
	}
	return nil
}

func (m *Manager) waitForExit(inst *instance) {
	inst.mu.RLock()
	cmd := inst.cmd
	inst.mu.RUnlock()
	if cmd == nil {
		return
	}

	err := cmd.Wait()
	now := time.Now()
	exit := ExitState{At: now}
	if err == nil {
		exit.Success = true
	} else {
		exit.Error = err.Error()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exit.Code = exitErr.ExitCode()
		} else {
			exit.Code = -1
		}
	}

	inst.mu.Lock()
	inst.running = false
	inst.pid = 0
	inst.cmd = nil
	inst.stoppedAt = &now
	inst.lastExit = &exit
	manualStop := inst.manualStop
	allowRestart := inst.cfg.AutoRestart.Enabled && !inst.shutdown && !manualStop
	if allowRestart {
		inst.restartCount++
	}
	hc := inst.healthCheck
	inst.healthCheck = nil
	retries := inst.restartCount
	maxRetries := inst.cfg.AutoRestart.MaxRetries
	retryDelay := inst.cfg.AutoRestart.RetryDelayMs
	inst.mu.Unlock()
	stopHealthChecker(hc)

	m.publishEvent(Event{Type: "stopped", Name: inst.cfg.Name, At: now, Message: exit.Error})
	if err != nil {
		log.Printf("instance %s exited: %v", inst.cfg.Name, err)
	}

	if allowRestart {
		if maxRetries > 0 && retries > maxRetries {
			m.publishEvent(Event{Type: "restart_exhausted", Name: inst.cfg.Name, At: time.Now()})
			return
		}
		if retryDelay > 0 {
			time.Sleep(time.Duration(retryDelay) * time.Millisecond)
		}
		if startErr := m.startInstance(inst, true); startErr != nil {
			m.publishEvent(Event{Type: "restart_failed", Name: inst.cfg.Name, At: time.Now(), Message: startErr.Error()})
		}
	}
}

func (m *Manager) captureLogs(inst *instance, stream string, reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		entry := LogEntry{At: time.Now(), Stream: stream, Text: scanner.Text()}
		inst.logMu.Lock()
		inst.logs.add(entry)
		for ch := range inst.logSubscribers {
			select {
			case ch <- entry:
			default:
			}
		}
		inst.logMu.Unlock()
	}
	if err := scanner.Err(); err != nil {
		log.Printf("instance %s %s log read error: %v", inst.cfg.Name, stream, err)
	}
}

func (m *Manager) capturePipeLog(inst *instance, stream string, reader io.ReadCloser) {
	defer reader.Close()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 128*1024), 2*1024*1024)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		entry := LogEntry{At: time.Now(), Stream: stream, Text: text}
		inst.logMu.Lock()
		inst.logs.add(entry)
		for ch := range inst.logSubscribers {
			select {
			case ch <- entry:
			default:
			}
		}
		inst.logMu.Unlock()
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		log.Printf("instance %s %s read error: %v", inst.cfg.Name, stream, err)
	}
}

func (m *Manager) capturePty(inst *instance, reader io.ReadCloser) {
	defer func() {
		if err := reader.Close(); err != nil {
			log.Printf("instance %s pty close error: %v", inst.cfg.Name, err)
		}
	}()

	// Exact-match keys (lowercase) for ppp TUI info lines.
	statsKeys := map[string]bool{
		"duration": true, "sessions": true, "tx": true, "rx": true,
		"in": true, "out": true, "max concurrent": true,
		"public ip": true, "interface ip": true,
		"hosting environment": true, "process": true,
		"application": true, "template": true, "mode": true, "cwd": true, "config": true,
		"triplet":        true,
		"managed server": true, "vpn server": true,
		"http proxy": true, "socks proxy": true,
		"p/a controller": true,
		"name":           true, "index": true, "interface": true,
		"aggligator": true, "proxy interlayer": true,
		"tcp/ip cc": true, "block quic": true,
		"mux state": true, "link state": true,
	}

	// isStatsKey returns true if the key should be captured as a runtime stat.
	// Handles both exact matches and dynamic prefixes like "Service 1", "DNS Server 2".
	isStatsKey := func(key string) bool {
		lower := strings.ToLower(key)
		if statsKeys[lower] {
			return true
		}
		// Dynamic keys: "Service N" (up to 9 services), "DNS Server N"
		if strings.HasPrefix(lower, "service ") || strings.HasPrefix(lower, "dns server ") {
			return true
		}
		return false
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 256*1024), 8*1024*1024)

	lastLine := ""
	for scanner.Scan() {
		raw := scanner.Text()
		clean := StripANSI(raw)
		if clean == "" || clean == lastLine {
			continue
		}

		// Parse structured stats from ppp TUI lines
		if idx := strings.Index(clean, ":"); idx > 0 {
			left := clean[:idx]
			right := clean[idx+1:]

			// Remove box chars and trim
			key := stripBox(left)
			val := stripBox(right)
			key = strings.TrimSpace(key)
			val = strings.TrimSpace(val)

			if key != "" && val != "" && isStatsKey(key) {
				lastLine = clean
				inst.logMu.Lock()
				if inst.runtimeStats == nil {
					inst.runtimeStats = make(map[string]string)
				}
				inst.runtimeStats[strings.ToLower(key)] = val
				inst.logMu.Unlock()
				continue // don't add stats lines to log buffer
			}
		}

		// Skip TUI noise (borders, hints, empty lines, ASCII art, section headers)
		trimmed := strings.TrimSpace(clean)
		if trimmed == "" || strings.HasPrefix(trimmed, "─") || strings.HasPrefix(trimmed, "┌") ||
			strings.HasPrefix(trimmed, "└") || strings.HasPrefix(trimmed, "├") ||
			strings.HasPrefix(trimmed, "┤") || strings.HasPrefix(trimmed, "┬") ||
			strings.HasPrefix(trimmed, "┴") || strings.Contains(trimmed, "PageUp") ||
			strings.Contains(trimmed, "Home/End") || strings.Contains(trimmed, "___") ||
			strings.Contains(trimmed, "/ _") || strings.Contains(trimmed, "| | |") ||
			strings.Contains(trimmed, "| |_|") || strings.Contains(trimmed, "\\___/") ||
			strings.Contains(trimmed, "Console UI started") ||
			strings.Contains(trimmed, "Exec openppp") ||
			strings.Contains(trimmed, "PPP PRIVATE NETWORK") ||
			trimmed == "VPN" || trimmed == "TUN" || trimmed == "NIC" {
			continue
		}

		lastLine = clean
		entry := LogEntry{At: time.Now(), Stream: "stdout", Text: clean}
		inst.logMu.Lock()
		inst.logs.add(entry)
		for ch := range inst.logSubscribers {
			select {
			case ch <- entry:
			default:
			}
		}
		inst.logMu.Unlock()
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, io.EOF) {
		log.Printf("instance %s pty read error: %v", inst.cfg.Name, err)
	}
}

func stripBox(s string) string {
	s = strings.ReplaceAll(s, "│", "")
	s = strings.ReplaceAll(s, "─", "")
	s = strings.ReplaceAll(s, "┌", "")
	s = strings.ReplaceAll(s, "┐", "")
	s = strings.ReplaceAll(s, "└", "")
	s = strings.ReplaceAll(s, "┘", "")
	s = strings.ReplaceAll(s, "├", "")
	s = strings.ReplaceAll(s, "┤", "")
	return s
}

func (m *Manager) publishEvent(event Event) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for ch := range m.eventSubscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

func snapshotStatus(name string, inst *instance) *StatusResponse {
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	var lastExit *ExitState
	if inst.lastExit != nil {
		copyExit := *inst.lastExit
		lastExit = &copyExit
	}
	args := append([]string(nil), inst.cfg.Args...)
	stats := make(map[string]string)
	inst.logMu.RLock()
	for k, v := range inst.runtimeStats {
		stats[k] = v
	}
	inst.logMu.RUnlock()
	return &StatusResponse{
		Name:         name,
		Running:      inst.running,
		PID:          inst.pid,
		StartedAt:    inst.startedAt,
		StoppedAt:    inst.stoppedAt,
		Binary:       inst.cfg.Binary,
		WorkDir:      inst.cfg.WorkDir,
		ConfigPath:   inst.cfg.ConfigPath,
		Args:         args,
		LastExit:     lastExit,
		AutoRestart:  inst.cfg.AutoRestart.Enabled,
		RestartCount: inst.restartCount,
		RuntimeStats: stats,
	}
}

func mergeEnv(extra map[string]string) []string {
	env := os.Environ()
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	return env
}

func instRunning(inst *instance) bool {
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	return inst.running
}

func shouldResetRestartWindow(inst *instance) bool {
	if inst.cfg.AutoRestart.ResetAfterMs <= 0 {
		return false
	}
	if inst.restartWindowAt.IsZero() {
		return true
	}
	return time.Since(inst.restartWindowAt) > time.Duration(inst.cfg.AutoRestart.ResetAfterMs)*time.Millisecond
}

func eventType(isRestart bool, restartType, defaultType string) string {
	if isRestart {
		return restartType
	}
	return defaultType
}
