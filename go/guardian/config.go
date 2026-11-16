package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

type GuardianConfig struct {
	Listen             string           `json:"listen"`
	Auth               AuthConfig       `json:"auth"`
	Instances          []InstanceConfig `json:"instances"`
	ProfilesDir        string           `json:"profilesDir"`
	BinariesDir        string           `json:"binariesDir"`
	Backup             BackupConfig     `json:"backup"`
	LogLines           int              `json:"logLines"`
	GeneratedJWTSecret bool             `json:"-"`
}

type AuthConfig struct {
	Enabled          bool   `json:"enabled"`
	JWTSecret        string `json:"jwtSecret"`
	TokenExpiryHours int    `json:"tokenExpiryHours"`
}

type InstanceConfig struct {
	Name        string            `json:"name"`
	Enabled     bool              `json:"enabled"`
	Binary      string            `json:"binary"`
	WorkDir     string            `json:"workDir"`
	ConfigPath  string            `json:"configPath"`
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env"`
	StopSignal  string            `json:"stopSignal"`
	StopWaitMs  int               `json:"stopWaitMs"`
	AutoRestart AutoRestartConfig `json:"autoRestart"`
	HealthCheck HealthCheckConfig `json:"healthCheck"`
	LogLines    int               `json:"logLines"`
	TUIEnabled  bool              `json:"tuiEnabled"`
}

type AutoRestartConfig struct {
	Enabled      bool `json:"enabled"`
	MaxRetries   int  `json:"maxRetries"`
	RetryDelayMs int  `json:"retryDelayMs"`
	ResetAfterMs int  `json:"resetAfterMs"`
}

type HealthCheckConfig struct {
	Enabled      bool   `json:"enabled"`
	IntervalMs   int    `json:"intervalMs"`
	TCPPort      int    `json:"tcpPort"`
	HTTPEndpoint string `json:"httpEndpoint"`
}

type BackupConfig struct {
	Enabled    bool   `json:"enabled"`
	MaxBackups int    `json:"maxBackups"`
	Dir        string `json:"dir"`
}

func DefaultConfig() *GuardianConfig {
	return &GuardianConfig{
		Listen:      "127.0.0.1:18080",
		ProfilesDir: "./profiles",
		BinariesDir: "./binaries",
		Backup: BackupConfig{
			Enabled:    true,
			MaxBackups: 10,
			Dir:        "./backups",
		},
		LogLines: 2000,
		Auth: AuthConfig{
			Enabled:          true,
			TokenExpiryHours: 24,
		},
	}
}

// checkListenSecurity refuses to expose the management API on a non-loopback
// address while authentication is disabled.
func checkListenSecurity(cfg *GuardianConfig) error {
	if cfg.Auth.Enabled {
		return nil
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		host = cfg.Listen
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing to listen on %q with auth.enabled=false; enable auth or bind to a loopback address", cfg.Listen)
}

func ensureAuthSecret(cfg *GuardianConfig) error {
	if cfg == nil || !cfg.Auth.Enabled || cfg.Auth.JWTSecret != "" {
		return nil
	}
	secret, err := generateJWTSecret()
	if err != nil {
		return fmt.Errorf("generate auth jwtSecret: %w", err)
	}
	cfg.Auth.JWTSecret = secret
	cfg.GeneratedJWTSecret = true
	return nil
}

func generateJWTSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func defaultInstanceConfig(global *GuardianConfig) InstanceConfig {
	return InstanceConfig{
		Enabled:    true,
		StopSignal: "interrupt",
		StopWaitMs: 5000,
		LogLines:   global.LogLines,
		Args:       []string{},
		Env:        map[string]string{},
		AutoRestart: AutoRestartConfig{
			Enabled:      false,
			MaxRetries:   3,
			RetryDelayMs: 3000,
			ResetAfterMs: 60000,
		},
		HealthCheck: HealthCheckConfig{
			Enabled:    false,
			IntervalMs: 5000,
		},
	}
}

func SaveConfigFile(path string, cfg *GuardianConfig) error {
	if path == "" {
		return fmt.Errorf("guardian config path is empty")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal guardian config: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return fmt.Errorf("ensure config directory: %w", err)
	}
	if err := writeConfigFile0600(absPath, data); err != nil {
		return fmt.Errorf("write guardian config: %w", err)
	}
	return nil
}

func writeConfigFile0600(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func LoadConfig(path string) (*GuardianConfig, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			// First run — use defaults, write config for future edits
			cfg := DefaultConfig()
			if err := ensureAuthSecret(cfg); err != nil {
				return nil, err
			}
			baseDir := filepath.Dir(absPath)
			cfg.ProfilesDir = filepath.Join(baseDir, cfg.ProfilesDir)
			cfg.BinariesDir = filepath.Join(baseDir, cfg.BinariesDir)
			cfg.Backup.Dir = filepath.Join(baseDir, cfg.Backup.Dir)
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	baseDir := filepath.Dir(absPath)
	resolve := func(p string) (string, error) {
		if p == "" {
			return "", nil
		}
		if filepath.IsAbs(p) {
			return filepath.Abs(p)
		}
		return filepath.Abs(filepath.Join(baseDir, p))
	}

	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:18080"
	}
	if cfg.LogLines <= 0 {
		cfg.LogLines = 2000
	}
	if cfg.Auth.TokenExpiryHours <= 0 {
		cfg.Auth.TokenExpiryHours = 24
	}
	if cfg.Backup.MaxBackups <= 0 {
		cfg.Backup.MaxBackups = 10
	}
	if cfg.ProfilesDir == "" {
		cfg.ProfilesDir = "./profiles"
	}
	if cfg.BinariesDir == "" {
		cfg.BinariesDir = "./binaries"
	}
	if cfg.Backup.Dir == "" {
		cfg.Backup.Dir = "./backups"
	}
	if err := ensureAuthSecret(cfg); err != nil {
		return nil, err
	}

	if cfg.ProfilesDir, err = resolve(cfg.ProfilesDir); err != nil {
		return nil, fmt.Errorf("resolve profilesDir: %w", err)
	}
	if cfg.BinariesDir, err = resolve(cfg.BinariesDir); err != nil {
		return nil, fmt.Errorf("resolve binariesDir: %w", err)
	}
	if cfg.Backup.Dir, err = resolve(cfg.Backup.Dir); err != nil {
		return nil, fmt.Errorf("resolve backup dir: %w", err)
	}

	for i := range cfg.Instances {
		merged := defaultInstanceConfig(cfg)
		current := cfg.Instances[i]

		if current.Name != "" {
			merged.Name = current.Name
		}
		merged.Enabled = current.Enabled
		if current.Binary != "" {
			merged.Binary = current.Binary
		}
		if current.WorkDir != "" {
			merged.WorkDir = current.WorkDir
		}
		if current.ConfigPath != "" {
			merged.ConfigPath = current.ConfigPath
		}
		if current.Args != nil {
			merged.Args = current.Args
		}
		if current.Env != nil {
			merged.Env = current.Env
		}
		if current.StopSignal != "" {
			merged.StopSignal = current.StopSignal
		}
		if current.StopWaitMs > 0 {
			merged.StopWaitMs = current.StopWaitMs
		}
		merged.AutoRestart = mergedAutoRestart(merged.AutoRestart, current.AutoRestart)
		merged.HealthCheck = mergedHealthCheck(merged.HealthCheck, current.HealthCheck)
		if current.LogLines > 0 {
			merged.LogLines = current.LogLines
		}
		merged.TUIEnabled = current.TUIEnabled

		if merged.Binary, err = resolve(merged.Binary); err != nil {
			return nil, fmt.Errorf("resolve instance %s binary: %w", merged.Name, err)
		}
		if merged.WorkDir == "" {
			merged.WorkDir = baseDir
		}
		if merged.WorkDir, err = resolve(merged.WorkDir); err != nil {
			return nil, fmt.Errorf("resolve instance %s workDir: %w", merged.Name, err)
		}
		if merged.ConfigPath, err = resolve(merged.ConfigPath); err != nil {
			return nil, fmt.Errorf("resolve instance %s configPath: %w", merged.Name, err)
		}

		cfg.Instances[i] = merged
	}

	return cfg, nil
}

func mergedAutoRestart(base, override AutoRestartConfig) AutoRestartConfig {
	base.Enabled = override.Enabled
	if override.MaxRetries > 0 {
		base.MaxRetries = override.MaxRetries
	}
	if override.RetryDelayMs > 0 {
		base.RetryDelayMs = override.RetryDelayMs
	}
	if override.ResetAfterMs > 0 {
		base.ResetAfterMs = override.ResetAfterMs
	}
	return base
}

func mergedHealthCheck(base, override HealthCheckConfig) HealthCheckConfig {
	base.Enabled = override.Enabled
	if override.IntervalMs > 0 {
		base.IntervalMs = override.IntervalMs
	}
	if override.TCPPort > 0 {
		base.TCPPort = override.TCPPort
	}
	if override.HTTPEndpoint != "" {
		base.HTTPEndpoint = override.HTTPEndpoint
	}
	return base
}
