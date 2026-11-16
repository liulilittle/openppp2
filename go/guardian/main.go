package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"ppp/guardian/api"
)

func main() {
	configPath := flag.String("config", "guardian.json", "path to guardian config")
	flag.Parse()
	resolvedConfigPath, err := filepath.Abs(*configPath)
	if err != nil {
		log.Fatalf("resolve config path failed: %v", err)
	}

	cfg, err := LoadConfig(resolvedConfigPath)
	if err != nil {
		log.Fatalf("load config failed: %v", err)
	}

	if err := checkListenSecurity(cfg); err != nil {
		log.Fatalf("%v", err)
	}

	if cfg.GeneratedJWTSecret {
		if err := SaveConfigFile(resolvedConfigPath, cfg); err != nil {
			log.Fatalf("persist generated auth secret failed: %v", err)
		}
		log.Printf("guardian generated and persisted an auth jwtSecret in %s", resolvedConfigPath)
	}

	guardian, err := NewGuardian(cfg, resolvedConfigPath)
	if err != nil {
		log.Fatalf("create guardian failed: %v", err)
	}

	execPath, _ := os.Executable()
	workDir, _ := os.Getwd()
	serverCfg := &api.GuardianServerConfig{
		AuthEnabled:      cfg.Auth.Enabled,
		JWTSecret:        cfg.Auth.JWTSecret,
		TokenExpiryHours: cfg.Auth.TokenExpiryHours,
		LogLines:         cfg.LogLines,
		ServiceName:      "openppp2-guardian",
		GuardianBinary:   execPath,
		GuardianWorkDir:  workDir,
		OnConfigChanged:  guardian.SaveConfig,
		OnAuthChanged:    guardian.UpdateAuthConfig,
	}
	server := api.NewServer(cfg.Listen, guardian.InstanceManager(), guardian.ProfileManager(), guardian.BinaryManager(), serverCfg, webuiFS)

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("guardian api server listening on %s", cfg.Listen)
		if err := server.Start(); err != nil {
			log.Printf("api server stopped: %v", err)
		}
	}()

	guardian.Start()

	log.Printf("guardian ready on %s (Ctrl+C to stop)", cfg.Listen)

	<-sigCh
	log.Printf("guardian shutting down (Ctrl+C again to force quit)")

	done := make(chan struct{})
	go func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		guardian.Shutdown()
		_ = server.Shutdown(shutdownCtx)
		close(done)
	}()

	select {
	case <-done:
		log.Printf("guardian stopped")
	case <-sigCh:
		log.Printf("force quit")
	}
}
