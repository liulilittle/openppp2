package api

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"ppp/guardian/auth"
	"ppp/guardian/binary"
	"ppp/guardian/instance"
	"ppp/guardian/profile"
)

type GuardianServerConfig struct {
	AuthEnabled      bool
	JWTSecret        string
	TokenExpiryHours int
	LogLines         int
	ServiceName      string
	GuardianBinary   string
	GuardianWorkDir  string
	OnConfigChanged  func() error
	OnAuthChanged    func(enabled bool, jwtSecret string) error
}

type Server struct {
	listenAddr  string
	instanceMgr *instance.Manager
	profileMgr  *profile.Manager
	binaryMgr   *binary.Manager
	httpServer  *http.Server
	wsHub       *WSHub
	authMu      sync.RWMutex // guards jwtSecret and authCfg.AuthEnabled/JWTSecret
	authCfg     GuardianServerConfig
	jwtSecret   string
	limiter     *authLimiter
	tokenStore  *auth.TokenStore
	startedAt   time.Time
	logger      *slog.Logger
	webuiFS     fs.FS
}

func NewServer(listenAddr string, instanceMgr *instance.Manager, profileMgr *profile.Manager, binaryMgr *binary.Manager, guardianCfg *GuardianServerConfig, webuiFS fs.FS) *Server {
	cfg := GuardianServerConfig{TokenExpiryHours: 24, LogLines: 200}
	if guardianCfg != nil {
		cfg = *guardianCfg
		if cfg.TokenExpiryHours <= 0 {
			cfg.TokenExpiryHours = 24
		}
		if cfg.LogLines <= 0 {
			cfg.LogLines = 200
		}
	}

	s := &Server{
		listenAddr:  listenAddr,
		instanceMgr: instanceMgr,
		profileMgr:  profileMgr,
		binaryMgr:   binaryMgr,
		authCfg:     cfg,
		jwtSecret:   cfg.JWTSecret,
		tokenStore:  auth.NewTokenStore(),
		limiter:     newAuthLimiter(),
		startedAt:   time.Now(),
		logger:      slog.Default(),
		webuiFS:     webuiFS,
	}
	s.wsHub = NewWSHub(instanceMgr, slog.Default())
	s.httpServer = &http.Server{
		Addr:              listenAddr,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	s.registerRoutes()
	return s
}

func (s *Server) Start() error {
	s.logger.Info("guardian api server starting", "addr", s.listenAddr)
	err := s.httpServer.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("guardian api server shutting down")
	return s.httpServer.Shutdown(ctx)
}
