package api

import (
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"

	"ppp/guardian/service"
)

func (s *Server) handleServiceStatus(w http.ResponseWriter, r *http.Request) {
	serviceName := strings.TrimSpace(s.authCfg.ServiceName)
	if serviceName == "" {
		serviceName = "openppp2-guardian"
	}
	Success(w, service.GetStatus(serviceName))
}

func (s *Server) handleServiceInstall(w http.ResponseWriter, r *http.Request) {
	if runtime.GOOS != "linux" {
		Error(w, http.StatusNotImplemented, "service installation is only supported on Linux with systemd")
		return
	}
	serviceName := strings.TrimSpace(s.authCfg.ServiceName)
	if serviceName == "" {
		serviceName = "openppp2-guardian"
	}
	if strings.TrimSpace(s.authCfg.GuardianBinary) == "" {
		Error(w, http.StatusBadRequest, "guardian binary path is not configured")
		return
	}
	if strings.TrimSpace(s.authCfg.GuardianWorkDir) == "" {
		Error(w, http.StatusBadRequest, "guardian working directory is not configured")
		return
	}

	execStart := fmt.Sprintf("%s -config guardian.json", strconv.Quote(s.authCfg.GuardianBinary))
	if err := service.InstallSystemd(service.SystemdConfig{
		ServiceName: serviceName,
		Description: "OpenPPP2 Guardian Daemon",
		ExecStart:   execStart,
		WorkingDir:  s.authCfg.GuardianWorkDir,
	}); err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	Success(w, map[string]any{"ok": true, "serviceName": serviceName})
}

func (s *Server) handleServiceUninstall(w http.ResponseWriter, r *http.Request) {
	if runtime.GOOS != "linux" {
		Error(w, http.StatusNotImplemented, "service uninstallation is only supported on Linux with systemd")
		return
	}
	serviceName := strings.TrimSpace(s.authCfg.ServiceName)
	if serviceName == "" {
		serviceName = "openppp2-guardian"
	}
	if err := service.UninstallSystemd(serviceName); err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	Success(w, map[string]any{"ok": true, "serviceName": serviceName})
}
