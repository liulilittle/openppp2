package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"ppp/guardian/auth"
	"ppp/guardian/instance"
)

type WSHub struct {
	instanceMgr *instance.Manager
	logger      *slog.Logger
}

func NewWSHub(instanceMgr *instance.Manager, logger *slog.Logger) *WSHub {
	if logger == nil {
		logger = slog.Default()
	}
	return &WSHub{instanceMgr: instanceMgr, logger: logger}
}

func (s *Server) handleWSLogs(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeStream(r) {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	name := r.PathValue("name")
	ch, unsubscribe, err := s.instanceMgr.LogSubscribe(name)
	if err != nil {
		Error(w, http.StatusNotFound, err.Error())
		return
	}
	defer unsubscribe()
	s.streamSSE(w, r, ch)
}

func (s *Server) handleWSEvents(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeStream(r) {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	ch, unsubscribe := s.instanceMgr.EventSubscribe()
	defer unsubscribe()
	s.streamSSE(w, r, ch)
}

func (s *Server) authorizeStream(r *http.Request) bool {
	enabled, secret := s.authState()
	if !enabled {
		return true
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		token = bearerToken(r.Header.Get("Authorization"))
	}
	if token == "" || !s.tokenStore.Validate(token) {
		return false
	}
	_, err := auth.ValidateToken(token, secret)
	return err == nil
}

func (s *Server) streamSSE(w http.ResponseWriter, r *http.Request, ch any) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		Error(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	rc := http.NewResponseController(w)
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	switch stream := ch.(type) {
	case <-chan instance.LogEntry:
		for {
			select {
			case <-r.Context().Done():
				return
			case <-heartbeat.C:
				if !s.writeSSEHeartbeat(w, flusher, rc) {
					return
				}
			case msg, ok := <-stream:
				if !ok {
					return
				}
				if !s.writeSSEData(w, flusher, rc, msg) {
					return
				}
			}
		}
	case <-chan instance.Event:
		for {
			select {
			case <-r.Context().Done():
				return
			case <-heartbeat.C:
				if !s.writeSSEHeartbeat(w, flusher, rc) {
					return
				}
			case msg, ok := <-stream:
				if !ok {
					return
				}
				if !s.writeSSEData(w, flusher, rc, msg) {
					return
				}
			}
		}
	default:
		Error(w, http.StatusInternalServerError, "unsupported stream type")
	}
}

func (s *Server) writeSSEData(w http.ResponseWriter, flusher http.Flusher, rc *http.ResponseController, msg any) bool {
	payload, err := json.Marshal(msg)
	if err != nil {
		s.logger.Error("marshal sse payload", "error", err)
		return true
	}
	setSSEWriteDeadline(rc)
	if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
		return false
	}
	flusher.Flush()
	clearSSEWriteDeadline(rc)
	return true
}

func (s *Server) writeSSEHeartbeat(w http.ResponseWriter, flusher http.Flusher, rc *http.ResponseController) bool {
	setSSEWriteDeadline(rc)
	if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
		return false
	}
	flusher.Flush()
	clearSSEWriteDeadline(rc)
	return true
}

func setSSEWriteDeadline(rc *http.ResponseController) {
	if rc == nil {
		return
	}
	_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
}

func clearSSEWriteDeadline(rc *http.ResponseController) {
	if rc == nil {
		return
	}
	_ = rc.SetWriteDeadline(time.Time{})
}
