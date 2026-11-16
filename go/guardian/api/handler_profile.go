package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

type profileContentRequest struct {
	Content string `json:"content"`
}

func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.profileMgr.List()
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	Success(w, profiles)
}

func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	p, err := s.profileMgr.Get(r.PathValue("name"))
	if err != nil {
		Error(w, http.StatusNotFound, err.Error())
		return
	}
	Success(w, p)
}

func (s *Server) handleSaveProfile(w http.ResponseWriter, r *http.Request) {
	content, err := readProfileBody(r)
	if err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.profileMgr.Save(r.PathValue("name"), content); err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	profile, err := s.profileMgr.Get(r.PathValue("name"))
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	Success(w, profile)
}

func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	if err := s.profileMgr.Delete(r.PathValue("name")); err != nil {
		Error(w, http.StatusNotFound, err.Error())
		return
	}
	Success(w, map[string]bool{"deleted": true})
}

func (s *Server) handleValidateProfile(w http.ResponseWriter, r *http.Request) {
	content, err := readProfileBody(r)
	if err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.profileMgr.Validate(content); err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	Success(w, map[string]bool{"valid": true})
}

func (s *Server) handleProfileBackups(w http.ResponseWriter, r *http.Request) {
	items, err := s.profileMgr.Backups(r.PathValue("name"))
	if err != nil {
		Error(w, http.StatusNotFound, err.Error())
		return
	}
	Success(w, items)
}

func (s *Server) handleRestoreProfile(w http.ResponseWriter, r *http.Request) {
	if err := s.profileMgr.Restore(r.PathValue("name"), r.PathValue("backupId")); err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	profile, err := s.profileMgr.Get(r.PathValue("name"))
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	Success(w, profile)
}

func readProfileBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(body)) == "" {
		return nil, errors.New("profile request body is empty")
	}
	var req profileContentRequest
	if err := json.Unmarshal(body, &req); err == nil && req.Content != "" {
		return []byte(req.Content), nil
	}
	return body, nil
}
