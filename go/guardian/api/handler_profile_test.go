package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ppp/guardian/profile"
)

func TestSaveProfileRejectsEmptyBody(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil, profile.NewManager(t.TempDir(), profile.BackupConfig{}), nil, &GuardianServerConfig{}, nil)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/profiles/test", strings.NewReader(" \n\t"))
	req.SetPathValue("name", "test")
	res := httptest.NewRecorder()

	server.handleSaveProfile(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", res.Code, http.StatusBadRequest, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "profile request body is empty") {
		t.Fatalf("body = %s, want explicit empty-body error", res.Body.String())
	}
}

func TestSaveProfileAcceptsMinimalKnownProfile(t *testing.T) {
	manager := profile.NewManager(t.TempDir(), profile.BackupConfig{})
	server := NewServer("127.0.0.1:0", nil, manager, nil, &GuardianServerConfig{}, nil)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/profiles/test", strings.NewReader(`{"client":{}}`))
	req.SetPathValue("name", "test")
	res := httptest.NewRecorder()

	server.handleSaveProfile(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", res.Code, http.StatusOK, res.Body.String())
	}
	got, err := manager.Get("test")
	if err != nil {
		t.Fatalf("Get(test): %v", err)
	}
	if got.Content != `{"client":{}}` {
		t.Fatalf("saved content = %q, want minimal valid profile", got.Content)
	}
}
