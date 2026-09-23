package ppp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func standaloneAdminHandler(t *testing.T) (http.Handler, *ManagedServer) {
	t.Helper()
	store, err := OpenLocalStore(filepath.Join(t.TempDir(), "manager-data.json"), "admin-secret", "http://subscriptions.example")
	if err != nil {
		t.Fatal(err)
	}
	server := &ManagedServer{
		configuration: &ManagedServerConfiguration{Admin: &AdminConfiguration{Token: "admin-secret", Path: "/admin/", PublicBaseURL: "http://subscriptions.example"}},
		local:         store, nodes: make(map[int]*_vpn_server), servers: make(map[int]*tb_server), users: make(map[string]*_vpn_user), dirty: make(map[string]bool),
	}
	server.admin = server.newAdminHandler()
	return server.admin, server
}

func adminRequest(handler http.Handler, method, target string, body any) *httptest.ResponseRecorder {
	var content *bytes.Reader
	if body == nil {
		content = bytes.NewReader(nil)
	} else {
		data, _ := json.Marshal(body)
		content = bytes.NewReader(data)
	}
	request := httptest.NewRequest(method, target, content)
	request.Header.Set("Authorization", "Bearer admin-secret")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestAdminAuthorization(t *testing.T) {
	server := &ManagedServer{configuration: &ManagedServerConfiguration{Admin: &AdminConfiguration{Token: "admin-secret"}}}

	request := httptest.NewRequest("GET", "/api/v1/status", nil)
	if server.adminAuthorized(request) {
		t.Fatal("request without bearer token was authorized")
	}
	request.Header.Set("Authorization", "Bearer wrong-secret")
	if server.adminAuthorized(request) {
		t.Fatal("request with wrong bearer token was authorized")
	}
	request.Header.Set("Authorization", "Bearer admin-secret")
	if !server.adminAuthorized(request) {
		t.Fatal("request with configured bearer token was rejected")
	}
}

func TestAdminHandlerServesUIAndProtectsAPI(t *testing.T) {
	server := &ManagedServer{configuration: &ManagedServerConfiguration{Admin: &AdminConfiguration{Token: "admin-secret", Path: "/admin/"}}}
	handler := server.newAdminHandler()

	uiRecorder := httptest.NewRecorder()
	handler.ServeHTTP(uiRecorder, httptest.NewRequest("GET", "/admin/", nil))
	if uiRecorder.Code != 200 {
		t.Fatalf("admin UI status = %d", uiRecorder.Code)
	}
	redirectRecorder := httptest.NewRecorder()
	handler.ServeHTTP(redirectRecorder, httptest.NewRequest("GET", "/admin", nil))
	if redirectRecorder.Code != 307 || redirectRecorder.Header().Get("Location") != "/admin/" {
		t.Fatalf("admin redirect = %d %q", redirectRecorder.Code, redirectRecorder.Header().Get("Location"))
	}

	apiRecorder := httptest.NewRecorder()
	handler.ServeHTTP(apiRecorder, httptest.NewRequest("GET", "/api/v1/status", nil))
	if apiRecorder.Code != 401 {
		t.Fatalf("unauthenticated API status = %d", apiRecorder.Code)
	}
}

func TestAdminDialogCancelControlsDoNotSubmit(t *testing.T) {
	data, err := adminWebUI.ReadFile("webui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(data), `type="button" data-dialog-close`); count != 2 {
		t.Fatalf("non-submitting dialog close controls = %d, want 2", count)
	}
}

func TestAdminUIAdaptsToStandaloneMode(t *testing.T) {
	index, err := adminWebUI.ReadFile("webui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	app, err := adminWebUI.ReadFile("webui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), `id="usersNav"`) || !strings.Contains(string(index), `id="serversNav"`) {
		t.Fatal("mode-aware navigation hooks are missing")
	}
	if !strings.Contains(string(app), "state.status?.managed === true") || !strings.Contains(string(app), "订阅节点") {
		t.Fatal("standalone UI mode handling is missing")
	}
}

func TestDecodeAdminJSONRejectsTrailingValue(t *testing.T) {
	request := httptest.NewRequest("POST", "/api/v1/users", strings.NewReader(`{"guid":"one"}{"guid":"two"}`))
	var input adminUserInput
	if err := decodeAdminJSON(request, &input); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
}

func TestNormalizeAdminPath(t *testing.T) {
	tests := map[string]string{"": "/admin/", "console": "/console/", "/ops/../console/": "/console/"}
	for input, want := range tests {
		got, err := normalizeAdminPath(input)
		if err != nil || got != want {
			t.Fatalf("normalizeAdminPath(%q) = %q, %v", input, got, err)
		}
	}
	if _, err := normalizeAdminPath("/ppp/admin"); err == nil {
		t.Fatal("reserved admin path was accepted")
	}
}

func TestServerFromInput(t *testing.T) {
	server, err := serverFromInput(adminServerInput{
		Name: "Hong Kong 01", Link: "ppp://hk.example.com:20000/",
		Protocol: "aes-128-cfb", ProtocolKey: "p", Transport: "aes-256-cfb", TransportKey: "t",
	})
	if err != nil {
		t.Fatal(err)
	}
	if server.Link != "ppp://hk.example.com:20000/" {
		t.Fatalf("link = %q", server.Link)
	}
	if _, err := serverFromInput(adminServerInput{Name: "bad", Link: "https://example.com"}); err == nil {
		t.Fatal("non-ppp server link was accepted")
	}
}

func TestBuildSubscriptionDocument(t *testing.T) {
	item := tb_subscription{Name: "Demo", ProfilePrefix: "Demo", Token: "must-not-leak", UpdatedAt: time.Unix(1_700_000_000, 0).UTC()}
	user := tb_user{Guid: "F4569420-4E49-4CBA-9C36-94E722C8E363"}
	servers := []tb_server{{
		Id: 7, Name: "HK 01", Link: "ppp://hk.example.com:20000/",
		Kf: 154543927, Kx: 128, Kl: 10, Kh: 12,
		Protocol: "aes-128-cfb", ProtocolKey: "p-key", Transport: "aes-256-cfb", TransportKey: "t-key",
	}}

	data, etag, err := buildSubscriptionDocument(item, user, servers, map[string]any{"mtu": 1400})
	if err != nil {
		t.Fatal(err)
	}
	if etag == "" {
		t.Fatal("etag is empty")
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document["type"] != "openppp2-subscription" || int(document["version"].(float64)) != 1 {
		t.Fatalf("unexpected subscription header: %#v", document)
	}
	if _, leaked := document["token"]; leaked {
		t.Fatal("public subscription leaked token")
	}
	nodes := document["nodes"].([]any)
	node := nodes[0].(map[string]any)
	client := node["client"].(map[string]any)
	if client["guid"] != user.Guid {
		t.Fatalf("client guid = %v", client["guid"])
	}
	key := node["key"].(map[string]any)
	if key["protocol-key"] != "p-key" || node["server"] != servers[0].Link {
		t.Fatalf("unexpected generated node: %#v", node)
	}
}

func TestNormalizeServerIDs(t *testing.T) {
	ids := normalizeServerIDs([]int{3, 1, 3, 0, -1, 2})
	want := []int{1, 2, 3}
	if len(ids) != len(want) {
		t.Fatalf("ids = %#v", ids)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ids = %#v", ids)
		}
	}
}

func TestStandaloneSubscriptionAPI(t *testing.T) {
	handler, managedServer := standaloneAdminHandler(t)
	legacy := httptest.NewRecorder()
	managedServer.request(legacy, httptest.NewRequest(http.MethodGet, "/ppp/consumer/load", nil))
	if legacy.Code != http.StatusNotFound {
		t.Fatalf("standalone legacy managed endpoint status = %d", legacy.Code)
	}
	status := adminRequest(handler, http.MethodGet, "/api/v1/status", nil)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"managed":false`) {
		t.Fatalf("standalone status = %d %s", status.Code, status.Body.String())
	}
	users := adminRequest(handler, http.MethodGet, "/api/v1/users", nil)
	if users.Code != http.StatusOK || strings.TrimSpace(users.Body.String()) != "[]" {
		t.Fatalf("standalone users = %d %s", users.Code, users.Body.String())
	}

	server := adminRequest(handler, http.MethodPost, "/api/v1/servers", adminServerInput{
		Name: "Mobile", Link: "ppp://vpn.example.com:20000/", Protocol: "aes-128-cfb",
		ProtocolKey: "protocol-key", Transport: "aes-256-cfb", TransportKey: "transport-key",
		Kf: 154543927, Kx: 128, Kl: 10, Kh: 12,
	})
	if server.Code != http.StatusCreated {
		t.Fatalf("create local server = %d %s", server.Code, server.Body.String())
	}

	created := adminRequest(handler, http.MethodPost, "/api/v1/subscriptions", adminSubscriptionInput{
		Name: "Demo", UserGuid: "F4569420-4E49-4CBA-9C36-94E722C8E363", ProfilePrefix: "Mobile",
		ServerIDs: []int{1}, Options: map[string]any{"mtu": 1380, "allowLan": true}, Enabled: true,
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create local subscription = %d %s", created.Code, created.Body.String())
	}
	var view adminSubscriptionView
	if err := json.Unmarshal(created.Body.Bytes(), &view); err != nil || view.Token == "" {
		t.Fatalf("decode local subscription: %#v, %v", view, err)
	}
	blockedDelete := adminRequest(handler, http.MethodDelete, "/api/v1/servers/1", nil)
	if blockedDelete.Code != http.StatusConflict {
		t.Fatalf("delete referenced local server = %d %s", blockedDelete.Code, blockedDelete.Body.String())
	}
	updated := adminRequest(handler, http.MethodPut, "/api/v1/subscriptions/1", adminSubscriptionInput{
		Name: "Demo Updated", UserGuid: view.UserGuid, ProfilePrefix: "Mobile",
		ServerIDs: []int{1}, Options: map[string]any{"mtu": 1390}, Enabled: true,
	})
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), "Demo Updated") {
		t.Fatalf("update local subscription = %d %s", updated.Code, updated.Body.String())
	}

	preview := adminRequest(handler, http.MethodGet, "/api/v1/subscriptions/1/preview", nil)
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `"guid": "F4569420-4E49-4CBA-9C36-94E722C8E363"`) {
		t.Fatalf("preview local subscription = %d %s", preview.Code, preview.Body.String())
	}
	public := httptest.NewRecorder()
	handler.ServeHTTP(public, httptest.NewRequest(http.MethodGet, "/sub/"+view.Token, nil))
	if public.Code != http.StatusOK {
		t.Fatalf("public local subscription = %d %s", public.Code, public.Body.String())
	}

	rotated := adminRequest(handler, http.MethodPost, "/api/v1/subscriptions/1/rotate-token", nil)
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotate local subscription = %d %s", rotated.Code, rotated.Body.String())
	}
	var rotatedView adminSubscriptionView
	_ = json.Unmarshal(rotated.Body.Bytes(), &rotatedView)
	if rotatedView.Token == "" || rotatedView.Token == view.Token {
		t.Fatal("local subscription token was not rotated")
	}
	oldPublic := httptest.NewRecorder()
	handler.ServeHTTP(oldPublic, httptest.NewRequest(http.MethodGet, "/sub/"+view.Token, nil))
	if oldPublic.Code != http.StatusNotFound {
		t.Fatalf("old local subscription token status = %d", oldPublic.Code)
	}
	deleted := adminRequest(handler, http.MethodDelete, "/api/v1/subscriptions/1", nil)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete local subscription = %d %s", deleted.Code, deleted.Body.String())
	}
	deletedServer := adminRequest(handler, http.MethodDelete, "/api/v1/servers/1", nil)
	if deletedServer.Code != http.StatusOK {
		t.Fatalf("delete unreferenced local server = %d %s", deletedServer.Code, deletedServer.Body.String())
	}
}

func managedServerWithServerRecord(t *testing.T) *ManagedServer {
	t.Helper()
	cfg := defaultManagedServerConfiguration()
	cfg.Key = "shared-secret"
	server := &ManagedServer{
		configuration: cfg,
		managed:       true,
		nodes:         make(map[int]*_vpn_server),
		servers:       make(map[int]*tb_server),
		users:         make(map[string]*_vpn_user),
		dirty:         make(map[string]bool),
	}
	server.servers[1] = &tb_server{
		Id: 1, Link: "ppp://vpn.example.com:20000/",
		Protocol: "aes-128-cfb", ProtocolKey: "protocol-key",
		Transport: "aes-256-cfb", TransportKey: "transport-key",
	}
	return server
}

func legacyRequest(server *ManagedServer, target string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	server.request(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	return recorder
}

func TestLegacyServerRoutesRejectRequestsWithoutTheKey(t *testing.T) {
	server := managedServerWithServerRecord(t)

	for _, target := range []string{
		"/ppp/server/all",
		"/ppp/server/get?node=1",
		"/ppp/server/load",
		"/ppp/server/all?key=wrong",
	} {
		body := legacyRequest(server, target).Body.String()

		var response _HttpResponse
		if err := json.Unmarshal([]byte(body), &response); err != nil {
			t.Fatalf("%s response = %s (%v)", target, body, err)
		}
		if response.Code != _ERROR_ARG_KEY {
			t.Fatalf("%s code = %d, want %d", target, response.Code, _ERROR_ARG_KEY)
		}

		// Node records carry the tunnel keys, so a rejected call must not
		// disclose any part of them.
		for _, secret := range []string{"protocol-key", "transport-key", "vpn.example.com"} {
			if strings.Contains(body, secret) {
				t.Fatalf("%s leaked %q: %s", target, secret, body)
			}
		}
	}
}

func TestLegacyServerAllAcceptsTheConfiguredKey(t *testing.T) {
	server := managedServerWithServerRecord(t)
	body := legacyRequest(server, "/ppp/server/all?key=shared-secret").Body.String()

	var response _HttpResponse
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatalf("response = %s (%v)", body, err)
	}
	if response.Code != _ERROR_OK {
		t.Fatalf("code = %d, want %d", response.Code, _ERROR_OK)
	}
	if !strings.Contains(response.Tag, "protocol-key") {
		t.Fatalf("authorized response did not carry the record: %s", body)
	}
}
