package ppp

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

//go:embed webui/*
var adminWebUI embed.FS

func normalizeAdminPath(value string) (string, error) {
	clean := path.Clean("/" + strings.Trim(strings.TrimSpace(value), "/"))
	if clean == "/" {
		clean = "/admin"
	}
	for _, reserved := range []string{"/api", "/sub", "/ppp"} {
		if clean == reserved || strings.HasPrefix(clean, reserved+"/") {
			return "", fmt.Errorf("admin path %q conflicts with a reserved endpoint", clean)
		}
	}
	return clean + "/", nil
}

type adminUserInput struct {
	Guid            string `json:"guid"`
	IncomingTraffic int64  `json:"incomingTraffic"`
	OutgoingTraffic int64  `json:"outgoingTraffic"`
	ExpiredTime     uint32 `json:"expiredTime"`
	BandwidthQoS    uint32 `json:"bandwidthQoS"`
}

type adminServerInput struct {
	Link         string `json:"link"`
	Name         string `json:"name"`
	Kf           int    `json:"kf"`
	Kx           int    `json:"kx"`
	Kl           int    `json:"kl"`
	Kh           int    `json:"kh"`
	Protocol     string `json:"protocol"`
	ProtocolKey  string `json:"protocolKey"`
	Transport    string `json:"transport"`
	TransportKey string `json:"transportKey"`
	Masked       bool   `json:"masked"`
	Plaintext    bool   `json:"plaintext"`
	DeltaEncode  bool   `json:"deltaEncode"`
	ShuffleData  bool   `json:"shuffleData"`
	BandwidthQoS uint32 `json:"bandwidthQoS"`
}

type adminServerView struct {
	ID           int    `json:"id"`
	Link         string `json:"link"`
	Name         string `json:"name"`
	Kf           int    `json:"kf"`
	Kx           int    `json:"kx"`
	Kl           int    `json:"kl"`
	Kh           int    `json:"kh"`
	Protocol     string `json:"protocol"`
	ProtocolKey  string `json:"protocolKey"`
	Transport    string `json:"transport"`
	TransportKey string `json:"transportKey"`
	Masked       bool   `json:"masked"`
	Plaintext    bool   `json:"plaintext"`
	DeltaEncode  bool   `json:"deltaEncode"`
	ShuffleData  bool   `json:"shuffleData"`
	BandwidthQoS uint32 `json:"bandwidthQoS"`
	Online       bool   `json:"online"`
}

func (my *ManagedServer) newAdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", my.adminStatus)
	mux.HandleFunc("GET /api/v1/users", my.adminListUsers)
	mux.HandleFunc("POST /api/v1/users", my.adminCreateUser)
	mux.HandleFunc("PUT /api/v1/users/{guid}", my.adminUpdateUser)
	mux.HandleFunc("DELETE /api/v1/users/{guid}", my.adminDeleteUser)
	mux.HandleFunc("GET /api/v1/servers", my.adminListServers)
	mux.HandleFunc("POST /api/v1/servers", my.adminCreateServer)
	mux.HandleFunc("PUT /api/v1/servers/{id}", my.adminUpdateServer)
	mux.HandleFunc("DELETE /api/v1/servers/{id}", my.adminDeleteServer)
	mux.HandleFunc("GET /api/v1/subscriptions", my.adminListSubscriptions)
	mux.HandleFunc("POST /api/v1/subscriptions", my.adminCreateSubscription)
	mux.HandleFunc("PUT /api/v1/subscriptions/{id}", my.adminUpdateSubscription)
	mux.HandleFunc("DELETE /api/v1/subscriptions/{id}", my.adminDeleteSubscription)
	mux.HandleFunc("POST /api/v1/subscriptions/{id}/rotate-token", my.adminRotateSubscriptionToken)
	mux.HandleFunc("GET /api/v1/subscriptions/{id}/preview", my.adminPreviewSubscription)
	mux.HandleFunc("GET /sub/{token}", my.publicSubscription)

	adminPath := my.configuration.Admin.Path
	if !strings.HasPrefix(adminPath, "/") {
		adminPath = "/" + adminPath
	}
	if !strings.HasSuffix(adminPath, "/") {
		adminPath += "/"
	}
	assets, err := fs.Sub(adminWebUI, "webui")
	if err == nil {
		mux.Handle(adminPath, http.StripPrefix(adminPath, http.FileServer(http.FS(assets))))
		mux.HandleFunc(strings.TrimSuffix(adminPath, "/"), func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, adminPath, http.StatusTemporaryRedirect)
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/v1/") && !my.adminAuthorized(r) {
			adminError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (my *ManagedServer) adminAuthorized(r *http.Request) bool {
	configured := strings.TrimSpace(my.configuration.Admin.Token)
	if configured == "" {
		return false
	}
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return false
	}
	provided := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	want := sha256.Sum256([]byte(configured))
	got := sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

func adminJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

func adminError(w http.ResponseWriter, status int, message string) {
	adminJSON(w, status, map[string]string{"error": message})
}

func decodeAdminJSON(r *http.Request, value any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 2*1024*1024+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain one JSON object")
		}
		return err
	}
	return nil
}

func (my *ManagedServer) adminStatus(w http.ResponseWriter, _ *http.Request) {
	if my.local != nil {
		adminJSON(w, http.StatusOK, map[string]any{
			"managed": false, "users": 0, "servers": len(my.local.ListServers()),
			"onlineServers": 0, "subscriptions": len(my.local.ListSubscriptions()), "time": time.Now().UTC(),
		})
		return
	}
	db := my.FetchDB(true)
	if db == nil || db.LoadDB() == nil {
		adminError(w, http.StatusServiceUnavailable, "database is unavailable")
		return
	}
	var users int64
	var servers int64
	var subscriptions int64
	if err := db.LoadDB().Model(&tb_user{}).Count(&users).Error; err != nil {
		adminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := db.LoadDB().Model(&tb_server{}).Count(&servers).Error; err != nil {
		adminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := db.LoadDB().Model(&tb_subscription{}).Count(&subscriptions).Error; err != nil {
		adminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	my.Lock()
	online := len(my.nodes)
	my.Unlock()
	adminJSON(w, http.StatusOK, map[string]any{
		"managed": true, "users": users, "servers": servers, "onlineServers": online, "subscriptions": subscriptions,
		"time": time.Now().UTC(),
	})
}

func (my *ManagedServer) adminListUsers(w http.ResponseWriter, _ *http.Request) {
	if my.local != nil {
		adminJSON(w, http.StatusOK, []tb_user{})
		return
	}
	var users []tb_user
	if err := my.FetchDB(true).LoadDB().Order("guid ASC").Limit(1000).Find(&users).Error; err != nil {
		adminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	adminJSON(w, http.StatusOK, users)
}

func (my *ManagedServer) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	if my.local != nil {
		adminError(w, http.StatusNotFound, "managed user API is unavailable")
		return
	}
	var input adminUserInput
	if err := decodeAdminJSON(r, &input); err != nil {
		adminError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(input.Guid) == "" {
		input.Guid = uuid.NewString()
	}
	input.Guid = strings.ToUpper(strings.TrimSpace(input.Guid))
	if !StringAuxiliary.IsGuid(input.Guid) || input.IncomingTraffic < 0 || input.OutgoingTraffic < 0 {
		adminError(w, http.StatusBadRequest, "invalid guid or traffic quota")
		return
	}
	user := tb_user{Guid: input.Guid, IncomingTraffic: input.IncomingTraffic, OutgoingTraffic: input.OutgoingTraffic, ExpiredTime: input.ExpiredTime, BandwidthQoS: input.BandwidthQoS}
	if err := my.FetchDB(false).LoadDB().Create(&user).Error; err != nil {
		adminError(w, http.StatusConflict, err.Error())
		return
	}
	_ = my.redis.Del(_REDIS_USER_DATA_KEY + ":" + user.Guid)
	adminJSON(w, http.StatusCreated, user)
}

func (my *ManagedServer) adminUpdateUser(w http.ResponseWriter, r *http.Request) {
	if my.local != nil {
		adminError(w, http.StatusNotFound, "managed user API is unavailable")
		return
	}
	guid := strings.ToUpper(strings.TrimSpace(r.PathValue("guid")))
	if !StringAuxiliary.IsGuid(guid) {
		adminError(w, http.StatusBadRequest, "invalid guid")
		return
	}
	var input adminUserInput
	if err := decodeAdminJSON(r, &input); err != nil || input.IncomingTraffic < 0 || input.OutgoingTraffic < 0 {
		if err == nil {
			err = errors.New("traffic quota cannot be negative")
		}
		adminError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, code, err := my.server_user_set_traffic_and_seconds(guid, input.IncomingTraffic, input.OutgoingTraffic, input.ExpiredTime, input.BandwidthQoS)
	if code == _ERROR_USER_NOT_EXISTS {
		adminError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil || code != _ERROR_OK || user == nil {
		if err == nil {
			err = fmt.Errorf("user update failed with code %d", code)
		}
		adminError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	adminJSON(w, http.StatusOK, tb_user{
		Guid: user.Guid, IncomingTraffic: user.IncomingTraffic, OutgoingTraffic: user.OutgoingTraffic,
		ExpiredTime: user.ExpiredTime, BandwidthQoS: user.BandwidthQoS,
	})
}

func (my *ManagedServer) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	if my.local != nil {
		adminError(w, http.StatusNotFound, "managed user API is unavailable")
		return
	}
	guid := strings.ToUpper(strings.TrimSpace(r.PathValue("guid")))
	if !StringAuxiliary.IsGuid(guid) {
		adminError(w, http.StatusBadRequest, "invalid guid")
		return
	}
	db := my.FetchDB(false).LoadDB()
	var count int64
	if err := db.Model(&tb_subscription{}).Where("user_guid = ?", guid).Count(&count).Error; err != nil {
		adminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if count > 0 {
		adminError(w, http.StatusConflict, "user is referenced by a subscription")
		return
	}
	result := db.Delete(&tb_user{}, "guid = ?", guid)
	if result.Error != nil {
		adminError(w, http.StatusInternalServerError, result.Error.Error())
		return
	}
	if result.RowsAffected == 0 {
		adminError(w, http.StatusNotFound, "user not found")
		return
	}
	_ = my.redis.Del(_REDIS_USER_DATA_KEY + ":" + guid)
	_ = my.redis.SRem(_REDIS_USER_SYNC_KEY, guid)
	my.Lock()
	delete(my.users, guid)
	delete(my.dirty, guid)
	my.Unlock()
	adminJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (my *ManagedServer) adminListServers(w http.ResponseWriter, _ *http.Request) {
	if my.local != nil {
		servers := my.local.ListServers()
		views := make([]adminServerView, 0, len(servers))
		for index := range servers {
			views = append(views, serverView(&servers[index], false))
		}
		adminJSON(w, http.StatusOK, views)
		return
	}
	servers, err := my.server_find_all_servers()
	if err != nil {
		adminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]adminServerView, 0, len(servers))
	my.Lock()
	for _, server := range servers {
		_, online := my.nodes[server.Id]
		views = append(views, serverView(server, online))
	}
	my.Unlock()
	adminJSON(w, http.StatusOK, views)
}

func (my *ManagedServer) adminCreateServer(w http.ResponseWriter, r *http.Request) {
	var input adminServerInput
	if err := decodeAdminJSON(r, &input); err != nil {
		adminError(w, http.StatusBadRequest, err.Error())
		return
	}
	server, err := serverFromInput(input)
	if err != nil {
		adminError(w, http.StatusBadRequest, err.Error())
		return
	}
	if my.local != nil {
		created, err := my.local.CreateServer(*server)
		if err != nil {
			adminError(w, http.StatusInternalServerError, err.Error())
			return
		}
		adminJSON(w, http.StatusCreated, serverView(&created, false))
		return
	}
	if err := my.FetchDB(false).LoadDB().Create(server).Error; err != nil {
		adminError(w, http.StatusConflict, err.Error())
		return
	}
	_, _ = my.server_load_all_servers()
	adminJSON(w, http.StatusCreated, serverView(server, false))
}

func (my *ManagedServer) adminUpdateServer(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id < 1 {
		adminError(w, http.StatusBadRequest, "invalid server id")
		return
	}
	var input adminServerInput
	if err := decodeAdminJSON(r, &input); err != nil {
		adminError(w, http.StatusBadRequest, err.Error())
		return
	}
	next, err := serverFromInput(input)
	if err != nil {
		adminError(w, http.StatusBadRequest, err.Error())
		return
	}
	if my.local != nil {
		updated, err := my.local.UpdateServer(id, *next)
		if errors.Is(err, os.ErrNotExist) {
			adminError(w, http.StatusNotFound, "server not found")
			return
		}
		if err != nil {
			adminError(w, http.StatusInternalServerError, err.Error())
			return
		}
		adminJSON(w, http.StatusOK, serverView(&updated, false))
		return
	}
	db := my.FetchDB(false).LoadDB()
	var server tb_server
	if err := db.First(&server, id).Error; err != nil {
		adminError(w, http.StatusNotFound, "server not found")
		return
	}
	next.Id = id
	if err := db.Save(next).Error; err != nil {
		adminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = my.server_load_all_servers()
	my.Lock()
	_, online := my.nodes[id]
	my.Unlock()
	adminJSON(w, http.StatusOK, serverView(next, online))
}

func (my *ManagedServer) adminDeleteServer(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id < 1 {
		adminError(w, http.StatusBadRequest, "invalid server id")
		return
	}
	if my.local != nil {
		err := my.local.DeleteServer(id)
		if errors.Is(err, os.ErrNotExist) {
			adminError(w, http.StatusNotFound, "server not found")
			return
		}
		if err != nil {
			adminError(w, http.StatusConflict, err.Error())
			return
		}
		adminJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if my.subscriptionReferencesServer(id) {
		adminError(w, http.StatusConflict, "server is referenced by a subscription")
		return
	}
	result := my.FetchDB(false).LoadDB().Delete(&tb_server{}, id)
	if result.Error != nil {
		adminError(w, http.StatusInternalServerError, result.Error.Error())
		return
	}
	if result.RowsAffected == 0 {
		adminError(w, http.StatusNotFound, "server not found")
		return
	}
	my.Lock()
	delete(my.servers, id)
	node := my.nodes[id]
	delete(my.nodes, id)
	my.Unlock()
	if node != nil && node.ws != nil {
		node.ws.Close()
	}
	adminJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func serverFromInput(input adminServerInput) (*tb_server, error) {
	input.Link = strings.TrimSpace(input.Link)
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || !strings.HasPrefix(input.Link, "ppp://") {
		return nil, errors.New("server name and ppp:// link are required")
	}
	if !input.Plaintext && (strings.TrimSpace(input.Protocol) == "" || strings.TrimSpace(input.Transport) == "") {
		return nil, errors.New("protocol and transport are required unless plaintext is enabled")
	}
	return &tb_server{
		Link: input.Link, Name: input.Name, Kf: input.Kf, Kx: input.Kx, Kl: input.Kl, Kh: input.Kh,
		Protocol: input.Protocol, ProtocolKey: input.ProtocolKey, Transport: input.Transport, TransportKey: input.TransportKey,
		Masked: input.Masked, Plaintext: input.Plaintext, DeltaEncode: input.DeltaEncode, ShuffleData: input.ShuffleData,
		BandwidthQoS: input.BandwidthQoS,
	}, nil
}

func serverView(server *tb_server, online bool) adminServerView {
	return adminServerView{
		ID: server.Id, Link: server.Link, Name: server.Name, Kf: server.Kf, Kx: server.Kx, Kl: server.Kl, Kh: server.Kh,
		Protocol: server.Protocol, ProtocolKey: server.ProtocolKey, Transport: server.Transport, TransportKey: server.TransportKey,
		Masked: server.Masked, Plaintext: server.Plaintext, DeltaEncode: server.DeltaEncode, ShuffleData: server.ShuffleData,
		BandwidthQoS: server.BandwidthQoS, Online: online,
	}
}
