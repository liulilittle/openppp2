package ppp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxSubscriptionBytes = 2 * 1024 * 1024

type tb_subscription struct {
	ID            uint      `gorm:"primaryKey;column:id"`
	Name          string    `gorm:"column:name;size:255;not null"`
	Token         string    `gorm:"column:token;size:64;uniqueIndex;not null"`
	UserGuid      string    `gorm:"column:user_guid;size:36;index;not null"`
	ProfilePrefix string    `gorm:"column:profile_prefix;size:255"`
	ServerIDsJSON string    `gorm:"column:server_ids;type:longtext;not null"`
	OptionsJSON   string    `gorm:"column:options_json;type:longtext"`
	Enabled       bool      `gorm:"column:enabled;not null"`
	CreatedAt     time.Time `gorm:"column:created_at"`
	UpdatedAt     time.Time `gorm:"column:updated_at"`
}

type adminSubscriptionInput struct {
	Name          string         `json:"name"`
	UserGuid      string         `json:"userGuid"`
	ProfilePrefix string         `json:"profilePrefix"`
	ServerIDs     []int          `json:"serverIds"`
	Options       map[string]any `json:"options"`
	Enabled       bool           `json:"enabled"`
}

type adminSubscriptionView struct {
	ID            uint           `json:"id"`
	Name          string         `json:"name"`
	Token         string         `json:"token"`
	URL           string         `json:"url"`
	UserGuid      string         `json:"userGuid"`
	ProfilePrefix string         `json:"profilePrefix"`
	ServerIDs     []int          `json:"serverIds"`
	Options       map[string]any `json:"options"`
	Enabled       bool           `json:"enabled"`
	CreatedAt     time.Time      `json:"createdAt"`
	UpdatedAt     time.Time      `json:"updatedAt"`
}

func (my *ManagedServer) adminListSubscriptions(w http.ResponseWriter, r *http.Request) {
	if my.local != nil {
		items := my.local.ListSubscriptions()
		views := make([]adminSubscriptionView, 0, len(items))
		for _, item := range items {
			views = append(views, my.subscriptionView(r, item))
		}
		adminJSON(w, http.StatusOK, views)
		return
	}
	var subscriptions []tb_subscription
	if err := my.FetchDB(true).LoadDB().Order("updated_at DESC").Find(&subscriptions).Error; err != nil {
		adminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]adminSubscriptionView, 0, len(subscriptions))
	for _, item := range subscriptions {
		views = append(views, my.subscriptionView(r, item))
	}
	adminJSON(w, http.StatusOK, views)
}

func (my *ManagedServer) adminCreateSubscription(w http.ResponseWriter, r *http.Request) {
	var input adminSubscriptionInput
	if err := decodeAdminJSON(r, &input); err != nil {
		adminError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := my.subscriptionFromInput(input)
	if err != nil {
		adminError(w, http.StatusBadRequest, err.Error())
		return
	}
	item.Token, err = newSubscriptionToken()
	if err != nil {
		adminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if my.local != nil {
		item, err = my.local.CreateSubscription(item)
		if err != nil {
			adminError(w, http.StatusConflict, err.Error())
			return
		}
		adminJSON(w, http.StatusCreated, my.subscriptionView(r, item))
		return
	}
	if err := my.FetchDB(false).LoadDB().Create(&item).Error; err != nil {
		adminError(w, http.StatusConflict, err.Error())
		return
	}
	adminJSON(w, http.StatusCreated, my.subscriptionView(r, item))
}

func (my *ManagedServer) adminUpdateSubscription(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		adminError(w, http.StatusBadRequest, "invalid subscription id")
		return
	}
	var input adminSubscriptionInput
	if err := decodeAdminJSON(r, &input); err != nil {
		adminError(w, http.StatusBadRequest, err.Error())
		return
	}
	next, err := my.subscriptionFromInput(input)
	if err != nil {
		adminError(w, http.StatusBadRequest, err.Error())
		return
	}
	if my.local != nil {
		updated, err := my.local.UpdateSubscription(uint(id), next)
		if errors.Is(err, os.ErrNotExist) {
			adminError(w, http.StatusNotFound, "subscription not found")
			return
		}
		if err != nil {
			adminError(w, http.StatusBadRequest, err.Error())
			return
		}
		adminJSON(w, http.StatusOK, my.subscriptionView(r, updated))
		return
	}
	db := my.FetchDB(false).LoadDB()
	var current tb_subscription
	if err := db.First(&current, uint(id)).Error; err != nil {
		adminError(w, http.StatusNotFound, "subscription not found")
		return
	}
	next.ID = current.ID
	next.Token = current.Token
	next.CreatedAt = current.CreatedAt
	if err := db.Save(&next).Error; err != nil {
		adminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	adminJSON(w, http.StatusOK, my.subscriptionView(r, next))
}

func (my *ManagedServer) adminDeleteSubscription(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		adminError(w, http.StatusBadRequest, "invalid subscription id")
		return
	}
	if my.local != nil {
		err := my.local.DeleteSubscription(uint(id))
		if errors.Is(err, os.ErrNotExist) {
			adminError(w, http.StatusNotFound, "subscription not found")
			return
		}
		if err != nil {
			adminError(w, http.StatusInternalServerError, err.Error())
			return
		}
		adminJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	result := my.FetchDB(false).LoadDB().Delete(&tb_subscription{}, uint(id))
	if result.Error != nil {
		adminError(w, http.StatusInternalServerError, result.Error.Error())
		return
	}
	if result.RowsAffected == 0 {
		adminError(w, http.StatusNotFound, "subscription not found")
		return
	}
	adminJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (my *ManagedServer) adminRotateSubscriptionToken(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		adminError(w, http.StatusBadRequest, "invalid subscription id")
		return
	}
	if my.local != nil {
		token, err := newSubscriptionToken()
		if err != nil {
			adminError(w, http.StatusInternalServerError, err.Error())
			return
		}
		item, err := my.local.RotateSubscriptionToken(uint(id), token)
		if errors.Is(err, os.ErrNotExist) {
			adminError(w, http.StatusNotFound, "subscription not found")
			return
		}
		if err != nil {
			adminError(w, http.StatusInternalServerError, err.Error())
			return
		}
		adminJSON(w, http.StatusOK, my.subscriptionView(r, item))
		return
	}
	db := my.FetchDB(false).LoadDB()
	var item tb_subscription
	if err := db.First(&item, uint(id)).Error; err != nil {
		adminError(w, http.StatusNotFound, "subscription not found")
		return
	}
	item.Token, err = newSubscriptionToken()
	if err != nil {
		adminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := db.Save(&item).Error; err != nil {
		adminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	adminJSON(w, http.StatusOK, my.subscriptionView(r, item))
}

func (my *ManagedServer) adminPreviewSubscription(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		adminError(w, http.StatusBadRequest, "invalid subscription id")
		return
	}
	var item tb_subscription
	if my.local != nil {
		var ok bool
		item, ok = my.local.GetSubscription(uint(id))
		if !ok {
			adminError(w, http.StatusNotFound, "subscription not found")
			return
		}
	} else {
		if err := my.FetchDB(true).LoadDB().First(&item, uint(id)).Error; err != nil {
			adminError(w, http.StatusNotFound, "subscription not found")
			return
		}
	}
	document, _, err := my.encodeSubscription(item)
	if err != nil {
		adminError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(document)
}

func (my *ManagedServer) publicSubscription(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.PathValue("token"))
	if token == "" {
		http.NotFound(w, r)
		return
	}
	var item tb_subscription
	if my.local != nil {
		var ok bool
		item, ok = my.local.GetSubscriptionByToken(token)
		if !ok {
			http.NotFound(w, r)
			return
		}
	} else {
		if err := my.FetchDB(true).LoadDB().Where("token = ? AND enabled = ?", token, true).First(&item).Error; err != nil {
			http.NotFound(w, r)
			return
		}
	}
	document, etag, err := my.encodeSubscription(item)
	if err != nil {
		http.Error(w, "subscription unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "private, max-age=60")
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", item.UpdatedAt.UTC().Format(http.TimeFormat))
	_, _ = w.Write(document)
}

func (my *ManagedServer) subscriptionFromInput(input adminSubscriptionInput) (tb_subscription, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.UserGuid = strings.ToUpper(strings.TrimSpace(input.UserGuid))
	input.ProfilePrefix = strings.TrimSpace(input.ProfilePrefix)
	if input.Name == "" || !StringAuxiliary.IsGuid(input.UserGuid) {
		return tb_subscription{}, errors.New("name and valid userGuid are required")
	}
	input.ServerIDs = normalizeServerIDs(input.ServerIDs)
	if len(input.ServerIDs) == 0 {
		return tb_subscription{}, errors.New("at least one server is required")
	}
	if my.local != nil {
		available := make(map[int]struct{})
		for _, server := range my.local.ListServers() {
			available[server.Id] = struct{}{}
		}
		for _, id := range input.ServerIDs {
			if _, exists := available[id]; !exists {
				return tb_subscription{}, errors.New("one or more subscription servers do not exist")
			}
		}
	} else {
		db := my.FetchDB(true).LoadDB()
		var userCount int64
		if err := db.Model(&tb_user{}).Where("guid = ?", input.UserGuid).Count(&userCount).Error; err != nil || userCount != 1 {
			return tb_subscription{}, errors.New("subscription user does not exist")
		}
		var serverCount int64
		if err := db.Model(&tb_server{}).Where("id IN ?", input.ServerIDs).Count(&serverCount).Error; err != nil || serverCount != int64(len(input.ServerIDs)) {
			return tb_subscription{}, errors.New("one or more subscription servers do not exist")
		}
	}
	serverIDs, _ := json.Marshal(input.ServerIDs)
	if input.Options == nil {
		input.Options = map[string]any{}
	}
	options, err := json.Marshal(input.Options)
	if err != nil {
		return tb_subscription{}, fmt.Errorf("encode options: %w", err)
	}
	return tb_subscription{
		Name: input.Name, UserGuid: input.UserGuid, ProfilePrefix: input.ProfilePrefix,
		ServerIDsJSON: string(serverIDs), OptionsJSON: string(options), Enabled: input.Enabled,
	}, nil
}

func (my *ManagedServer) subscriptionView(r *http.Request, item tb_subscription) adminSubscriptionView {
	var serverIDs []int
	_ = json.Unmarshal([]byte(item.ServerIDsJSON), &serverIDs)
	options := map[string]any{}
	_ = json.Unmarshal([]byte(item.OptionsJSON), &options)
	baseURL := strings.TrimRight(strings.TrimSpace(my.configuration.Admin.PublicBaseURL), "/")
	if baseURL == "" && r != nil {
		scheme := "http"
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			scheme = "https"
		}
		baseURL = scheme + "://" + r.Host
	}
	return adminSubscriptionView{
		ID: item.ID, Name: item.Name, Token: item.Token, URL: baseURL + "/sub/" + item.Token,
		UserGuid: item.UserGuid, ProfilePrefix: item.ProfilePrefix, ServerIDs: serverIDs, Options: options,
		Enabled: item.Enabled, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}

func (my *ManagedServer) encodeSubscription(item tb_subscription) ([]byte, string, error) {
	var serverIDs []int
	if err := json.Unmarshal([]byte(item.ServerIDsJSON), &serverIDs); err != nil || len(serverIDs) == 0 {
		return nil, "", errors.New("subscription server list is invalid")
	}
	options := map[string]any{}
	if item.OptionsJSON != "" {
		if err := json.Unmarshal([]byte(item.OptionsJSON), &options); err != nil {
			return nil, "", errors.New("subscription options are invalid")
		}
	}
	user := tb_user{Guid: item.UserGuid}
	var servers []tb_server
	if my.local != nil {
		servers = my.local.ListServers()
	} else {
		if err := my.FetchDB(true).LoadDB().First(&user, "guid = ?", item.UserGuid).Error; err != nil {
			return nil, "", errors.New("subscription user not found")
		}
		if err := my.FetchDB(true).LoadDB().Where("id IN ?", serverIDs).Find(&servers).Error; err != nil {
			return nil, "", err
		}
	}
	byID := make(map[int]tb_server, len(servers))
	for _, server := range servers {
		byID[server.Id] = server
	}
	orderedServers := make([]tb_server, 0, len(serverIDs))
	for _, id := range serverIDs {
		if server, ok := byID[id]; ok {
			orderedServers = append(orderedServers, server)
		}
	}
	if len(orderedServers) != len(serverIDs) {
		return nil, "", errors.New("one or more subscription servers were removed")
	}
	return buildSubscriptionDocument(item, user, orderedServers, options)
}

func buildSubscriptionDocument(item tb_subscription, user tb_user, servers []tb_server, options map[string]any) ([]byte, string, error) {
	nodes := make([]map[string]any, 0, len(servers))
	for _, server := range servers {
		nodes = append(nodes, map[string]any{
			"id":       fmt.Sprintf("server-%d", server.Id),
			"name":     server.Name,
			"subtitle": server.Link,
			"server":   server.Link,
			"key": map[string]any{
				"kf": server.Kf, "kx": server.Kx, "kl": server.Kl, "kh": server.Kh,
				"protocol": server.Protocol, "protocol-key": server.ProtocolKey,
				"transport": server.Transport, "transport-key": server.TransportKey,
				"masked": server.Masked, "plaintext": server.Plaintext,
				"delta-encode": server.DeltaEncode, "shuffle-data": server.ShuffleData,
			},
			"client":  map[string]any{"guid": user.Guid},
			"options": options,
		})
	}
	if len(nodes) == 0 {
		return nil, "", errors.New("subscription has no available servers")
	}
	document := map[string]any{
		"type": "openppp2-subscription", "version": 1, "name": item.Name,
		"profilePrefix": item.ProfilePrefix, "updatedAt": item.UpdatedAt.UTC(), "nodes": nodes,
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, "", err
	}
	data = append(data, '\n')
	if len(data) > maxSubscriptionBytes {
		return nil, "", errors.New("subscription exceeds 2 MB")
	}
	digest := sha256.Sum256(data)
	return data, `"` + hex.EncodeToString(digest[:]) + `"`, nil
}

func (my *ManagedServer) subscriptionReferencesServer(id int) bool {
	if my.local != nil {
		for _, item := range my.local.ListSubscriptions() {
			var ids []int
			_ = json.Unmarshal([]byte(item.ServerIDsJSON), &ids)
			for _, current := range ids {
				if current == id {
					return true
				}
			}
		}
		return false
	}
	var subscriptions []tb_subscription
	if err := my.FetchDB(true).LoadDB().Select("server_ids").Find(&subscriptions).Error; err != nil {
		return true
	}
	for _, item := range subscriptions {
		var ids []int
		_ = json.Unmarshal([]byte(item.ServerIDsJSON), &ids)
		for _, current := range ids {
			if current == id {
				return true
			}
		}
	}
	return false
}

func normalizeServerIDs(ids []int) []int {
	seen := map[int]struct{}{}
	result := make([]int, 0, len(ids))
	for _, id := range ids {
		if id < 1 {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	sort.Ints(result)
	return result
}

func newSubscriptionToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
