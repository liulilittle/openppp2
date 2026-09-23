package ppp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const localManagerDataVersion = 1

type localManagerData struct {
	Version            int               `json:"version"`
	AdminToken         string            `json:"adminToken"`
	PublicBaseURL      string            `json:"publicBaseUrl,omitempty"`
	NextServerID       int               `json:"nextServerId"`
	NextSubscriptionID uint              `json:"nextSubscriptionId"`
	Servers            []tb_server       `json:"servers"`
	Subscriptions      []tb_subscription `json:"subscriptions"`
}

type LocalStore struct {
	sync.Mutex
	path string
	data localManagerData
}

func OpenLocalStore(path, adminToken, publicBaseURL string) (*LocalStore, error) {
	if path == "" {
		path = "manager-data.json"
	}
	fullPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	store := &LocalStore{path: fullPath}
	content, err := os.ReadFile(fullPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(content) == 0 {
		store.data = localManagerData{
			Version: localManagerDataVersion, NextServerID: 1, NextSubscriptionID: 1,
			Servers: []tb_server{}, Subscriptions: []tb_subscription{},
		}
	} else if err := json.Unmarshal(content, &store.data); err != nil {
		return nil, fmt.Errorf("decode local manager data: %w", err)
	}
	if err := validateLocalManagerData(store.data); err != nil {
		return nil, err
	}
	changed := len(content) == 0
	if normalizeLocalManagerData(&store.data) {
		changed = true
	}
	if adminToken != "" && store.data.AdminToken != adminToken {
		store.data.AdminToken = adminToken
		changed = true
	}
	if store.data.AdminToken == "" {
		store.data.AdminToken, err = newSubscriptionToken()
		if err != nil {
			return nil, err
		}
		changed = true
	}
	if publicBaseURL != "" && store.data.PublicBaseURL != publicBaseURL {
		store.data.PublicBaseURL = publicBaseURL
		changed = true
	}
	if changed {
		if err := store.saveLocked(store.data); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func normalizeLocalManagerData(data *localManagerData) bool {
	changed := false
	if data.Version == 0 {
		data.Version = localManagerDataVersion
		changed = true
	}
	if data.Servers == nil {
		data.Servers = []tb_server{}
		changed = true
	}
	if data.Subscriptions == nil {
		data.Subscriptions = []tb_subscription{}
		changed = true
	}
	maxServerID := 0
	for _, server := range data.Servers {
		maxServerID = max(maxServerID, server.Id)
	}
	if data.NextServerID <= maxServerID {
		data.NextServerID = maxServerID + 1
		changed = true
	}
	if data.NextServerID < 1 {
		data.NextServerID = 1
		changed = true
	}
	maxSubscriptionID := uint(0)
	for _, item := range data.Subscriptions {
		maxSubscriptionID = max(maxSubscriptionID, item.ID)
	}
	if data.NextSubscriptionID <= maxSubscriptionID {
		data.NextSubscriptionID = maxSubscriptionID + 1
		changed = true
	}
	if data.NextSubscriptionID < 1 {
		data.NextSubscriptionID = 1
		changed = true
	}
	return changed
}

func validateLocalManagerData(data localManagerData) error {
	if data.Version != 0 && data.Version != localManagerDataVersion {
		return fmt.Errorf("unsupported local manager data version %d", data.Version)
	}
	serverIDs := make(map[int]struct{}, len(data.Servers))
	maxServerID := 0
	for _, server := range data.Servers {
		if server.Id < 1 {
			return errors.New("local server id must be positive")
		}
		if _, exists := serverIDs[server.Id]; exists {
			return fmt.Errorf("duplicate local server id %d", server.Id)
		}
		serverIDs[server.Id] = struct{}{}
		maxServerID = max(maxServerID, server.Id)
	}
	tokens := make(map[string]struct{}, len(data.Subscriptions))
	maxSubscriptionID := uint(0)
	for _, item := range data.Subscriptions {
		if item.ID == 0 || item.Token == "" || !StringAuxiliary.IsGuid(item.UserGuid) {
			return errors.New("local subscription id, token, or guid is invalid")
		}
		if _, exists := tokens[item.Token]; exists {
			return errors.New("duplicate local subscription token")
		}
		tokens[item.Token] = struct{}{}
		var ids []int
		if err := json.Unmarshal([]byte(item.ServerIDsJSON), &ids); err != nil || len(ids) == 0 {
			return errors.New("local subscription server list is invalid")
		}
		for _, id := range ids {
			if _, exists := serverIDs[id]; !exists {
				return fmt.Errorf("local subscription references missing server %d", id)
			}
		}
		maxSubscriptionID = max(maxSubscriptionID, item.ID)
	}
	if data.NextServerID <= maxServerID {
		data.NextServerID = maxServerID + 1
	}
	if data.NextSubscriptionID <= maxSubscriptionID {
		data.NextSubscriptionID = maxSubscriptionID + 1
	}
	return nil
}

func cloneLocalManagerData(data localManagerData) localManagerData {
	data.Servers = append([]tb_server(nil), data.Servers...)
	data.Subscriptions = append([]tb_subscription(nil), data.Subscriptions...)
	return data
}

func (store *LocalStore) saveLocked(data localManagerData) error {
	data.Version = localManagerDataVersion
	if data.NextServerID < 1 {
		data.NextServerID = 1
	}
	if data.NextSubscriptionID < 1 {
		data.NextSubscriptionID = 1
	}
	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	dir := filepath.Dir(store.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".manager-data-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(content)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryPath, store.path)
}

func (store *LocalStore) AdminToken() string {
	store.Lock()
	defer store.Unlock()
	return store.data.AdminToken
}

func (store *LocalStore) PublicBaseURL() string {
	store.Lock()
	defer store.Unlock()
	return store.data.PublicBaseURL
}

func (store *LocalStore) ListServers() []tb_server {
	store.Lock()
	defer store.Unlock()
	servers := append([]tb_server(nil), store.data.Servers...)
	sort.Slice(servers, func(i, j int) bool { return servers[i].Id < servers[j].Id })
	return servers
}

func (store *LocalStore) CreateServer(server tb_server) (tb_server, error) {
	store.Lock()
	defer store.Unlock()
	next := cloneLocalManagerData(store.data)
	server.Id = next.NextServerID
	next.NextServerID++
	next.Servers = append(next.Servers, server)
	if err := store.saveLocked(next); err != nil {
		return tb_server{}, err
	}
	store.data = next
	return server, nil
}

func (store *LocalStore) UpdateServer(id int, server tb_server) (tb_server, error) {
	store.Lock()
	defer store.Unlock()
	next := cloneLocalManagerData(store.data)
	for index := range next.Servers {
		if next.Servers[index].Id == id {
			server.Id = id
			next.Servers[index] = server
			if err := store.saveLocked(next); err != nil {
				return tb_server{}, err
			}
			store.data = next
			return server, nil
		}
	}
	return tb_server{}, os.ErrNotExist
}

func (store *LocalStore) DeleteServer(id int) error {
	store.Lock()
	defer store.Unlock()
	for _, item := range store.data.Subscriptions {
		var ids []int
		_ = json.Unmarshal([]byte(item.ServerIDsJSON), &ids)
		for _, serverID := range ids {
			if serverID == id {
				return errors.New("server is referenced by a subscription")
			}
		}
	}
	next := cloneLocalManagerData(store.data)
	for index := range next.Servers {
		if next.Servers[index].Id == id {
			next.Servers = append(next.Servers[:index], next.Servers[index+1:]...)
			if err := store.saveLocked(next); err != nil {
				return err
			}
			store.data = next
			return nil
		}
	}
	return os.ErrNotExist
}

func (store *LocalStore) ListSubscriptions() []tb_subscription {
	store.Lock()
	defer store.Unlock()
	items := append([]tb_subscription(nil), store.data.Subscriptions...)
	sort.Slice(items, func(i, j int) bool { return items[i].UpdatedAt.After(items[j].UpdatedAt) })
	return items
}

func (store *LocalStore) GetSubscription(id uint) (tb_subscription, bool) {
	store.Lock()
	defer store.Unlock()
	for _, item := range store.data.Subscriptions {
		if item.ID == id {
			return item, true
		}
	}
	return tb_subscription{}, false
}

func (store *LocalStore) GetSubscriptionByToken(token string) (tb_subscription, bool) {
	store.Lock()
	defer store.Unlock()
	for _, item := range store.data.Subscriptions {
		if item.Token == token && item.Enabled {
			return item, true
		}
	}
	return tb_subscription{}, false
}

func (store *LocalStore) CreateSubscription(item tb_subscription) (tb_subscription, error) {
	store.Lock()
	defer store.Unlock()
	next := cloneLocalManagerData(store.data)
	item.ID = next.NextSubscriptionID
	next.NextSubscriptionID++
	now := time.Now().UTC()
	item.CreatedAt, item.UpdatedAt = now, now
	next.Subscriptions = append(next.Subscriptions, item)
	if err := validateLocalManagerData(next); err != nil {
		return tb_subscription{}, err
	}
	if err := store.saveLocked(next); err != nil {
		return tb_subscription{}, err
	}
	store.data = next
	return item, nil
}

func (store *LocalStore) UpdateSubscription(id uint, item tb_subscription) (tb_subscription, error) {
	store.Lock()
	defer store.Unlock()
	next := cloneLocalManagerData(store.data)
	for index, current := range next.Subscriptions {
		if current.ID == id {
			item.ID, item.Token, item.CreatedAt = id, current.Token, current.CreatedAt
			item.UpdatedAt = time.Now().UTC()
			next.Subscriptions[index] = item
			if err := validateLocalManagerData(next); err != nil {
				return tb_subscription{}, err
			}
			if err := store.saveLocked(next); err != nil {
				return tb_subscription{}, err
			}
			store.data = next
			return item, nil
		}
	}
	return tb_subscription{}, os.ErrNotExist
}

func (store *LocalStore) DeleteSubscription(id uint) error {
	store.Lock()
	defer store.Unlock()
	next := cloneLocalManagerData(store.data)
	for index := range next.Subscriptions {
		if next.Subscriptions[index].ID == id {
			next.Subscriptions = append(next.Subscriptions[:index], next.Subscriptions[index+1:]...)
			if err := store.saveLocked(next); err != nil {
				return err
			}
			store.data = next
			return nil
		}
	}
	return os.ErrNotExist
}

func (store *LocalStore) RotateSubscriptionToken(id uint, token string) (tb_subscription, error) {
	store.Lock()
	defer store.Unlock()
	next := cloneLocalManagerData(store.data)
	for index := range next.Subscriptions {
		if next.Subscriptions[index].ID == id {
			next.Subscriptions[index].Token = token
			next.Subscriptions[index].UpdatedAt = time.Now().UTC()
			if err := validateLocalManagerData(next); err != nil {
				return tb_subscription{}, err
			}
			if err := store.saveLocked(next); err != nil {
				return tb_subscription{}, err
			}
			store.data = next
			return next.Subscriptions[index], nil
		}
	}
	return tb_subscription{}, os.ErrNotExist
}
