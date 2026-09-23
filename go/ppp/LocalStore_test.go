package ppp

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultStandaloneConfiguration(t *testing.T) {
	cfg := LoadManagedServerConfiguration(filepath.Join(t.TempDir(), "missing.json"))
	if cfg == nil {
		t.Fatal("missing configuration did not produce standalone defaults")
	}
	if cfg.Prefixes != ":10000" || cfg.Path != "/ppp/webhook" || cfg.Admin.Path != "/admin/" {
		t.Fatalf("unexpected standalone defaults: %#v", cfg)
	}
	if cfg.Admin.DataPath != "manager-data.json" {
		t.Fatalf("data path = %q", cfg.Admin.DataPath)
	}
	managed, err := cfg.ManagedMode()
	if err != nil || managed {
		t.Fatalf("standalone ManagedMode = %v, %v", managed, err)
	}
}

func TestLocalStorePersistsIdentityAndRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manager-data.json")
	store, err := OpenLocalStore(path, "", "https://sub.example.com")
	if err != nil {
		t.Fatal(err)
	}
	adminToken := store.AdminToken()
	if adminToken == "" {
		t.Fatal("admin token was not generated")
	}
	initial, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(initial, []byte("null")) {
		t.Fatalf("new local manager data contains null collections: %s", initial)
	}

	server, err := store.CreateServer(tb_server{Name: "Mobile", Link: "ppp://vpn.example.com:20000/"})
	if err != nil {
		t.Fatal(err)
	}
	item, err := store.CreateSubscription(tb_subscription{
		Name: "Demo", UserGuid: "F4569420-4E49-4CBA-9C36-94E722C8E363",
		ServerIDsJSON: "[1]", OptionsJSON: "{}", Enabled: true, Token: "public-token",
	})
	if err != nil {
		t.Fatal(err)
	}

	reloaded, err := OpenLocalStore(path, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.AdminToken() != adminToken || reloaded.PublicBaseURL() != "https://sub.example.com" {
		t.Fatal("local manager identity did not survive reload")
	}
	servers := reloaded.ListServers()
	subscriptions := reloaded.ListSubscriptions()
	if len(servers) != 1 || servers[0].Id != server.Id || len(subscriptions) != 1 || subscriptions[0].ID != item.ID {
		t.Fatalf("reloaded records = %#v, %#v", servers, subscriptions)
	}
}

func TestManagedModeRequiresCompleteExternalConfiguration(t *testing.T) {
	cfg := defaultManagedServerConfiguration()
	cfg.Database = &DBRootConfiguration{}
	if managed, err := cfg.ManagedMode(); err == nil || managed {
		t.Fatalf("partial ManagedMode = %v, %v", managed, err)
	}

	cfg.Database.Master = &DBNodeConfiguration{Host: "mysql", Port: 3306, DbName: "ppp"}
	cfg.Redis = &RedisConfiguration{Addresses: []string{"redis:26379"}, MasterName: "mymaster"}
	if managed, err := cfg.ManagedMode(); err != nil || !managed {
		t.Fatalf("complete ManagedMode = %v, %v", managed, err)
	}
}
