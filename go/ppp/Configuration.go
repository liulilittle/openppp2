package ppp

import (
	"errors"
	"log"
	"os"
	"ppp/auxiliary"
	"ppp/io"
)

type DBNodeConfiguration struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DbName   string `json:"db"`
}

// sentinel-mode
type RedisConfiguration struct {
	Addresses  []string `json:"addresses"`
	MasterName string   `json:"master"`
	DB         int      `json:"db"`
	Password   string   `json:"password"`
}

type DBRootConfiguration struct {
	Master          *DBNodeConfiguration   `json:"master"`
	Slaves          []*DBNodeConfiguration `json:"slaves"`
	MaxOpenConns    int                    `json:"max-open-conns"`
	MaxIdleConns    int                    `json:"max-idle-conns"`
	ConnMaxLifetime int                    `json:"conn-max-life-time"`
}

type ConcurrencyControlConfiguration struct {
	NodeWebsocketTimeout int `json:"node-websocket-timeout"`
	NodeMysqlQuery       int `json:"node-mysql-query"`
	UserMysqlQuery       int `json:"user-mysql-query"`
	UserCacheTimeout     int `json:"user-cache-timeout"`
	UserArchiveTimeout   int `json:"user-archive-timeout"`
}

type InterfacesConfiguration struct {
	ConsumerReload string `json:"consumer-reload"`
	ConsumerLoad   string `json:"consumer-load"`
	ConsumerSet    string `json:"consumer-set"`
	ConsumerNew    string `json:"consumer-new"`
	ServerGet      string `json:"server-get"`
	ServerAll      string `json:"server-all"`
	ServerLoad     string `json:"server-load"`
}

type AdminConfiguration struct {
	Token         string `json:"token"`
	Path          string `json:"path"`
	PublicBaseURL string `json:"public-base-url"`
	DataPath      string `json:"data"`
}

func defaultManagedServerConfiguration() *ManagedServerConfiguration {
	return &ManagedServerConfiguration{
		Prefixes: ":10000",
		Path:     "/ppp/webhook",
		Interfaces: &InterfacesConfiguration{
			ConsumerReload: "/ppp/consumer/reload", ConsumerLoad: "/ppp/consumer/load",
			ConsumerSet: "/ppp/consumer/set", ConsumerNew: "/ppp/consumer/new",
			ServerGet: "/ppp/server/get", ServerAll: "/ppp/server/all", ServerLoad: "/ppp/server/load",
		},
		ConcurrencyControl: &ConcurrencyControlConfiguration{},
		Admin:              &AdminConfiguration{Path: "/admin/", DataPath: "manager-data.json"},
	}
}

func (cfg *ManagedServerConfiguration) ManagedMode() (bool, error) {
	if cfg == nil {
		return false, nil
	}
	hasDatabase := cfg.Database != nil
	hasRedis := cfg.Redis != nil
	if !hasDatabase && !hasRedis {
		return false, nil
	}
	if !hasDatabase || cfg.Database.Master == nil || !hasRedis || len(cfg.Redis.Addresses) == 0 || cfg.Redis.MasterName == "" {
		return false, errors.New("managed mode requires complete database.master and redis configuration")
	}
	return true, nil
}

type ManagedServerConfiguration struct {
	Database           *DBRootConfiguration             `json:"database"`
	Redis              *RedisConfiguration              `json:"redis"`
	Key                string                           `json:"key"`
	Path               string                           `json:"path"`
	Prefixes           string                           `json:"prefixes"`
	Interfaces         *InterfacesConfiguration         `json:"interfaces"`
	ConcurrencyControl *ConcurrencyControlConfiguration `json:"concurrency-control"`
	Admin              *AdminConfiguration              `json:"admin"`
}

var File io.File
var JsonAuxiliary auxiliary.JsonAuxiliary
var StringAuxiliary auxiliary.StringAuxiliary
var LOG_ERROR *log.Logger = auxiliary.LOG_ERROR()

func LoadManagedServerConfigurationByOsArgs() *ManagedServerConfiguration {
	var path string

	args := os.Args
	if len(args) > 1 {
		path = args[1]
	}

	return LoadManagedServerConfiguration(path)
}

func LoadManagedServerConfiguration(path string) *ManagedServerConfiguration {
	json := File.ReadAllText(File.GetFullPath(path))
	if json == "" {
		json = File.ReadAllText(File.GetFullPath("appsettings.json"))
	}

	cfg := defaultManagedServerConfiguration()
	if json != "" && !JsonAuxiliary.Deserialize(json, cfg) {
		return nil
	}
	if cfg.Admin == nil {
		cfg.Admin = &AdminConfiguration{Path: "/admin/", DataPath: "manager-data.json"}
	}
	if token := os.Getenv("OPENPPP2_ADMIN_TOKEN"); token != "" {
		cfg.Admin.Token = token
	}
	adminPath, err := normalizeAdminPath(cfg.Admin.Path)
	if err != nil {
		LOG_ERROR.Println(err)
		return nil
	}
	cfg.Admin.Path = adminPath
	if cfg.Admin.DataPath == "" {
		cfg.Admin.DataPath = "manager-data.json"
	}

	if cfg.ConcurrencyControl == nil || cfg.Interfaces == nil || cfg.Prefixes == "" || cfg.Path == "" {
		return nil
	} else if _, err := cfg.ManagedMode(); err != nil {
		LOG_ERROR.Println(err)
		return nil
	} else {
		return cfg
	}
}
