package ppp

import (
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

type ManagedServerConfiguration struct {
	Database           *DBRootConfiguration             `json:"database"`
	Redis              *RedisConfiguration              `json:"redis"`
	Key                string                           `json:"key"`
	Path               string                           `json:"path"`
	Prefixes           string                           `json:"prefixes"`
	Interfaces         *InterfacesConfiguration         `json:"interfaces"`
	ConcurrencyControl *ConcurrencyControlConfiguration `json:"concurrency-control"`
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
		if json == "" {
			return nil
		}
	}

	var cfg ManagedServerConfiguration
	if !JsonAuxiliary.Deserialize(json, &cfg) {
		return nil
	}

	redis := cfg.Redis
	database := cfg.Database

	if cfg.ConcurrencyControl == nil || cfg.Interfaces == nil || cfg.Prefixes == "" {
		return nil
	} else if redis == nil || database == nil || database.Master == nil {
		return nil
	} else if len(redis.Addresses) < 1 || redis.MasterName == "" {
		return nil
	} else {
		return &cfg
	}
}
