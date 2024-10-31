package ppp

import (
	"container/list"
	"errors"
	"fmt"
	"ppp/io"
	"strconv"
	"time"

	"gorm.io/gorm"
)

type _vpn_server struct {
	ws      *io.WebSocket
	timeout uint32
}

type tb_server struct {
	Id int `gorm:"primaryKey;column:id"`

	Link string `gorm:"column:link"`
	Name string `gorm:"column:name"`

	Kf int `gorm:"column:kf"`
	Kx int `gorm:"column:kx"`
	Kl int `gorm:"column:kl"`
	Kh int `gorm:"column:kh"`

	Protocol     string `gorm:"column:protocol"`
	ProtocolKey  string `gorm:"column:protocol_key"`
	Transport    string `gorm:"column:transport"`
	TransportKey string `gorm:"column:transport_key"`

	Masked      bool `gorm:"column:masked"`
	Plaintext   bool `gorm:"column:plaintext"`
	DeltaEncode bool `gorm:"column:delta_encode"`
	ShuffleData bool `gorm:"column:shuffle_data"`

	BandwidthQoS uint32 `gorm:"column:qos"`
}

const (
	_REDIS_NODE_MYSQL_CONCURRENCY_LOCK_KEY     = "ppp:server:concurrency:db"
	_REDIS_NODE_MYSQL_CONCURRENCY_LOCK_TIMEOUT = 1
	_NODE_WEBSOCKET_TIMEOUT                    = 20
)

func (my *ManagedServer) server_find_all_servers() ([]*tb_server, error) {
	DB := my.FetchDB(true).LoadDB()

	var nodes []*tb_server
	result := DB.Find(&nodes)

	err := result.Error
	if err != nil {
		return nil, err
	} else {
		result := make([]*tb_server, 0)
		for _, v := range nodes {
			if v != nil && v.Id > 0 {
				result = append(result, v)
			}
		}
		return result, nil
	}
}

func (my *ManagedServer) server_load_all_servers() (int, error) {
	servers, err := my.server_find_all_servers()
	if err != nil {
		return _ERROR_DB, err
	} else if len(servers) < 1 {
		return _ERROR_OK, nil
	}

	my.Lock()
	defer my.Unlock()

	my.servers = make(map[int]*tb_server)
	for _, server := range servers {
		node := server.Id
		my.servers[node] = server
	}

	return _ERROR_OK, err
}

func (my *ManagedServer) server_find_server_by_server(node int) (*tb_server, int, error) {
	var server *tb_server

	// Get the configurations of the VPN node from the local caches.
	if node < 1 {
		return nil, _ERROR_ARG_NODE, fmt.Errorf("server node id may not be less than 1")
	} else {
		my.Lock()
		server, ok := my.servers[node]
		my.Unlock()
		if ok {
			return server, _ERROR_OK, nil
		}
	}

	// Obtain the lock timeout period for querying the database of the same VPN node.
	SERVER_CONCURRENCY_LOCK_TIMEOUT := _REDIS_NODE_MYSQL_CONCURRENCY_LOCK_TIMEOUT
	if my.configuration.ConcurrencyControl.NodeMysqlQuery > 0 {
		SERVER_CONCURRENCY_LOCK_TIMEOUT = my.configuration.ConcurrencyControl.NodeMysqlQuery
	}

	// Prevents the mysql database from being breached by malicious bursts of concurrent processing that may be working on small nodes.
	key := _REDIS_NODE_MYSQL_CONCURRENCY_LOCK_KEY + ":" + strconv.Itoa(node)
	status := my.redis.SetNX(key, "1", time.Second*time.Duration(SERVER_CONCURRENCY_LOCK_TIMEOUT))
	if status < 0 {
		return nil, _ERROR_REDIS, fmt.Errorf("failed to set the fuse lock flag to the setnx atom in the redis cluster server this may be due to a redis link failure")
	} else if status > 0 {
		return nil, _ERROR_OPERATING_TOO_FAST, fmt.Errorf("attempts to obtain a lock in the redis cluster failed because there was already a server competing for the atomic lock instance")
	}

	// Run the primary key GUID to query the configuration data of the VPN node.
	DB := my.FetchDB(true).LoadDB()
	ER := DB.First(&server, node).Error
	if ER != nil {
		if ER != gorm.ErrRecordNotFound {
			return nil, _ERROR_DB, ER
		}
		return nil, _ERROR_SERVER_NOT_EXISTS, ER
	}

	my.Lock()
	my.servers[node] = server
	my.Unlock()
	return server, _ERROR_OK, nil
}

func server_auto_migrate_all_tables(db *io.DB) error {
	var server tb_server
	err := db.AutoMigrate(&server)
	if err != nil {
		return err
	}

	var user tb_user
	err = db.AutoMigrate(&user)
	if err != nil {
		return err
	}

	return nil
}

func server_connect_all_redis(cfg *ManagedServerConfiguration) (*io.RedisClient, error) {
	redis := io.NewRedisClient(cfg.Redis.MasterName, cfg.Redis.Password, cfg.Redis.Addresses, cfg.Redis.DB)
	if redis == nil {
		return nil, errors.New("unable to instantiate a new redis client instances")
	}

	err := redis.Ping()
	if err != nil {
		redis.Close()
		return nil, err
	}

	return redis, nil
}

func server_connect_all_databases(cfg *ManagedServerConfiguration) (*io.DB, *list.List, error) {
	root := cfg.Database

	var master_db *io.DB
	var dbs *list.List
	var any = false

	finalize := func() bool {
		if any {
			return false
		}

		ok := false
		if dbs != nil && dbs.Len() > 0 {
			for i := dbs.Front(); i != nil; i = i.Next() {
				v, b := i.Value.(*io.DB)
				if !b {
					continue
				}

				err := v.Close()
				if err == nil {
					ok = true
				}
			}
		}

		if master_db != nil {
			err := master_db.Close()
			if err == nil {
				ok = true
			}
		}
		return ok
	}

	defer finalize()

	master_cfg := root.Master
	master_db, err := io.ConnectDB(master_cfg.Host,
		master_cfg.Port,
		master_cfg.User,
		master_cfg.Password,
		master_cfg.DbName,
		root.MaxOpenConns, root.MaxIdleConns, root.ConnMaxLifetime)
	if err != nil {
		return nil, nil, err
	}

	err = server_auto_migrate_all_tables(master_db)
	if err != nil {
		return nil, nil, err
	}

	dbs = list.New()
	for _, v := range root.Slaves {
		db, err := io.ConnectDB(v.Host, v.Port, v.User, v.Password, v.DbName, root.MaxOpenConns, root.MaxIdleConns, root.ConnMaxLifetime)
		if err != nil {
			return nil, nil, err
		}

		any = true
		dbs.PushBack(db)
	}

	if any {
		return master_db, dbs, nil
	}

	return nil, nil, errors.New("no configuration items are configured to open a database link")
}

func (my *ManagedServer) server_tick() {
	for !my.disposed {
		my.server_update()
		time.Sleep(time.Second)
	}
}

func (my *ManagedServer) server_update() {
	// Tick all VPN server node websocket connection processing.
	my.server_tick_all_nodes()

	// Synchronize all user datas to the databases.
	err := my.server_sync_all_users_to_databases(false)
	if err != nil {
		LOG_ERROR.Println(err)
	}
}

func (my *ManagedServer) server_load() *io.WebSocketServer {
	my.Lock()
	defer my.Unlock()

	return my.ppp
}

func (my *ManagedServer) server_exchange(ws *io.WebSocketServer) *io.WebSocketServer {
	my.Lock()
	defer my.Unlock()

	ppp := my.ppp
	my.ppp = ws
	return ppp
}

func (my *ManagedServer) server_calc_qos_by_server_and_user(server *tb_server, user *_vpn_user) uint32 {
	// If the QOS of the user is not specified, the QOS configured on the server is used.
	qos := user.BandwidthQoS
	if qos == 0 {
		qos = server.BandwidthQoS
	}

	return qos
}
