package ppp

import (
	"container/list"
	"errors"
	"net/http"
	"ppp/io"
	"sync"
)

type ManagedServer struct {
	sync.Mutex
	disposed      bool
	ppp           *io.WebSocketServer
	configuration *ManagedServerConfiguration
	redis         *io.RedisClient

	servers map[int]*tb_server
	nodes   map[int]*_vpn_server
	users   map[string]*_vpn_user
	dirty   map[string]bool

	db_master *io.DB
	db_salves *list.List
}

func (my *ManagedServer) FetchDB(read_only bool) *io.DB {
	my.Lock()
	defer my.Unlock()

	if !read_only {
		return my.db_master
	}

	salves := my.db_salves
	if salves == nil {
		return my.db_master
	}

	for salves.Len() > 0 {
		i := salves.Front()
		if i == nil {
			return my.db_master
		}

		db, ok := i.Value.(*io.DB)
		salves.Remove(i)

		if !ok {
			continue
		}

		salves.PushBack(db)
		return db
	}
	return my.db_master
}

func NewManagedServer() (*ManagedServer, error) {
	// Read in managed ppp configuration files structures.
	cfg := LoadManagedServerConfigurationByOsArgs()
	if cfg == nil {
		return nil, errors.New("unable to find a valid configuration files, failed to instantiate the managed ppp")
	}

	// Link to redis nosql database nodes via redis v8 library (sentinel mode).
	redis, err := server_connect_all_redis(cfg)
	if err != nil {
		return nil, err
	}

	// Link to the mysql database nodes through the gorm framework.
	master_db, salve_dbs, err := server_connect_all_databases(cfg)
	if err != nil {
		return nil, err
	}

	// Instantiate one and construct the management ppp object instance.
	ppp := &ManagedServer{
		disposed:      false,
		configuration: cfg,
		db_master:     master_db,
		db_salves:     salve_dbs,
		redis:         redis,
		nodes:         make(map[int]*_vpn_server),
		users:         make(map[string]*_vpn_user),
		dirty:         make(map[string]bool),
	}

	// Instantiate a WebSocket ppp, taking care to only instantiate WebSocket nodes
	// That are based on the transparent HTTP protocol, not those that also support SSL.
	wsserver, err := io.NewWebSocketServer(cfg.Prefixes, cfg.Path,
		func(ws *io.WebSocket) bool {
			ok := ppp.accept(ws)
			if ok {
				ppp.run(ws)
			}

			ws.Close()
			return ok
		}, ppp.request)
	if err != nil {
		return nil, err
	}

	ppp.ppp = wsserver
	return ppp, nil
}

func (my *ManagedServer) ListenAndServe() error {
	ppp := my.ppp
	if ppp == nil {
		return errors.New("ppp is closed")
	}

	// Push all server list data to the redis distributed cache cluster.
	_, err := my.server_load_all_servers()
	if err != nil {
		return err
	}

	// Push all user data into the local cache if it needs to be loaded.
	err = my.server_load_all_users()
	if err != nil {
		return err
	}

	// Run the server and always tick processing coroutines.
	go my.server_tick()
	return ppp.ListenAndServe()
}

func (my *ManagedServer) accept(ws *io.WebSocket) bool {
	ppp := my.server_load()
	if ppp == nil {
		return false
	}

	packet := my.read_packet_from_peer(ws)
	if packet == nil {
		return false
	} else if packet.Cmd != _PACKET_CMD_CONNECT {
		return false
	} else if packet.Node < 1 {
		return false
	}

	return my.websocket_api_on_connect(ws, packet)
}

func (my *ManagedServer) run(ws *io.WebSocket) {
	var ppp *io.WebSocketServer
	for {
		ppp = my.server_load()
		if ppp == nil {
			break
		}

		packet := my.read_packet_from_peer(ws)
		if packet == nil {
			break
		}

		cmd := packet.Cmd
		if cmd == _PACKET_CMD_ECHO {
			my.websocket_api_on_echo(ws, packet)
			continue
		} else {
			my.websocket_api_on_echo(ws, packet)
		}

		switch cmd {
		case _PACKET_CMD_AUTHENTICATION:
			my.websocket_api_on_authentication(ws, packet)
		case _PACKET_CMD_TRAFFIC:
			my.websocket_api_on_traffic(ws, packet)
		}
	}

	my.server_del_node(ws)
}

func (my *ManagedServer) request(w http.ResponseWriter, r *http.Request) {
	if io.HttpIsInPath(my.configuration.Interfaces.ConsumerSet, r.RequestURI) {
		my.http_api_consumer_set(w, r)
	} else if io.HttpIsInPath(my.configuration.Interfaces.ConsumerNew, r.RequestURI) {
		my.http_api_consumer_new(w, r)
	} else if io.HttpIsInPath(my.configuration.Interfaces.ConsumerReload, r.RequestURI) {
		my.http_api_consumer_load(w, r, true)
	} else if io.HttpIsInPath(my.configuration.Interfaces.ConsumerLoad, r.RequestURI) {
		my.http_api_consumer_load(w, r, false)
	} else if io.HttpIsInPath(my.configuration.Interfaces.ServerAll, r.RequestURI) {
		my.http_api_server_all(w, r)
	} else if io.HttpIsInPath(my.configuration.Interfaces.ServerGet, r.RequestURI) {
		my.http_api_server_get(w, r)
	} else if io.HttpIsInPath(my.configuration.Interfaces.ServerLoad, r.RequestURI) {
		my.http_api_server_load(w, r)
	} else {
		http.NotFound(w, r)
	}

	io.HttpFlush(w)
}

func (my *ManagedServer) IsDisposed() bool {
	return my.disposed
}

func (my *ManagedServer) Dispose() {
	// Sets the disposed flag for the current managed server instance to released.
	var disposed bool = false

	my.Lock()
	disposed =
		my.disposed
	my.disposed = true
	my.Unlock()

	// Must first be forced to shut down the network server ws server listening, then in processing data archive.
	server := my.server_exchange(nil)
	if server != nil {
		server.Close()
	}

	// Forcibly close the WS link between all VPN server nodes and this server.
	my.server_close_all_nodes()

	// If the object has not been released, the business logic that the server program needs to process is released.
	if !disposed {
		// Force all changed user base data to be archived immediately.
		// If storage is not completed or fails, please solve the problem between distributed clusters as soon as possible
		// Before restarting the server program to complete automatic archiving.
		my.server_sync_all_users_to_databases(true)
	}
}
