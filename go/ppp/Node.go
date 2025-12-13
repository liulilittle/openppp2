package ppp

import (
	"ppp/io"
	"time"
)

func (my *ManagedServer) server_tick_all_nodes() {
	// Prepares the register variables that need to be used inside the current function.
	now := uint32(time.Now().Unix())
	nodes := my.nodes
	connections := make([]*io.WebSocket, 0)

	// Check the list of WS links that have timed out and do not receive a heartbeat.
	my.Lock()
	for k, v := range nodes {
		if now >= v.timeout {
			connections = append(connections, v.ws)
			delete(nodes, k)
		}
	}
	my.Unlock()

	// Forcibly close the WS node that has timed out and does not receive ECHO heartbeat packets.
	for _, v := range connections {
		v.Close()
	}
}

func (my *ManagedServer) server_add_node(ws *io.WebSocket, node int) {
	my.Lock()
	defer my.Unlock()

	// Update the next timeout time of the VPN node server.
	ws.Tag = node
	server := &_vpn_server{
		ws:      ws,
		timeout: 0,
	}
	my.nodes[node] = server
	my.server_active_node(server)
}

func (my *ManagedServer) server_active_node(server *_vpn_server) {
	// Gets the maximum timeout for the VPN node server websocket connection.
	NODE_WEBSOCKET_TIMEOUT := _NODE_WEBSOCKET_TIMEOUT
	if my.configuration.ConcurrencyControl.NodeWebsocketTimeout > 0 {
		NODE_WEBSOCKET_TIMEOUT = my.configuration.ConcurrencyControl.NodeWebsocketTimeout
	}

	now := uint32(time.Now().Unix())
	server.timeout = now + uint32(NODE_WEBSOCKET_TIMEOUT)
}

func (my *ManagedServer) server_get_node(ws *io.WebSocket) *_vpn_server {
	node, ok := ws.Tag.(int)
	if !ok {
		return nil
	}

	my.Lock()
	defer my.Unlock()

	return my.nodes[node]
}

func (my *ManagedServer) server_del_node(ws *io.WebSocket) {
	node, ok := ws.Tag.(int)
	if ok {
		my.Lock()
		delete(my.nodes, node)
		my.Unlock()
	}

	ws.Close()
}

func (my *ManagedServer) server_close_all_nodes() {
	var nodes map[int]*_vpn_server

	for {
		my.Lock()
		nodes = my.nodes
		my.nodes = make(map[int]*_vpn_server)
		my.Unlock()
		break
	}

	for _, v := range nodes {
		v.ws.Close()
	}
}
