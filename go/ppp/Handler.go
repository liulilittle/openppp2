package ppp

import (
	"math"
	"net/http"
	"ppp/io"
	"strconv"
	"strings"
)

type _HttpResponse struct {
	Code    int    `json:"Code"`
	Message string `json:"Message"`
	Tag     string `json:"Tag"`
}

const (
	_ERROR_OK                 = 0   // success.
	_ERROR_OPERATING_TOO_FAST = 1   // operating too fast.
	_ERROR_JSON               = 2   // json error.
	_ERROR_ARG                = 11  // argument error.
	_ERROR_ARG_GUID           = 12  // argument guid error.
	_ERROR_ARG_NODE           = 13  // argument node error.
	_ERROR_ARG_KEY            = 14  // argument key error.
	_ERROR_ARG_TX             = 15  // argument tx error.
	_ERROR_ARG_RX             = 16  // argument rx error.
	_ERROR_ARG_QOS            = 17  // argument qos error.
	_ERROR_ARG_SECONDS        = 18  // argument seconds error
	_ERROR_DB                 = 101 // db access error.
	_ERROR_REDIS              = 151 // redis access error.
	_ERROR_REDIS_CONFLICT     = 152 // redis key conflict.
	_ERROR_USER_NOT_EXISTS    = 201 // consumer not found.
	_ERROR_USER_NOT_LOGIN     = 202 // consumer not login.
	_ERROR_USER_ALREAY_EXISTS = 203 // consumer alreay exists.
	_ERROR_SERVER_NOT_EXISTS  = 301 // server not found.
)

func (my *ManagedServer) websocket_api_on_echo(ws *io.WebSocket, packet *_Packet) {
	server := my.server_get_node(ws)
	if server != nil {
		my.server_active_node(server)
	}

	cmd := packet.Cmd
	if cmd == _PACKET_CMD_ECHO {
		my.send_packet_to_peer(ws, packet)
	}
}

func (my *ManagedServer) websocket_api_on_connect(ws *io.WebSocket, packet *_Packet) bool {
	if packet.Data != my.configuration.Key {
		return false
	}

	server, _, err := my.server_find_server_by_server(packet.Node)
	if err != nil {
		my.send_packet_to_peer_ex(ws, _PACKET_CMD_CONNECT, packet.Id, packet.Node, packet.Guid, "0")
		return false
	} else {
		ok := my.send_packet_to_peer_ex(ws, _PACKET_CMD_CONNECT, packet.Id, packet.Node, packet.Guid, "1")
		if !ok {
			return false
		}
	}

	my.server_add_node(ws, server.Id)
	return true
}

func (my *ManagedServer) websocket_api_on_traffic(ws *io.WebSocket, packet *_Packet) {
	status := my.server_on_traffic(ws, packet)
	if status > -1 {
		my.send_packet_to_peer(ws, packet)
	}
}

func (my *ManagedServer) websocket_api_on_authentication(ws *io.WebSocket, packet *_Packet) {
	status, user := my.server_on_authentication(ws, packet.Guid, packet.Node)
	if status > -1 {
		if user != nil {
			packet.Data = JsonAuxiliary.Serialize(user)
		}

		my.send_packet_to_peer(ws, packet)
	}
}

func (my *ManagedServer) http_api_send_response_ex(w http.ResponseWriter, code int, tag string, msg error) {
	var what string

	if msg != nil {
		what = msg.Error()
	}

	my.http_api_send_response(w, code, tag, what)
}

func (my *ManagedServer) http_api_send_response(w http.ResponseWriter, code int, tag string, msg string) {
	if code == _ERROR_OK {
		if len(msg) < 1 {
			msg = "ok"
		}
	}

	r := &_HttpResponse{
		Code:    code,
		Tag:     tag,
		Message: msg,
	}

	json := JsonAuxiliary.Serialize(r)
	w.Write([]byte(json))
}

func (my *ManagedServer) http_api_server_get(w http.ResponseWriter, r *http.Request) bool {
	q := r.URL.Query()
	node := 0
	node_i64, err := strconv.ParseInt(io.HttpQuery(q, "node"), 10, 64)
	if err != nil {
		my.http_api_send_response_ex(w, _ERROR_ARG_NODE, "", err)
		return false
	} else {
		node = int(node_i64)
	}

	server, code, err := my.server_find_server_by_server(node)
	if err != nil {
		my.http_api_send_response_ex(w, code, "", err)
		return false
	}

	json := JsonAuxiliary.Serialize(server)
	my.http_api_send_response(w, code, json, "")
	return true
}

func (my *ManagedServer) http_api_server_all(w http.ResponseWriter, r *http.Request) bool {
	type server_all_json_array struct {
		List []*tb_server `json:"List"`
	}

	var packet server_all_json_array
	packet.List = make([]*tb_server, 0)

	my.Lock()
	for _, v := range my.servers {
		packet.List = append(packet.List, v)
	}
	my.Unlock()

	json := JsonAuxiliary.Serialize(packet)
	my.http_api_send_response(w, _ERROR_OK, json, "")
	return true
}

func (my *ManagedServer) http_api_server_load(w http.ResponseWriter, r *http.Request) bool {
	code, err := my.server_load_all_servers()
	if err != nil {
		my.http_api_send_response_ex(w, code, "", err)
		return false
	}

	return my.http_api_server_all(w, r)
}

func (my *ManagedServer) http_api_consumer_set_or_new(w http.ResponseWriter, r *http.Request, set_or_new bool) bool {
	q := r.URL.Query()
	key := io.HttpQuery(q, "key")

	if key != my.configuration.Key {
		my.http_api_send_response(w, _ERROR_ARG_KEY, "", "")
		return false
	}

	guid := io.HttpQuery(q, "guid")
	guid = strings.ToUpper(guid)

	if !StringAuxiliary.IsGuid(guid) {
		my.http_api_send_response(w, _ERROR_ARG_GUID, "", "")
		return false
	}

	tx, err := strconv.ParseInt(io.HttpQuery(q, "tx"), 10, 64)
	if err != nil {
		my.http_api_send_response_ex(w, _ERROR_ARG_TX, "", err)
		return false
	}

	rx, err := strconv.ParseInt(io.HttpQuery(q, "rx"), 10, 64)
	if err != nil {
		my.http_api_send_response_ex(w, _ERROR_ARG_RX, "", err)
		return false
	}

	seconds, err := strconv.ParseUint(io.HttpQuery(q, "seconds"), 10, 64)
	if err != nil {
		my.http_api_send_response_ex(w, _ERROR_ARG_SECONDS, "", err)
		return false
	}

	qos, err := strconv.ParseUint(io.HttpQuery(q, "qos"), 10, 64)
	if err != nil {
		my.http_api_send_response_ex(w, _ERROR_ARG_QOS, "", err)
		return false
	}

	tx = max(0, tx)
	rx = max(0, rx)
	qos = min(qos, math.MaxUint32)
	seconds = min(seconds, math.MaxUint32)

	if tx < 1 || rx < 1 || seconds < 1 {
		my.http_api_send_response(w, _ERROR_ARG, "", "argument (tx, rx, seconds) cannot be less than or equal to 0")
		return false
	}

	if set_or_new {
		user, code, err := my.server_user_set_traffic_and_seconds(guid, rx, tx, uint32(seconds), uint32(qos))
		if err != nil {
			my.http_api_send_response_ex(w, code, "", err)
			return false
		}

		json := JsonAuxiliary.Serialize(user)
		my.http_api_send_response(w, _ERROR_OK, json, "")
	} else {
		code := my.server_user_new_to_databases(guid, rx, tx, uint32(seconds), uint32(qos))
		my.http_api_send_response(w, code, "", "")
	}
	return true
}

func (my *ManagedServer) http_api_consumer_set(w http.ResponseWriter, r *http.Request) bool {
	return my.http_api_consumer_set_or_new(w, r, true)
}

func (my *ManagedServer) http_api_consumer_new(w http.ResponseWriter, r *http.Request) bool {
	return my.http_api_consumer_set_or_new(w, r, false)
}

func (my *ManagedServer) http_api_consumer_load(w http.ResponseWriter, r *http.Request, reload bool) bool {
	q := r.URL.Query()
	key := io.HttpQuery(q, "key")

	if key != my.configuration.Key {
		my.http_api_send_response(w, _ERROR_ARG_KEY, "", "")
		return false
	}

	guid := io.HttpQuery(q, "guid")
	guid = strings.ToUpper(guid)

	if !StringAuxiliary.IsGuid(guid) {
		my.http_api_send_response(w, _ERROR_ARG_GUID, "", "")
		return false
	}

	if !reload {
		my.Lock()
		_, ok := my.users[guid]
		my.Unlock()

		if !ok {
			my.http_api_send_response(w, _ERROR_USER_NOT_LOGIN, "", "")
			return false
		}
	}

	status, user, code, err := my.server_load_user_by_guid(guid)
	if status != 0 {
		my.http_api_send_response_ex(w, code, "", err)
		return false
	}

	json := JsonAuxiliary.Serialize(user)
	my.http_api_send_response(w, _ERROR_OK, json, "")
	return true
}
