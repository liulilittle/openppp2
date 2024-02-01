package io

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"ppp/auxiliary"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

type WebSocket struct {
	connection *websocket.Conn
	ppp        *WebSocketServer
	disposed   bool
	Tag        any
}

type WebSocketServer struct {
	sync.Mutex
	ppp         *http.Server
	path        string
	acceptor    func(*WebSocket) bool
	request     func(http.ResponseWriter, *http.Request)
	connections *_WebConnectionTable
}

type _WebConnectionTable struct {
	m map[*websocket.Conn]*WebSocket
}

var StringAuxiliary auxiliary.StringAuxiliary
var upgrader_ = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // 允许所有的请求来源
	},
}

func NewWebSocketServer(prefixes string, path string, acceptor func(*WebSocket) bool, request func(http.ResponseWriter, *http.Request)) (*WebSocketServer, error) {
	if prefixes == "" {
		return nil, errors.New("prefixes is null or empty")
	}

	if acceptor == nil {
		return nil, errors.New("acceptor is null")
	}

	ppp := &http.Server{
		Addr: prefixes,
	}
	wsserver := WebSocketServer{
		ppp:      ppp,
		path:     path,
		acceptor: acceptor,
		request:  request,
		connections: &_WebConnectionTable{
			m: make(map[*websocket.Conn]*WebSocket),
		},
	}
	ppp.Handler = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			err := wsserver.onRequest(w, r)
			if err != nil {
				log.Println("Failed to upgrade connection:", err)
			}
		})
	return &wsserver, nil
}

func (my *WebSocketServer) server_load() *http.Server {
	my.Lock()
	defer my.Unlock()

	return my.ppp
}

func (my *WebSocketServer) server_exchange(http *http.Server) *http.Server {
	my.Lock()
	defer my.Unlock()

	ppp := my.ppp
	my.ppp = http
	return ppp
}

func (my *WebSocketServer) ListenAndServe() error {
	ppp := my.server_load()
	if ppp == nil {
		return errors.New("ppp is closed")
	}

	err := ppp.ListenAndServe()
	if err != http.ErrServerClosed {
		return err
	} else {
		return nil
	}
}

func (my *WebSocketServer) Close() bool {
	ppp := my.server_exchange(nil)
	if ppp == nil {
		return false
	}

	my.Lock()
	connections := my.connections
	my.connections = nil
	my.Unlock()

	if connections != nil {
		for _, v := range connections.m {
			v.Close()
		}
	}

	ppp.Close()
	return true
}

func (my *WebSocketServer) release(key *websocket.Conn) bool {
	connections := my.connections
	if connections == nil {
		return false
	}

	ws := connections.del(my, key)
	if ws == nil {
		return false
	} else {
		return ws.Close()
	}
}

func HttpFlush(w http.ResponseWriter) bool {
	f, ok := w.(http.Flusher)
	if !ok {
		return false
	} else if f != nil {
		f.Flush()
		return true
	} else {
		return false
	}
}

func HttpIsInPath(root string, sw string) bool {
	if len(root) <= 1 {
		return true
	}

	path := "/"
	if len(sw) > 0 {
		path = strings.ToLower(StringAuxiliary.Trim(sw))
		if path == "" {
			return false
		}
	}

	sz := strings.IndexAny(path, "?#")
	if sz != -1 {
		path = path[:sz]
	}

	if len(path) < len(root) {
		return false
	}

	lroot := strings.ToLower(root)
	if path == lroot {
		return true
	}

	if len(path) == len(lroot) {
		return false
	}

	ch := path[len(lroot)]
	return ch == '/'
}

func HttpQuery(values url.Values, key string) string {
	v := values[key]
	if len(v) < 1 {
		return ""
	} else {
		return v[0]
	}
}

func (my *WebSocketServer) onRequest(w http.ResponseWriter, r *http.Request) error {
	ok := HttpIsInPath(my.path, r.RequestURI) /* r.URL.Path */
	if !ok {
		// Deliver the request HTTP to a custom handler.
		request := my.request
		if request == nil {
			http.NotFound(w, r)
			HttpFlush(w)
		} else {
			request(w, r)
		}
	} else {
		// Upgrade the HTTP connection to a WebSocket connection
		connection, err := upgrader_.Upgrade(w, r, nil)
		if err != nil {
			http.Error(w, "503 service unavailable", http.StatusServiceUnavailable)
			HttpFlush(w)
			return err
		}

		// Add the client to the connections
		wc := my.connections.add(my, connection)
		if wc == nil {
			http.Error(w, "500 internal server error", http.StatusInternalServerError)
			HttpFlush(w)
		} else {
			go func(wc *WebSocket) {
				wc.run()
				wc.Close()
			}(wc)
		}
	}
	return nil
}

func (my *_WebConnectionTable) add(s *WebSocketServer, connection *websocket.Conn) *WebSocket {
	m := my.m
	wc := WebSocket{
		ppp:        s,
		connection: connection,
	}

	s.Lock()
	defer s.Unlock()

	m[connection] = &wc
	return &wc
}

func (my *_WebConnectionTable) del(s *WebSocketServer, key *websocket.Conn) *WebSocket {
	var wc *WebSocket
	m := my.m

	s.Lock()
	defer s.Unlock()

	if value, ok := m[key]; ok {
		wc = value
		delete(m, key)
	}

	return wc
}

func (my *WebSocket) acceptor_load() func(*WebSocket) bool {
	if my.disposed {
		return nil
	}

	ppp := my.ppp
	if ppp == nil {
		return nil
	}

	httpd := ppp.server_load()
	if httpd == nil {
		return nil
	}

	return ppp.acceptor
}

func (my *WebSocket) run() bool {
	acceptor := my.acceptor_load()
	if acceptor == nil {
		return false
	} else {
		return acceptor(my)
	}
}

func (my *WebSocket) Close() bool {
	connection := my.connection
	if my.disposed {
		return false
	}

	my.disposed = true
	if connection == nil {
		return false
	}

	ppp := my.ppp
	if ppp != nil {
		ppp.release(connection)
	}

	connection.Close()
	return true
}

func (my *WebSocket) Read() []byte {
	connection := my.connection
	if my.disposed {
		return nil
	}

	if connection == nil {
		return nil
	}

	messageType, p, err := connection.ReadMessage()
	if err != nil {
		return nil
	}

	if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
		return nil
	}
	return p
}

func (my *WebSocket) Write(buffer []byte, offset int, length int) bool {
	if buffer == nil || offset < 0 || length < 0 {
		return false
	}

	if len(buffer) < offset+length {
		return false
	}

	connection := my.connection
	if my.disposed {
		return false
	}

	if connection == nil {
		return false
	}

	messages := buffer[offset : offset+length]
	err := connection.WriteMessage(websocket.BinaryMessage, messages)
	return err == nil
}
