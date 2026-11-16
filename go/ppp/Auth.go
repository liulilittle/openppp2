package ppp

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"ppp/io"
)

// _MAX_TRAFFIC_REPORT bounds a single RX/TX counter in a traffic report (1 TiB).
const _MAX_TRAFFIC_REPORT = int64(1) << 40

// secureEqual compares two secrets in constant time. Both inputs are hashed
// first so the comparison cost does not depend on the length of either side.
func secureEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// http_api_key_authorized checks the shared key, accepted either as the
// legacy ?key= query parameter or as an "Authorization: Bearer <key>" header.
func (my *ManagedServer) http_api_key_authorized(r *http.Request) bool {
	want := my.configuration.Key
	if secureEqual(io.HttpQuery(r.URL.Query(), "key"), want) {
		return true
	}

	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		return secureEqual(strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")), want)
	}
	return false
}

// parse_traffic_counter parses a reported RX/TX counter. Values that are not
// plain non-negative decimals, or exceed _MAX_TRAFFIC_REPORT, are rejected so
// that they can never wrap into a negative int64.
func parse_traffic_counter(s string) (int64, bool) {
	var n uint64
	if len(s) < 1 || len(s) > 20 {
		return 0, false
	}
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, false
		}
		d := uint64(c - '0')
		if n > (^uint64(0)-d)/10 {
			return 0, false
		}
		n = n*10 + d
	}
	if n > uint64(_MAX_TRAFFIC_REPORT) {
		return 0, false
	}
	return int64(n), true
}

// node_matches_session reports whether a node id claimed in a packet equals
// the node bound to the websocket at handshake time.
func node_matches_session(ws *io.WebSocket, node int) bool {
	if ws == nil {
		return false
	}
	bound, ok := ws.Tag.(int)
	return ok && bound > 0 && bound == node
}
