package ppp

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"ppp/io"
)

func TestSecureEqual(t *testing.T) {
	if !secureEqual("abc", "abc") || secureEqual("abc", "abd") || secureEqual("abc", "abcd") || secureEqual("", "x") {
		t.Fatal("secureEqual returned a wrong result")
	}
}

func TestHttpKeyAuthorized(t *testing.T) {
	my := &ManagedServer{configuration: &ManagedServerConfiguration{Key: "k3y"}}
	cases := []struct {
		target, auth string
		want         bool
	}{
		{"/x?key=k3y", "", true},
		{"/x?key=bad", "", false},
		{"/x", "", false},
		{"/x", "Bearer k3y", true},
		{"/x", "Bearer bad", false},
		{"/x", "k3y", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", c.target, nil)
		if c.auth != "" {
			r.Header.Set("Authorization", c.auth)
		}
		if got := my.http_api_key_authorized(r); got != c.want {
			t.Fatalf("%q auth=%q: got %v want %v", c.target, c.auth, got, c.want)
		}
	}
}

func TestParseTrafficCounter(t *testing.T) {
	good := map[string]int64{"0": 0, "1": 1, "1099511627776": _MAX_TRAFFIC_REPORT}
	for in, want := range good {
		if got, ok := parse_traffic_counter(in); !ok || got != want {
			t.Fatalf("%q: got %d,%v", in, got, ok)
		}
	}
	bad := []string{"", "-1", "+1", "1099511627777", "9223372036854775808", "18446744073709551615", "18446744073709551616", "99999999999999999999999", "1e3", " 1"}
	for _, in := range bad {
		if _, ok := parse_traffic_counter(in); ok {
			t.Fatalf("%q was accepted", in)
		}
	}
}

func TestTrafficUnpackRejectsOverflow(t *testing.T) {
	my := &ManagedServer{}
	body, _ := json.Marshal(map[string]any{"Tasks": []map[string]string{
		{"Guid": "11111111-1111-4111-8111-111111111111", "RX": "18446744073709551615", "TX": "5"},
		{"Guid": "22222222-2222-4222-8222-222222222222", "RX": "9223372036854775808", "TX": "5"},
		{"Guid": "33333333-3333-4333-8333-333333333333", "RX": "10", "TX": "20"},
	}})
	status, list := my.server_on_traffic_unpack_many_tasks(nil, &_Packet{Data: string(body)})
	if status != 0 || len(list) != 1 || list[0].RX != 10 || list[0].TX != 20 || list[0].RX < 0 {
		t.Fatalf("unexpected result: status=%d list=%v", status, list)
	}
}

func TestNodeMustMatchSession(t *testing.T) {
	ws := &io.WebSocket{Tag: 7}
	if !node_matches_session(ws, 7) {
		t.Fatal("bound node was rejected")
	}
	if node_matches_session(ws, 8) || node_matches_session(&io.WebSocket{}, 7) || node_matches_session(nil, 7) {
		t.Fatal("mismatched or unbound node was accepted")
	}

	my := &ManagedServer{}
	if status, user := my.server_on_authentication(ws, "11111111-1111-4111-8111-111111111111", 8); status != -1 || user != nil {
		t.Fatal("authentication with a foreign node was not dropped")
	}
	if status := my.server_on_traffic(ws, &_Packet{Node: 8, Data: "{}"}); status != -1 {
		t.Fatal("traffic with a foreign node was not dropped")
	}
}

func TestSendResponseExHidesDetail(t *testing.T) {
	my := &ManagedServer{}
	w := httptest.NewRecorder()
	my.http_api_send_response_ex(w, _ERROR_DB, "", errString("Error 1045: access denied for user root"))
	if strings.Contains(w.Body.String(), "1045") || strings.Contains(w.Body.String(), "root") {
		t.Fatalf("detail leaked: %s", w.Body.String())
	}
}

type errString string

func (e errString) Error() string { return string(e) }
