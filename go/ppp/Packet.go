package ppp

import (
	"fmt"
	"ppp/io"
	"strconv"
	"strings"
)

type _Packet struct {
	Id   int    `json:"Id"`
	Node int    `json:"Node"`
	Guid string `json:"Guid"`
	Cmd  int    `json:"Cmd"`
	Data string `json:"Data"`
}

const (
	_PACKET_CMD_ECHO           = 1000
	_PACKET_CMD_CONNECT        = 1001
	_PACKET_HEADER_LENGTH      = 8
	_PACKET_CMD_AUTHENTICATION = 1002
	_PACKET_CMD_TRAFFIC        = 1003
)

func (my *ManagedServer) send_json_to_peer(ws *io.WebSocket, messages string) bool {
	if messages == "" {
		return false
	}

	packet := []byte(messages)
	packet_length := len(packet)

	if packet == nil || packet_length < 1 {
		return false
	}

	hex := fmt.Sprintf("%08x", packet_length)
	if len(hex) != 8 {
		return false
	}

	packet = append([]byte(hex), packet...)
	return ws.Write(packet, 0, len(packet))
}

func (my *ManagedServer) send_packet_to_peer(ws *io.WebSocket, packet *_Packet) bool {
	if packet == nil {
		return false
	}

	json := JsonAuxiliary.Serialize(packet)
	return my.send_json_to_peer(ws, json)
}

func (my *ManagedServer) send_packet_to_peer_ex(ws *io.WebSocket, cmd int, id int, node int, guid string, data string) bool {
	packet := &_Packet{
		Id:   id,
		Cmd:  cmd,
		Node: node,
		Guid: guid,
		Data: data,
	}
	return my.send_packet_to_peer(ws, packet)
}

func (my *ManagedServer) read_json_from_peer(ws *io.WebSocket) string {
	content := ws.Read()
	content_length := 0
	if content != nil {
		content_length = len(content)
	}

	if content_length < _PACKET_HEADER_LENGTH {
		return ""
	}

	header_length := string(content[:_PACKET_HEADER_LENGTH])
	packet_length, err := strconv.ParseInt(header_length, 16, 32)
	if err != nil {
		return ""
	} else if packet_length < 1 {
		return ""
	} else {
		n := packet_length + _PACKET_HEADER_LENGTH
		if n != int64(content_length) {
			return ""
		}
	}

	json := string(content[_PACKET_HEADER_LENGTH:])
	return StringAuxiliary.Trim(json)
}

func (my *ManagedServer) read_packet_from_peer(ws *io.WebSocket) *_Packet {
	message := my.read_json_from_peer(ws)
	if message == "" {
		return nil
	}

	var packet _Packet
	if !JsonAuxiliary.Deserialize(message, &packet) {
		return nil
	}

	guid := packet.Guid
	packet.Guid = strings.ToUpper(guid)
	return &packet
}
