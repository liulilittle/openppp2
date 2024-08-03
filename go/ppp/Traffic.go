package ppp

import (
	"fmt"
	"ppp/io"
	"strconv"
	"strings"
)

type _vpn_user_upload_traffic_task struct {
	Guid string `json:"Guid"`
	RX   int64  `json:"RX"`
	TX   int64  `json:"TX"`
}

type _vpn_user_upload_traffic_task_json_object struct {
	Guid string `json:"Guid"`
	RX   string `json:"RX"`
	TX   string `json:"TX"`
}

type _vpn_user_upload_traffic_task_json_array struct {
	Tasks []*_vpn_user_upload_traffic_task_json_object `json:"Tasks"`
}

func (my *ManagedServer) server_on_traffic_unpack_many_tasks(ws *io.WebSocket, packet *_Packet) (int, []*_vpn_user_upload_traffic_task) {
	json_string := packet.Data
	if json_string == "" {
		return 0, nil
	}

	var v _vpn_user_upload_traffic_task_json_array
	if !JsonAuxiliary.Deserialize(json_string, &v) {
		return -1, nil
	}

	tasks := v.Tasks
	if len(tasks) < 1 {
		return 0, nil
	}

	list := make([]*_vpn_user_upload_traffic_task, 0)
	for _, task := range tasks {
		guid := task.Guid
		if !StringAuxiliary.IsGuid(guid) {
			continue
		}

		RX, err := strconv.ParseUint(task.RX, 10, 64)
		if err != nil {
			continue
		}

		TX, err := strconv.ParseUint(task.TX, 10, 64)
		if err != nil {
			continue
		}

		if RX < 1 && TX < 1 {
			continue
		}

		guid = strings.ToUpper(guid)
		list = append(list, &_vpn_user_upload_traffic_task{
			RX:   int64(RX),
			TX:   int64(TX),
			Guid: guid,
		})
	}

	if len(list) < 1 {
		return 0, nil
	} else {
		return 0, list
	}
}

func (my *ManagedServer) server_on_traffic_sync_dirty_to_redis(ws *io.WebSocket, packet *_Packet) (int, []*_vpn_user_upload_traffic_task) {
	// Unpack the passed multiple sync task data from the Packet.
	status, tasks := my.server_on_traffic_unpack_many_tasks(ws, packet)
	if status != 0 || len(tasks) < 1 {
		return status, nil
	}

	// Data variables that need temporary storage on the stack.
	sync_to_redis_members := make([]any, 0)
	sync_to_local_tasks := make([]*_vpn_user_upload_traffic_task, 0)

	// The pre-check of synchronous data streams, which does not use versions/memos/transactions pattern,
	// Can significantly improve performance and reduce memory load power consumption because the server is designed for SP/A and MT/A.
	for _, v := range tasks {
		guid := v.Guid

		// Get user base information from the local cache using the GUID primary key.
		my.Lock()
		user, ok := my.users[guid]
		my.Unlock()

		// Try to load user base information from redis or mysql using the GUID primary key.
		if !ok {
			status, user, _, _ = my.server_load_user_by_guid(guid)
			if status != 0 {
				continue
			}
		}

		// Check whether the changes of user basic information rx and tx need to be synchronized to redis and mysql databases in advanced.
		old_rx := user.IncomingTraffic
		old_tx := user.OutgoingTraffic

		new_rx := max(0, old_rx+int64(v.RX))
		new_tx := max(0, old_tx+int64(v.TX))

		if new_rx != old_rx || new_tx != old_tx {
			sync_to_local_tasks = append(sync_to_local_tasks, v)
			sync_to_redis_members = append(sync_to_redis_members, guid)
		}
	}

	// Success is returned directly if no member data is generated that needs to be synchronized to set dirty tags to redis.
	if len(sync_to_redis_members) < 1 {
		return 0, nil
	}

	// Try to write the dirty label of synchronized data to the redis distributed cache cluster system, if it fails, give up and print an error.
	err := my.redis.SAdd(_REDIS_USER_SYNC_KEY, sync_to_redis_members...)
	if err != nil {
		fmt.Println(err)
		return -1, nil
	} else {
		return status, sync_to_local_tasks
	}
}

func (my *ManagedServer) server_on_traffic_sync_dirty_to_local(server *tb_server, tasks []*_vpn_user_upload_traffic_task) *_vpn_user_json_token_array {
	// Only if the passed task list is not empty.
	if len(tasks) < 1 {
		return nil
	}

	my.Lock()
	defer my.Unlock()

	// Synchronize all task data changes to the local memory.
	var list _vpn_user_json_token_array
	for _, v := range tasks {
		user, ok := my.users[v.Guid]
		if !ok {
			continue
		} else {
			my.dirty[v.Guid] = true
		}

		user.Lock()
		user.IncomingTraffic = max(0, user.IncomingTraffic-int64(v.RX))
		user.OutgoingTraffic = max(0, user.OutgoingTraffic-int64(v.TX))
		user.Unlock()

		token := &_vpn_user{
			Guid:            user.Guid,
			IncomingTraffic: user.IncomingTraffic,
			OutgoingTraffic: user.OutgoingTraffic,
			ExpiredTime:     user.ExpiredTime,
			BandwidthQoS:    my.server_calc_qos_by_server_and_user(server, user),
		}
		list.List = append(list.List, token)
	}
	return &list
}

func (my *ManagedServer) server_on_traffic(ws *io.WebSocket, packet *_Packet) int {
	// Check whether the server that the VPN user wants to login to exists!
	server, _, err := my.server_find_server_by_server(packet.Node)
	if err != nil {
		LOG_ERROR.Println(err)
		return -1
	}

	// Synchronize all user data changed by traffic data to redis.
	status, tasks := my.server_on_traffic_sync_dirty_to_redis(ws, packet)
	if status != 0 {
		return status
	}

	// Synchronize all user data that has changed traffic data to local.
	token := my.server_on_traffic_sync_dirty_to_local(server, tasks)
	if token != nil {
		packet.Data = JsonAuxiliary.Serialize(token)
	}

	return 0
}
