package ppp

import (
	"context"
	"errors"
	"fmt"
	"ppp/io"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

type _vpn_user struct {
	sync.Mutex
	Guid            string `json:"Guid"`
	ArchiveTime     uint32 `json:"ArchiveTime"`
	IncomingTraffic int64  `json:"IncomingTraffic"`
	OutgoingTraffic int64  `json:"OutgoingTraffic"`
	ExpiredTime     uint32 `json:"ExpiredTime"`
	BandwidthQoS    uint32 `json:"BandwidthQoS"`
}

type _vpn_user_json_token_array struct {
	List []*_vpn_user `json:"List"`
}

type tb_user struct {
	Guid            string `gorm:"primaryKey;column:guid"`
	IncomingTraffic int64  `gorm:"column:incoming_traffic"`
	OutgoingTraffic int64  `gorm:"column:outgoing_traffic"`
	ExpiredTime     uint32 `gorm:"column:expired_time"`
	BandwidthQoS    uint32 `gorm:"column:qos"`
}

const (
	_REDIS_USER_SYNC_KEY                       = "ppp:user:sync"
	_REDIS_USER_DATA_KEY                       = "ppp:user:data"
	_REDIS_USER_MYSQL_CONCURRENCY_LOCK_KEY     = "ppp:user:concurrency:db"
	_REDIS_USER_MYSQL_CONCURRENCY_LOCK_TIMEOUT = 1
	_REDIS_USER_CACHE_TIMEOUT                  = 3600
	_REDIS_USER_ARCHIVE_TIMEOUT                = 20
)

func (my *ManagedServer) server_find_user_by_guid(guid string) (*tb_user, error) {
	var user *tb_user

	DB := my.FetchDB(true).LoadDB()
	result := DB.First(&user)

	err := result.Error
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, errors.New("user base information does not exist, and the parameters are incorrect")
	}

	if user.Guid == "" {
		return nil, errors.New("basic user information cannot be found through the guid query")
	}

	return user, nil
}

func (my *ManagedServer) server_sync_user_to_redis(user *tb_user, now uint32, pipeline redis.Pipeliner) error {
	USER_CACHE_TIMEOUT := _REDIS_USER_CACHE_TIMEOUT
	if my.configuration.ConcurrencyControl.UserCacheTimeout > 0 {
		USER_CACHE_TIMEOUT = my.configuration.ConcurrencyControl.UserCacheTimeout
	}

	key := _REDIS_USER_DATA_KEY + ":" + user.Guid
	token := &_vpn_user{
		Guid:            user.Guid,
		ArchiveTime:     now,
		IncomingTraffic: user.IncomingTraffic,
		OutgoingTraffic: user.OutgoingTraffic,
		ExpiredTime:     user.ExpiredTime,
		BandwidthQoS:    user.BandwidthQoS,
	}

	json := JsonAuxiliary.Serialize(token)
	if pipeline == nil {
		return my.redis.Set(key, json, time.Second*time.Duration(USER_CACHE_TIMEOUT))
	}

	ctx := context.Background()
	return pipeline.Set(ctx, key, json, time.Second*time.Duration(USER_CACHE_TIMEOUT)).Err()
}

func (my *ManagedServer) server_query_user_by_guid(guid string, now uint32) (*tb_user, int, error) {
	var user *tb_user
	var err error

	json, err := my.redis.Get(_REDIS_USER_DATA_KEY + ":" + guid)
	if err != nil && err != redis.Nil {
		return nil, _ERROR_REDIS, err
	} else if json != "" {
		if !JsonAuxiliary.Deserialize(json, &user) {
			return nil, _ERROR_JSON, errors.New("failed to deserialize json to user")
		}

		return user, _ERROR_OK, nil
	}

	USER_CONCURRENCY_LOCK_TIMEOUT := _REDIS_USER_MYSQL_CONCURRENCY_LOCK_TIMEOUT
	if my.configuration.ConcurrencyControl.UserMysqlQuery > 0 {
		USER_CONCURRENCY_LOCK_TIMEOUT = my.configuration.ConcurrencyControl.UserMysqlQuery
	}

	status := my.redis.SetNX(_REDIS_USER_MYSQL_CONCURRENCY_LOCK_KEY+":"+guid, "1", time.Second*time.Duration(USER_CONCURRENCY_LOCK_TIMEOUT))
	if status < 0 {
		err = fmt.Errorf("failed to set the fuse lock flag to the setnx atom in the redis cluster server this may be due to a redis link failure")
		return nil, _ERROR_OPERATING_TOO_FAST, err
	} else if status > 0 {
		err = fmt.Errorf("attempts to obtain a lock in the redis cluster failed because there was already a server competing for the atomic lock instance")
		return nil, _ERROR_OPERATING_TOO_FAST, err
	}

	user, err = my.server_find_user_by_guid(guid)
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return user, _ERROR_DB, err
		} else {
			return user, _ERROR_USER_NOT_EXISTS, err
		}
	}

	err = my.server_sync_user_to_redis(user, now, nil)
	if err != nil {
		return nil, _ERROR_REDIS, nil
	} else {
		return user, _ERROR_OK, nil
	}
}

func (my *ManagedServer) server_load_user_by_guid(guid string) (int, *_vpn_user, int, error) {
	// Query the basic information of the VPN user through the user's primary key GUID.
	now := uint32(time.Now().Unix())
	user, code, err := my.server_query_user_by_guid(guid, now)
	if err != nil {
		LOG_ERROR.Println(err)
		return -1, nil, code, err
	}

	// Add the VPN user information to the server cache user information list.
	my.Lock()
	defer my.Unlock()

	archive_time := now
	old_user := my.users[guid]
	if old_user != nil {
		archive_time = old_user.ArchiveTime
	}

	vpn_user := &_vpn_user{
		Guid:            guid,
		ArchiveTime:     archive_time,
		IncomingTraffic: user.IncomingTraffic,
		OutgoingTraffic: user.OutgoingTraffic,
		ExpiredTime:     user.ExpiredTime,
		BandwidthQoS:    user.BandwidthQoS,
	}
	my.users[guid] = vpn_user
	return 0, vpn_user, _ERROR_OK, nil
}

func (my *ManagedServer) server_on_authentication(ws *io.WebSocket, guid string, node int) (int, *_vpn_user) {
	// Verify that the user's primary key GUID is formatted correctly!
	if !StringAuxiliary.IsGuid(guid) {
		return -1, nil
	}

	// Check whether the server that the VPN user wants to login to exists.
	server, _, err := my.server_find_server_by_server(node)
	if err != nil {
		LOG_ERROR.Println(err)
		return -1, nil
	} else {
		// Query basic VPN user information from the server's local memory cache.
		my.Lock()
		user, ok := my.users[guid]
		my.Unlock()

		// If the local VPN user information exists in the cache based on the GUID primary key.
		if ok {
			// The login user successfully logged onto the server, and the data that needs to be returned to the VPN node server is filled.
			return 0, &_vpn_user{
				Guid:            user.Guid,
				IncomingTraffic: user.IncomingTraffic,
				OutgoingTraffic: user.OutgoingTraffic,
				ExpiredTime:     user.ExpiredTime,
				BandwidthQoS:    my.server_calc_qos_by_server_and_user(server, user),
			}
		}
	}

	// Through the primary key GUID to query and load VPN user basic data.
	status, user, _, _ := my.server_load_user_by_guid(guid)
	if status != 0 {
		return status, nil
	}

	// The login user successfully logged onto the server, and the data that needs to be returned to the VPN node server is filled.
	return 0, &_vpn_user{
		Guid:            user.Guid,
		IncomingTraffic: user.IncomingTraffic,
		OutgoingTraffic: user.OutgoingTraffic,
		ExpiredTime:     user.ExpiredTime,
		BandwidthQoS:    my.server_calc_qos_by_server_and_user(server, user),
	}
}

func (my *ManagedServer) server_sync_all_users_to_databases(forced_save_to_databases bool) error {
	dbs := make([]*tb_user, 0)
	users := make(map[string]*_vpn_user)
	keys := make([]any, 0)
	now := uint32(time.Now().Unix())

	// The interval between obtaining user archives.
	USER_ARCHIVE_TIMEOUT := uint32(_REDIS_USER_ARCHIVE_TIMEOUT)
	if my.configuration.ConcurrencyControl.UserArchiveTimeout > 0 {
		USER_ARCHIVE_TIMEOUT = uint32(my.configuration.ConcurrencyControl.UserArchiveTimeout)
	}

	// Gets the current user data that needs to be synchronized to redis.
	my.Lock()
	for guid := range my.dirty {
		user, ok := my.users[guid]
		if ok {
			if forced_save_to_databases || now >= user.ArchiveTime+USER_ARCHIVE_TIMEOUT {
				users[guid] = user
			}
		} else {
			keys = append(keys, guid)
		}
	}
	my.Unlock()

	// Process set command parameters that need to batch synchronize user base data to redis.
	pipeline, err := my.redis.Pipeline()
	if err != nil {
		return err
	}

	// Collate userbase data that needs to be synchronized to the database via gorm and redis.
	bany := false
	for _, user := range users {
		json := JsonAuxiliary.Serialize(user)
		if json == "" {
			continue
		}

		// Add a mutex lock for the access and operation of vpn user basic information
		// In the local cache to prevent data problems caused by concurrency.
		user.Lock()
		defer user.Unlock()

		bany = true
		sync_user := &tb_user{
			Guid:            user.Guid,
			IncomingTraffic: user.IncomingTraffic,
			OutgoingTraffic: user.OutgoingTraffic,
			ExpiredTime:     user.ExpiredTime,
			BandwidthQoS:    user.BandwidthQoS,
		}

		err := my.server_sync_user_to_redis(sync_user, now, pipeline)
		if err != nil {
			return err
		} else {
			dbs = append(dbs, sync_user)
		}
	}

	// If the pipeline has any commands that need to be executed,
	// The Exec command needs to be invoked to send the pipeline's
	// Redis command combination to the redis server for processing.
	if bany {
		_, err = pipeline.Exec(context.Background())
		if err != nil {
			return err
		}
	}

	// Synchronize the changed all user datas to the mysql databases.
	if len(dbs) > 0 {
		var wg sync.WaitGroup
		var lk sync.Mutex

		// Define the variables needed to store the mysql databases.
		ER := 0
		DB := my.FetchDB(false).LoadDB()
		EXEC := func(guid string, user *tb_user) bool {
			err := DB.Model(user).
				Where("guid = ?", guid).
				Updates(map[string]any{
					"incoming_traffic": user.IncomingTraffic,
					"outgoing_traffic": user.OutgoingTraffic,
				}).Error

			lk.Lock()
			defer lk.Unlock()
			defer wg.Done()

			ok := err == nil
			if !ok {
				ER++
				delete(users, guid)
			} else {
				keys = append(keys, guid)
			}

			return ok
		}

		// Loop to create an infinite number of coroutines simultaneously requesting the mysql database to write changes.
		for _, user := range dbs {
			wg.Add(1)
			go func(user *tb_user) {
				// Execute to store basic user information data into the mysql databases.
				guid := user.Guid
				ok := EXEC(guid, user)

				// Print the log information about whether the basic user information is successfully stored.
				var log string
				if ok {
					log = fmt.Sprintf("store user ok: %s", guid)
				} else {
					log = fmt.Sprintf("store user er: %s", guid)
				}

				LOG_ERROR.Println(log)
			}(user)
		}

		// Wait for all concurrent mysql write tasks to completed.
		wg.Wait()

		// Concurrent write to mysql database all failed, serious and fatal server system error!
		if len(dbs) == ER {
			return errors.New("concurrent write to mysql database all failed, serious and fatal server system error")
		}
	}

	// If the above operation is successful,
	// The SREM operation is performed to delete the current marked Tag from redis.
	// If this operation is not successful, there is no need to roll back the redis user base data
	// That has been synchronized, and so on to re-synchronize user base data next time.
	if len(keys) > 0 {
		err := my.redis.SRem(_REDIS_USER_SYNC_KEY, keys...)
		if err != nil {
			return err
		}
	}

	// Synchronization ok releases the dirty flag of the local cache control user data stores.
	my.Lock()
	for _, v := range keys {
		k, ok := v.(string)
		if ok {
			delete(my.dirty, k)
		}
	}

	// Change the local cache user's archive time to the current time. The time error is usually within one second.
	for _, v := range users {
		v.ArchiveTime = now
	}
	my.Unlock()

	// Synchronization to redis and mysql databases is completed!
	return nil
}

func (my *ManagedServer) server_load_all_users() error {
	// Obtain the dirty index of user basic data key values to be synchronized from the redis server.
	guids, err := my.redis.SMembers(_REDIS_USER_SYNC_KEY)
	if err != nil {
		return err
	} else if len(guids) < 1 {
		return nil
	}

	// Organize the list of dirty objects that need to delete the user's underlying data because the user may be deleted from the database.
	srem_keys := make([]any, 0)
	for _, guid := range guids {
		status, user, _, _ := my.server_load_user_by_guid(guid)
		if status > 0 {
			srem_keys = append(srem_keys, guid)
			continue
		} else if status < 0 {
			return errors.New("failed to find the user base database from mysql and redis. please check whether the databaes server has crashed or whether the link is faulty")
		} else if user != nil {
			my.dirty[guid] = true
		} else {
			srem_keys = append(srem_keys, guid)
		}
	}

	// If you need to delete some useless dirty mark data,
	// Then try to delete, failure to return an error, the function needs to be called at
	// The time of opening the service, not in the server running, in the execution of this code.
	if len(srem_keys) > 0 {
		err := my.redis.SRem(_REDIS_USER_SYNC_KEY, srem_keys...)
		if err != nil {
			return err
		}
	}
	return nil
}

func (my *ManagedServer) server_user_set_traffic_and_seconds(guid string, rx int64, tx int64, seconds uint32, qos uint32) (*_vpn_user, int, error) {
	// First, try to obtain basic VPN user information from the local memory.
	my.Lock()
	user, ok := my.users[guid]
	my.Unlock()

	// If you do not get it, get it from redis and mysql, and load the vpn user basic information into memory.
	if !ok {
		status, _, code, err := my.server_load_user_by_guid(guid)
		if status != 0 {
			return nil, code, err
		}

		// After the user is successfully loaded from redis and mysql,
		// The basic information object of the vpn user is obtained from the memory cache.
		my.Lock()
		user, ok = my.users[guid]
		my.Unlock()

		// If the basic information about the VPN user still cannot be obtained, an error is returned.
		if !ok {
			return nil, _ERROR_USER_NOT_EXISTS, nil
		}
	}

	// Lock basic vpn user information in the local (mutex).
	user.Lock()
	defer user.Unlock()

	// This section describes how to set the basic information of the current VPN user.
	now := uint32(time.Now().Unix())
	user.IncomingTraffic = rx
	user.OutgoingTraffic = tx
	user.ExpiredTime = seconds
	user.BandwidthQoS = qos
	user.ArchiveTime = now

	// The newly changed VPN user information is stored in the mysql database.
	DB := my.FetchDB(false).LoadDB()
	err := DB.Model(&tb_user{}).
		Where("guid = ?", guid).
		Updates(map[string]any{
			"expired_time":     user.ExpiredTime,
			"qos":              user.BandwidthQoS,
			"incoming_traffic": user.IncomingTraffic,
			"outgoing_traffic": user.OutgoingTraffic,
		}).Error
	if err != nil {
		return nil, _ERROR_DB, err
	}

	// Store the vpn user base data of this change in redis.
	token := &tb_user{
		Guid:            user.Guid,
		IncomingTraffic: user.IncomingTraffic,
		OutgoingTraffic: user.OutgoingTraffic,
		ExpiredTime:     user.ExpiredTime,
		BandwidthQoS:    user.BandwidthQoS,
	}
	err = my.server_sync_user_to_redis(token, now, nil)
	if err != nil {
		return nil, _ERROR_REDIS, err
	}

	return user, _ERROR_OK, nil
}

func (my *ManagedServer) server_user_new_to_databases(guid string, rx int64, tx int64, seconds uint32, qos uint32) int {
	// First, try to obtain basic VPN user information from the local memory.
	my.Lock()
	_, ok := my.users[guid]
	my.Unlock()
	if ok {
		return _ERROR_USER_ALREAY_EXISTS
	}

	// Check the presence of user base information in the redis distributed cache.
	key := _REDIS_USER_DATA_KEY + ":" + guid
	status := my.redis.Exists(key)
	if status < 0 {
		return _ERROR_REDIS
	} else if status == 0 {
		return _ERROR_USER_ALREAY_EXISTS
	}

	// Create the user base information data ORM entry and insert it into the mysql databases.
	user := &tb_user{
		Guid:            guid,
		IncomingTraffic: rx,
		OutgoingTraffic: tx,
		ExpiredTime:     seconds,
		BandwidthQoS:    qos,
	}
	FD := my.FetchDB(false)
	DB := FD.LoadDB()
	err := DB.Model(&tb_user{}).Create(user).Error
	if err == nil {
		return _ERROR_OK
	}

	if FD.IsErrDuplicatedKey(err) {
		return _ERROR_USER_ALREAY_EXISTS
	}

	return _ERROR_DB
}
