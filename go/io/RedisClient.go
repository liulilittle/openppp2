package io

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

type RedisClient struct {
	MasterName    string
	SentinelAddrs []string
	Password      string
	DB            int
	Client        *redis.Client
}

func (my *RedisClient) Ping() error {
	client := my.Client
	if client == nil {
		return fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	return client.Ping(ctx).Err()
}

func (my *RedisClient) Close() {
	client := my.Client
	if client != nil {
		client.Close()
	}
}

func (my *RedisClient) NewFailoverClient() *redis.Client {
	sf := &redis.FailoverOptions{
		MasterName:    my.MasterName,
		SentinelAddrs: my.SentinelAddrs,
		Password:      my.Password,
		DB:            my.DB,
	}

	return redis.NewFailoverClient(sf)
}

func (my *RedisClient) Lock(key string, max_seconds int, critical_section func()) int {
	if critical_section == nil {
		return -1
	}

	if max_seconds < 1 {
		max_seconds = 10
	}

	client := my.Client
	if client == nil {
		return -1
	}

	timeout := time.Now().Add(time.Second * time.Duration(max_seconds))
	ctx := context.Background()
	for {
		value, err := client.SetNX(ctx, key, "1", time.Second*time.Duration(max_seconds)).Result()
		if err != nil {
			return -1
		}

		if value {
			critical_section()
			client.Del(ctx, key)
			return 0
		}

		now := time.Now()
		if now.After(timeout) || now.Equal(timeout) {
			return 1
		}

		time.Sleep(time.Microsecond * 100)
	}
}

func (my *RedisClient) HGet(key string, field string) (string, error) {
	client := my.Client
	if client == nil {
		return "", fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	value, err := client.HGet(ctx, key, field).Result()
	return value, err
}

func (my *RedisClient) HMGet(key string, fields ...string) ([]any, error) {
	client := my.Client
	if client == nil {
		return nil, fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	values, err := client.HMGet(ctx, key, fields...).Result()
	return values, err
}

func (my *RedisClient) SAdd(key string, members ...any) error {
	client := my.Client
	if client == nil {
		return fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	return client.SAdd(ctx, key, members...).Err()
}

func (my *RedisClient) SRem(key string, members ...any) error {
	client := my.Client
	if client == nil {
		return fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	return client.SRem(ctx, key, members...).Err()
}

func (my *RedisClient) SMembers(key string) ([]string, error) {
	client := my.Client
	if client == nil {
		return nil, fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	return client.SMembers(ctx, key).Result()
}

func (my *RedisClient) Pipeline() (redis.Pipeliner, error) {
	client := my.Client
	if client == nil {
		return nil, fmt.Errorf("redis client connect is nil")
	}

	pipe := client.Pipeline()
	return pipe, nil
}

func (my *RedisClient) HSet(key string, field string, value any) error {
	client := my.Client
	if client == nil {
		return fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	return client.HMSet(ctx, key, field, value).Err()
}

func (my *RedisClient) Get(key string) (string, error) {
	client := my.Client
	if client == nil {
		return "", fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	value, err := client.Get(ctx, key).Result()
	return value, err
}

func (my *RedisClient) Increment(key string, incr int64) (int64, error) {
	client := my.Client
	if client == nil {
		return 0, fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	value, err := client.IncrBy(ctx, key, incr).Result()
	return value, err
}

func (my *RedisClient) Decrement(key string, decr int64) (int64, error) {
	client := my.Client
	if client == nil {
		return 0, fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	value, err := client.DecrBy(ctx, key, decr).Result()
	return value, err
}

func (my *RedisClient) HIncrement(key string, field string, incr int64) (int64, error) {
	client := my.Client
	if client == nil {
		return 0, fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	value, err := client.HIncrBy(ctx, key, field, incr).Result()
	return value, err
}

func (my *RedisClient) HDecrement(key string, field string, decr int64) (int64, error) {
	return my.HIncrement(key, field, -decr)
}

func (my *RedisClient) Del(key ...string) error {
	client := my.Client
	if client == nil {
		return fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	return client.Del(ctx, key...).Err()
}

func (my *RedisClient) Exists(key string) int {
	client := my.Client
	if client == nil {
		return -1
	}

	ctx := context.Background()
	value, err := client.Exists(ctx, key).Result()
	if err != nil {
		return -1
	}

	if value > 0 {
		return 0
	} else {
		return 1
	}
}

func (my *RedisClient) HExists(key string, field string) int {
	client := my.Client
	if client == nil {
		return -1
	}

	ctx := context.Background()
	value, err := client.HExists(ctx, key, field).Result()
	if err != nil {
		return -1
	}

	if value {
		return 0
	} else {
		return 1
	}
}

func (my *RedisClient) SetNX(key string, v any, expiration time.Duration) int {
	client := my.Client
	if client == nil {
		return -1
	}

	ctx := context.Background()
	value, err := client.SetNX(ctx, key, v, expiration).Result()
	if err != nil {
		return -1
	}

	if value {
		return 0
	} else {
		return 1
	}
}

func (my *RedisClient) HSetNX(key string, field string, v any) int {
	client := my.Client
	if client == nil {
		return -1
	}

	ctx := context.Background()
	value, err := client.HSetNX(ctx, key, field, v).Result()
	if err != nil {
		return -1
	}

	if value {
		return 0
	} else {
		return 1
	}
}

func (my *RedisClient) HDel(key string, field ...string) error {
	client := my.Client
	if client == nil {
		return fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	return client.HDel(ctx, key, field...).Err()
}

func (my *RedisClient) Set(key string, v any, expiration time.Duration) error {
	client := my.Client
	if client == nil {
		return fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	return client.Set(ctx, key, v, expiration).Err()
}

func (my *RedisClient) MSet(values ...any) error {
	client := my.Client
	if client == nil {
		return fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	return client.MSet(ctx, values...).Err()
}

func (my *RedisClient) HMSet(key string, values ...any) error {
	client := my.Client
	if client == nil {
		return fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	return client.HMSet(ctx, key, values...).Err()
}

func (my *RedisClient) Expire(key string, expiration time.Duration) error {
	client := my.Client
	if client == nil {
		return fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	return client.Expire(ctx, key, expiration).Err()
}

func (my *RedisClient) HGetAll(key string) (map[string]string, error) {
	client := my.Client
	if client == nil {
		return nil, fmt.Errorf("redis client connect is nil")
	}

	ctx := context.Background()
	value, err := client.HGetAll(ctx, key).Result()
	return value, err
}

func NewRedisClient(master_name, password string, addresses []string, db int) *RedisClient {
	sentinel := RedisClient{
		MasterName:    master_name,
		SentinelAddrs: addresses,
		Password:      password,
		DB:            db,
	}

	sentinel.Client = sentinel.NewFailoverClient()
	return &sentinel
}
