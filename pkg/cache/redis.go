//redis客户端交互

package cache

import (
	"context"
	"encoding/json"

	"github.com/daxtar2/Guts/pkg/models"
	"github.com/redis/go-redis/v9"
)

// Redis 客户端
type RedisClient struct {
	client *redis.Client
	ctx    context.Context
}

// NewRedisClient 创建新的 Redis 客户端
func NewRedisClient(addr string) *RedisClient {
	client := redis.NewClient(&redis.Options{
		Addr: addr,
		DB:   0,
	})

	return &RedisClient{
		client: client,
		ctx:    context.Background(),
	}
}

// Connect 连接到 Redis
func (rc *RedisClient) Connect() error {
	// 测试连接
	_, err := rc.Get("test")
	if err == redis.Nil {
		// 键不存在，但连接正常
		return nil
	}
	return err
}

// Get 从 Redis 获取数据
func (rc *RedisClient) Get(key string) ([]byte, error) {
	return rc.client.Get(rc.ctx, key).Bytes()
}

// Set 将数据存储到 Redis
func (rc *RedisClient) Set(key string, value []byte) error {
	return rc.client.Set(rc.ctx, key, value, 0).Err()
}

// Publish 发布消息到 Redis
func (rc *RedisClient) Publish(channel string, message []byte) error {
	return rc.client.Publish(rc.ctx, channel, message).Err()
}

// Subscribe 订阅 Redis 频道
func (rc *RedisClient) Subscribe(channel string) *redis.PubSub {
	return rc.client.Subscribe(rc.ctx, channel)
}

// GetScanResult 从 Redis 获取扫描结果
func (rc *RedisClient) GetScanResult(id string) (*models.ScanResult, error) {
	data, err := rc.client.Get(rc.ctx, "scan_result:"+id).Bytes()
	if err != nil {
		return nil, err
	}

	var result models.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
