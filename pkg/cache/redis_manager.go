//服务相关配置管理器

package cache

import (
	"encoding/json"

	"golang.org/x/net/context"

	"github.com/daxtar2/Guts/pkg/models"
)

const (
	ConfigKey = "guts:config" // Redis中存储配置的key
)

type RedisManager struct {
	client *RedisClient
	ctx    context.Context
}

// NewRedisManager 创建新的 RedisManager
func NewRedisManager(addr string) *RedisManager {
	client := NewRedisClient(addr)
	return &RedisManager{
		client: client,
		ctx:    context.Background(),
	}
}

// LoadConfigWrapper 从 Redis 加载配置
func (rm *RedisManager) LoadConfigWrapper() (*ConfigWrapper, error) {
	return NewConfigWrapper(rm), nil
}

// SaveConfig 保存配置到 Redis
func (rm *RedisManager) SaveConfig(config *models.Config) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return rm.client.Set(ConfigKey, data)
}

// WatchConfig 监听配置变更
func (rm *RedisManager) WatchConfig(callback func(ConfigInterface)) {
	pubsub := rm.client.Subscribe("config:update")
	defer pubsub.Close()

	for {
		msg, err := pubsub.ReceiveMessage(rm.ctx)
		if err != nil {
			continue
		}

		var config models.Config
		if err := json.Unmarshal([]byte(msg.Payload), &config); err != nil {
			continue
		}

		callback(NewConfigWrapper(rm))
	}
}

// PublishUpdate 发布配置更新
func (rm *RedisManager) PublishUpdate(config ConfigInterface) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return rm.client.Publish("config:update", data)
}

// GetScanResult 从 Redis 获取扫描结果
func (rm *RedisManager) GetScanResult(id string) (*models.ScanResult, error) {
	return rm.client.GetScanResult(id)
}
