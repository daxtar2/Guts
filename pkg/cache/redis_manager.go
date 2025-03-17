//服务相关配置管理器

package cache

import (
	"encoding/json"
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/net/context"

	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/models"
)

const (
	ConfigKey = "guts:config" // Redis中存储配置的key
)

type RedisManager struct {
	Client *RedisClient
	ctx    context.Context
}

// NewRedisManager 创建新的 RedisManager
func NewRedisManager(addr string) *RedisManager {
	client := NewRedisClient(addr)
	return &RedisManager{
		Client: client,
		ctx:    context.Background(),
	}
}

// LoadConfigWrapper 从 Redis 加载配置
func (rm *RedisManager) LoadConfigWrapper() (*ConfigWrapper, error) {
	logger.Info("开始创建ConfigWrapper")

	wrapper := NewConfigWrapper(rm)

	// 尝试加载初始配置
	config, err := wrapper.LoadConfig()
	if err != nil {
		logger.Warn("首次加载配置失败，将使用默认配置", zap.Error(err))
		// 使用默认配置
		defaultConfig := &models.Config{}
		config, err = defaultConfig.LoadConfig()
		if err != nil {
			return nil, fmt.Errorf("加载默认配置失败: %v", err)
		}
	}

	wrapper.Config = config
	logger.Info("ConfigWrapper创建完成", zap.Any("config", config))

	return wrapper, nil
}

// SaveConfig 保存配置到 Redis
func (rm *RedisManager) SaveConfig(config *models.Config) error {
	data, err := json.Marshal(config)
	if err != nil {
		logger.Error("保存配置失败", zap.Error(err))
		return err
	}
	return rm.Client.Set(ConfigKey, data)
}

// WatchConfig 监听配置变更
func (rm *RedisManager) WatchConfig(callback func(ConfigInterface)) {
	pubsub := rm.Client.Subscribe("config:update")
	defer pubsub.Close()

	for msg := range pubsub.Channel() {
		var config models.Config
		if err := json.Unmarshal([]byte(msg.Payload), &config); err != nil {
			logger.Error("解析配置消息失败", zap.Error(err))
			continue
		}

		callback(&config)
	}
}

// PublishUpdate 发布配置更新
func (rm *RedisManager) PublishUpdate(config ConfigInterface) error {
	data, err := json.Marshal(config)
	if err != nil {
		logger.Error("发布配置更新失败", zap.Error(err))
		return err
	}
	return rm.Client.Publish("config:update", data)
}

// GetScanResult 从 Redis 获取扫描结果
func (rm *RedisManager) GetScanResult(id string) (*models.ScanResult, error) {
	result, err := rm.Client.GetScanResult(id)
	if err != nil {
		logger.Error("获取扫描结果失败", zap.Error(err))
		return nil, err
	}
	return result, nil
}

// ClearAllScanResults 清除所有扫描结果
func (m *RedisManager) ClearAllScanResults() error {
	if m.Client == nil {
		return fmt.Errorf("Redis 客户端未初始化")
	}

	return m.Client.ClearAllScanResults()
}
