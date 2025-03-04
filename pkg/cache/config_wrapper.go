package cache

import (
	"encoding/json"

	"github.com/daxtar2/Guts/pkg/models"
)

type ConfigWrapper struct {
	config    *models.Config
	manager   *RedisManager    // 引用 RedisManager
	Mitmproxy models.Mitmproxy `mapstructure:"mitmproxy"` // 确保这里有 Mitmproxy 字段
}

// NewConfigWrapper 创建新的 ConfigWrapper
func NewConfigWrapper(manager *RedisManager) *ConfigWrapper {
	return &ConfigWrapper{manager: manager}
}

// LoadConfig 从 Redis 加载配置
func (cw *ConfigWrapper) LoadConfig() (*models.Config, error) {
	data, err := cw.manager.client.Get(ConfigKey)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, &cw.config); err != nil {
		return nil, err
	}
	return cw.config, nil
}

// SaveConfig 保存配置到 Redis
func (cw *ConfigWrapper) SaveConfig(config *models.Config) error {
	cw.config = config // 更新内部配置
	data, err := json.Marshal(cw.config)
	if err != nil {
		return err
	}
	return cw.manager.client.Set(ConfigKey, data)
}

// WatchConfig 监听配置变更
func (cw *ConfigWrapper) WatchConfig(callback func(*models.Config)) {
	cw.manager.WatchConfig(func(configInterface ConfigInterface) {
		if config, ok := configInterface.(*models.Config); ok {
			callback(config)
		}
	})
}
