package cache

import (
	"encoding/json"

	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/models"
	"go.uber.org/zap"
)

type ConfigWrapper struct {
	config  *models.Config
	manager *RedisManager
}

// NewConfigWrapper 创建新的ConfigWrapper
func NewConfigWrapper(manager *RedisManager) *ConfigWrapper {
	return &ConfigWrapper{manager: manager}
}

// LoadConfig 从Redis加载配置
func (cw *ConfigWrapper) LoadConfig() (*models.Config, error) {
	// 1. 尝试从Redis加载
	data, err := cw.manager.client.Get(ConfigKey)
	if err != nil {
		logger.Debug("从Redis加载配置失败，将使用内存配置", zap.Error(err))
		return cw.config.LoadConfig()
	}

	// 2. 解析Redis中的配置
	if err := json.Unmarshal(data, &cw.config); err != nil {
		logger.Error("解析Redis配置失败", zap.Error(err))
		return cw.config.LoadConfig()
	}

	return cw.config, nil
}

// SaveConfig 保存配置到Redis
func (cw *ConfigWrapper) SaveConfig(config *models.Config) error {
	// 1. 更新内存配置
	if err := cw.config.SaveConfig(config); err != nil {
		return err
	}

	// 2. 序列化配置
	data, err := json.Marshal(cw.config)
	if err != nil {
		logger.Error("序列化配置失败", zap.Error(err))
		return err
	}

	// 3. 保存到Redis
	return cw.manager.client.Set(ConfigKey, data)
}

// WatchConfig 监听配置变更
func (cw *ConfigWrapper) WatchConfig(callback func(*models.Config)) {
	logger.Info("开始设置配置变更监听")

	go func() {
		cw.manager.WatchConfig(func(configInterface ConfigInterface) {
			logger.Debug("收到配置变更通知")

			if config, ok := configInterface.(*models.Config); ok {
				logger.Info("配置类型转换成功，执行回调")
				callback(config)
			} else {
				logger.Error("配置类型转换失败")
			}
		})
	}()

	logger.Info("配置变更监听器启动完成")
}
