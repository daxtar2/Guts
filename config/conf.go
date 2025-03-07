package config

import (
	"fmt"
	"sync"

	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/models"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	GConfig   *models.Config
	once      sync.Once
	RedisAddr string
)

// InitConfig 初始化配置
func InitConfig() error {
	var err error
	once.Do(func() {
		err = loadConfig()
	})
	return err
}

// loadConfig 从文件加载配置
func loadConfig() error {
	// 1. 设置默认配置
	//setDefaultConfig()

	// 2. 读取配置文件
	viper.SetConfigFile("./config/config.yaml")
	if err := viper.ReadInConfig(); err != nil {
		logger.Warn("无法读取配置文件，将使用默认配置",
			zap.String("path", viper.ConfigFileUsed()),
			zap.Error(err))
	}

	// 3. 解析配置到结构体
	GConfig = &models.Config{}
	if err := viper.Unmarshal(GConfig); err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 4. 保存Redis地址
	//RedisAddr = GConfig.Redis.Address

	return nil
}

// setDefaultConfig 设置默认配置
// func setDefaultConfig() {
// 	viper.SetDefault("mitmproxy.addr_port", ":9080")
// 	viper.SetDefault("mitmproxy.ssl_insecure", true)
// 	viper.SetDefault("mitmproxy.include_domain", []string{})
// 	viper.SetDefault("mitmproxy.exclude_domain", []string{
// 		"github.com", "github.io", "github.com.cn", "github.io.cn", "baidu.com",
// 	})
// 	viper.SetDefault("mitmproxy.filter_suffix", []string{
// 		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2",
// 	})
// 	viper.SetDefault("redis.address", "127.0.0.1:6379")
// 	viper.SetDefault("caconfig.ca_root_path", "./certs/")

// 	// 确保配置文件存在
// 	if err := viper.SafeWriteConfig(); err != nil {
// 		if _, ok := err.(viper.ConfigFileAlreadyExistsError); !ok {
// 			logger.Error("创建默认配置文件失败", zap.Error(err))
// 		}
// 	}
// }

// SaveConfigToFile 保存配置到文件
func SaveConfigToFile(config *models.Config) error {
	// 更新内存中的配置
	GConfig = config

	// 将配置写入viper
	viper.Set("mitmproxy", config.Mitmproxy)
	viper.Set("headermap", config.HeaderMap)
	viper.Set("caconfig", config.CaConfig)
	viper.Set("redis", config.Redis)

	// 写入文件
	if err := viper.WriteConfig(); err != nil {
		return fmt.Errorf("保存配置到文件失败: %v", err)
	}

	return nil
}

// GetConfig 获取当前配置的副本
func GetConfig() *models.Config {
	if GConfig == nil {
		return nil
	}
	return &models.Config{
		Mitmproxy: GConfig.Mitmproxy,
		Redis:     GConfig.Redis,
		HeaderMap: GConfig.HeaderMap,
		CaConfig:  GConfig.CaConfig,
	}
}

func SaveTemplateConfigToFile(templateFiltersConfig *models.TemplateFilterConfig) error {
	GConfig.TemplateFilter = *templateFiltersConfig
	// 将配置写入viper
	viper.Set("templatefilters", GConfig.TemplateFilter)

	// 写入文件
	if err := viper.WriteConfig(); err != nil {
		return fmt.Errorf("保存模板配置到文件失败: %v", err)
	}

	return nil
}
