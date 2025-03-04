package config

import (
	"fmt"

	"github.com/daxtar2/Guts/pkg/cache"
	"github.com/daxtar2/Guts/pkg/models"
	"github.com/spf13/viper"
)

var GConfig = &models.Config{}
var RedisAddr string

func loadConfig() {
	// 1. 首先加载默认配置
	viper.SetConfigFile("./config/config.yaml")
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("无法获取配置文件，配置文件路径: %s\n", viper.ConfigFileUsed())
		print(err)
	}

	// 2. 从配置文件获取基本配置
	RedisAddr = viper.GetString("redis.address")
	if err := viper.Unmarshal(&GConfig); err != nil {
		print(err)
	}

	// 3. 尝试从 Redis 加载配置
	if RedisAddr != "" {
		redisManager := cache.NewRedisManager(RedisAddr)
		configWrapper, err := redisManager.LoadConfigWrapper()
		if err != nil {
			print(err)
		}
		if config, err := configWrapper.LoadConfig(); err == nil {
			GConfig = config // 使用 Redis 中的配置覆盖默认配置
		}
	}
}

// SaveConfigToFile 保存配置到文件
func SaveConfigToFile(config *models.Config) error {
	// 将配置写回到 config.yaml
	viper.Set("mitmproxy", config.Mitmproxy)
	viper.Set("headermap", config.HeaderMap)
	viper.Set("caconfig", config.CaConfig)
	viper.Set("redis", config.Redis)

	return viper.WriteConfig()
}

//func init() {
//	loadConfig()
//}

func InitConfig() {
	loadConfig()
}
