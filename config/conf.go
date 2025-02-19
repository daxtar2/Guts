package config

//import ("github.com/daxtar2/Guts/pkg/config")
import (
	"fmt"
	"github.com/spf13/viper"
)

var GConfig = &Config{}
var RedisAddr string

func init() {
	viper.SetConfigName("config") // 配置文件名
	viper.SetConfigType("yaml")   // 配置文件类型
	viper.AddConfigPath(".")      // 配置文件路径，当前目录

	if err := viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("无法加载配置文件: %w", err))
	}

	// 从配置文件获取 Redis 地址
	RedisAddr = viper.GetString("redis.address")
	if RedisAddr == "" {
		panic("Redis 地址未定义")
	}
}
