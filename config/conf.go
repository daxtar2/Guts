package config

//import ("github.com/daxtar2/Guts/pkg/config")
import (
	"fmt"

	"github.com/spf13/viper"
)

var GConfig = &Config{}
var RedisAddr string

func loadConfig() {

	viper.SetConfigFile("./config/config.yaml")

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("无法获取配置文件，配置文件路径: %s\n", viper.ConfigFileUsed()) // 打印尝试加载的路径
		print(err)
	}
	fmt.Println("listening on:", viper.GetString("mitmproxy.addr_port"))
	fmt.Println("redis addr:", viper.GetString("redis.address"))
	fmt.Println("capath:", viper.GetString("caconfig.ca_root_path"))
	// 从配置文件获取配置信息
	RedisAddr = viper.GetString("redis.address")

	if err := viper.Unmarshal(&GConfig); err != nil {
		print(err)
	}
	fmt.Println(GConfig)
}

//func init() {
//	loadConfig()
//}

func InitConfig() {
	loadConfig()
}
