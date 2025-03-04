package models

import (
	"fmt"
)

type Config struct {
	Mitmproxy MitmproxyConfig `mapstructure:"mitmproxy"`
	Redis     RedisConfig     `mapstructure:"redis"`
	HeaderMap HeaderMap       `mapstructure:"headermap"`
	CaConfig  CaConfig        `mapstructure:"caconfig"`
}

type MitmproxyConfig struct {
	AddrPort      string   `mapstructure:"addr_port"`
	SslInsecure   bool     `mapstructure:"ssl_insecure"`
	IncludeDomain []string `mapstructure:"include_domain"`
	ExcludeDomain []string `mapstructure:"exclude_domain"`
	FilterSuffix  []string `mapstructure:"filter_suffix"`
}

type RedisConfig struct {
	Address string `mapstructure:"address"`
}

type HeaderMap struct {
	Headers   map[string]string `mapstructure:"headers"`
	SetCookie []string          `mapstructure:"set_cookie"`
}

type CaConfig struct {
	CaRootPath string `mapstructure:"ca_root_path"`
}

// LoadConfig 从配置对象本身加载配置
func (c *Config) LoadConfig() (*Config, error) {
	if c == nil {
		// 返回默认配置
		return &Config{
			Mitmproxy: MitmproxyConfig{
				AddrPort:      ":9080",
				SslInsecure:   true,
				IncludeDomain: []string{},
				ExcludeDomain: []string{},
				FilterSuffix:  []string{},
			},
			Redis: RedisConfig{
				Address: "127.0.0.1:6379",
			},
			HeaderMap: HeaderMap{
				Headers:   make(map[string]string),
				SetCookie: make([]string, 0),
			},
			CaConfig: CaConfig{
				CaRootPath: "./certs/",
			},
		}, nil
	}

	// 返回当前配置的副本
	return &Config{
		Mitmproxy: c.Mitmproxy,
		Redis:     c.Redis,
		HeaderMap: c.HeaderMap,
		CaConfig:  c.CaConfig,
	}, nil
}

// SaveConfig 保存配置到当前对象
func (c *Config) SaveConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// 更新当前对象
	c.Mitmproxy = config.Mitmproxy
	c.Redis = config.Redis
	c.HeaderMap = config.HeaderMap
	c.CaConfig = config.CaConfig

	return nil
}
