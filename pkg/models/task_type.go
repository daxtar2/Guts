package models

import (
	"fmt"
)

type Config struct {
	Mitmproxy      MitmproxyConfig      `mapstructure:"mitmproxy"`
	Redis          RedisConfig          `mapstructure:"redis"`
	HeaderMap      HeaderMap            `mapstructure:"headermap"`
	CaConfig       CaConfig             `mapstructure:"caconfig"`
	TemplateFilter TemplateFilterConfig `mapstructure:"templatefilters"`
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

type TemplateFilterConfig struct {
	Severity             string   `mapstructure:"severity"`             // filter by severities (accepts CSV values of info, low, medium, high, critical)
	ExcludeSeverities    string   `mapstructure:"excludeseverities"`    // filter by excluding severities (accepts CSV values of info, low, medium, high, critical)
	ProtocolTypes        string   `mapstructure:"protocoltypes"`        // filter by protocol types
	ExcludeProtocolTypes string   `mapstructure:"excludeprotocoltypes"` // filter by excluding protocol types
	Authors              []string `mapstructure:"authors"`              // fiter by author
	Tags                 []string `mapstructure:"tags"`                 // filter by tags present in template
	ExcludeTags          []string `mapstructure:"excludetags"`          // filter by excluding tags present in template
	IncludeTags          []string `mapstructure:"includetags"`          // filter by including tags present in template
	IDs                  []string `mapstructure:"ids"`                  // filter by template IDs
	ExcludeIDs           []string `mapstructure:"excludeids"`           // filter by excluding template IDs
	TemplateCondition    []string `mapstructure:"templatecondition"`    // DSL condition/ expression
	EnableCheck          bool     `mapstructure:"update_enable_check"`  // 是否启用更新检查
}

// LoadConfig 从配置对象本身加载配置
func (c *Config) LoadConfig() (*Config, error) {
	if c == nil { // s
		// 返回默认配置
		return &Config{
			Mitmproxy: MitmproxyConfig{
				AddrPort:      ":7777",
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

// GetTemplateFilters 返回模板过滤器配置
func (c *Config) GetTemplateFilters() TemplateFilterConfig {
	return c.TemplateFilter
}
