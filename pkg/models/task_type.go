package models

import (
	"fmt"
)

// Config 配置结构体
type Config struct {
	Mitmproxy      MitmproxyConfig      `mapstructure:"mitmproxy" json:"mitmproxy"`            // mitmproxy配置
	Redis          RedisConfig          `mapstructure:"redis" json:"redis"`                    // Redis配置
	HeaderMap      HeaderMap            `mapstructure:"headermap" json:"headerMap"`            // 请求头配置
	CaConfig       CaConfig             `mapstructure:"caconfig" json:"caConfig"`              // 证书配置
	TemplateFilter TemplateFilterConfig `mapstructure:"templatefilters" json:"templateFilter"` // 模板过滤配置
	ScanRate       ScanRateConfig       `mapstructure:"scanrate" json:"scanRate"`              // 扫描速率配置
	PathFuzz       PathFuzzConfig       `mapstructure:"path_fuzz" json:"pathFuzz"`             // 路径字典配置
}

type MitmproxyConfig struct {
	AddrPort      string   `mapstructure:"addrport"`
	SslInsecure   bool     `mapstructure:"sslinsecure"`
	IncludeDomain []string `mapstructure:"includedomain"`
	ExcludeDomain []string `mapstructure:"excludedomain"`
	FilterSuffix  []string `mapstructure:"filtersuffix"`
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

// ScanRateConfig 扫描速率配置
type ScanRateConfig struct {
	// 全局速率限制
	GlobalRate     int    `mapstructure:"globalrate"`     // 每秒请求数
	GlobalRateUnit string `mapstructure:"globalrateunit"` // 速率单位，默认为秒

	// 并发配置
	TemplateConcurrency           int `mapstructure:"templateconcurrency"`           // 模板并发
	HostConcurrency               int `mapstructure:"hostconcurrency"`               // 主机并发
	HeadlessHostConcurrency       int `mapstructure:"headlesshostconcurrency"`       // 无头浏览器主机并发
	HeadlessTemplateConcurrency   int `mapstructure:"headlesstemplateconcurrency"`   // 无头浏览器模板并发
	JavascriptTemplateConcurrency int `mapstructure:"javascripttemplateconcurrency"` // JavaScript模板并发
	TemplatePayloadConcurrency    int `mapstructure:"templatepayloadconcurrency"`    // 模板载荷并发
	ProbeConcurrency              int `mapstructure:"probeconcurrency"`              // 探测并发
}

// PathFuzzConfig 路径字典配置
type PathFuzzConfig struct {
	Enabled bool     `mapstructure:"enabled" json:"enabled"` // 是否启用路径字典
	Paths   []string `mapstructure:"paths" json:"paths"`     // 路径列表
}

// LoadConfig 从配置对象本身加载配置
func (c *Config) LoadConfig() (*Config, error) {
	if c == nil {
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
			TemplateFilter: TemplateFilterConfig{
				Severity:          "critical,high,medium",
				ExcludeSeverities: "low,info",
				ProtocolTypes:     "http",
				Authors:           []string{},
				Tags:              []string{},
				ExcludeTags:       []string{},
				IncludeTags:       []string{},
				IDs:               []string{},
				ExcludeIDs:        []string{},
				TemplateCondition: []string{},
				EnableCheck:       false,
			},
			ScanRate: ScanRateConfig{
				GlobalRate:     30,
				GlobalRateUnit: "second",
			},
			PathFuzz: PathFuzzConfig{
				Enabled: false,
				Paths:   []string{},
			},
		}, nil
	}

	// 返回当前配置的副本
	return &Config{
		Mitmproxy:      c.Mitmproxy,
		Redis:          c.Redis,
		HeaderMap:      c.HeaderMap,
		CaConfig:       c.CaConfig,
		TemplateFilter: c.TemplateFilter,
		ScanRate:       c.ScanRate,
		PathFuzz:       c.PathFuzz,
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
	c.TemplateFilter = config.TemplateFilter
	c.ScanRate = config.ScanRate
	c.PathFuzz = config.PathFuzz

	return nil
}

// GetTemplateFilters 返回模板过滤器配置
func (c *Config) GetTemplateFilters() TemplateFilterConfig {
	return c.TemplateFilter
}
