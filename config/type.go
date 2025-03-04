package config

import (
	"context"

	"github.com/redis/go-redis/v9"
)

type Config struct {
	Mitmproxy Mitmproxy `mapstructure:"mitmproxy"`
	HeaderMap HeaderMap `mapstructure:"headermap"`
	CaConfig  CaConfig  `mapstructure:"caconfig"`
	Redis     Redis     `mapstructure:"redis"`
}

type Mitmproxy struct {
	AddrPort      string   `mapstructure:"addr_port"`
	SslInsecure   bool     `mapstructure:"ssl_insecure"`
	IncludeDomain []string `mapstructure:"include_domain"`
	ExcludeDomain []string `mapstructure:"exclude_domain"`
	FilterSuffix  []string `mapstructure:"filter_suffix"`
}

type HeaderMap struct {
	Headers   map[string]string `mapstructure:"headers"`
	SetCookie []string          `mapstructure:"set_cookie"`
}

type CaConfig struct {
	CaRootPath string `mapstructure:"ca_root_path"`
}

type Redis struct {
	Address string `mapstructure:"address"`
}

type RedisManager struct {
	client *redis.Client
	ctx    context.Context
}

// type DefaultConfig struct {
// 	Templates:       goflags.StringSlice
// 	Workflows:                goflags.StringSlice
// 	RemoteTemplateDomainList: goflags.StringSlice
// 	TemplateURLs:             goflags.StringSlice
// 	WorkflowURLs:             goflags.StringSlice
// 	ExcludeTemplates:         goflags.StringSlice
// 	Tags:                     goflags.StringSlice
// 	ExcludeTags:              goflags.StringSlice
// 	IncludeTemplates:         goflags.StringSlice
// 	Authors:                  goflags.StringSlice
// 	Severities:               severity.Severities
// 	ExcludeSeverities:        severity.Severities
// 	IncludeTags:              goflags.StringSlice
// 	IncludeIds:               goflags.StringSlice
// 	ExcludeIds:               goflags.StringSlice
// 	Protocols:                types.ProtocolTypes
// 	ExcludeProtocols:         types.ProtocolTypes
// 	IncludeConditions:        goflags.StringSlice
// 	ExecutorOptions:          protocols.ExecutorOptions
// }
