package config

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
