package config

type Config struct {
	Mitmproxy Mitmproxy `yaml:"mitmproxy"`
	HeaderMap HeaderMap `yaml:"headermap"`
	CaConfig  CaConfig  `yaml:"caconfig"`
}

type Mitmproxy struct {
	AddrPort      string   `yaml:"addr_port"`
	SslInsecure   bool     `yaml:"ssl_insecure"`
	IncludeDomain []string `yaml:"include_domain"`
	ExcludeDomain []string `yaml:"exclude_domain"`
	FilterSuffix  []string `yaml:"filter_suffix"`
}

type HeaderMap struct {
	Headers   map[string]string `yaml:"headers"`
	SetCookie []string          `yaml:"set_cookie"`
}

type CaConfig struct {
	CaRootPath string `yaml:"ca_root_path"`
}
