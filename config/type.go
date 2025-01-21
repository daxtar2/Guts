package config

type Config struct {
	Mitmproxy Mitmproxy `json:"mitmproxy"`
	HeaderMap HeaderMap `json:"headermap"`
}

type Mitmproxy struct {
	AddrPort      string   `json:"addr_prot"`
	SslInsecure   bool     `json:"ssl_insecure"`
	IncludeDomain []string `json:"include_domain"`
	ExcludeDomain []string `json:"exclude_domain"`
	FilterSufffix []string `json:"filter_sufffix"`
}

type HeaderMap struct {
	Headers   map[string]string `json:"headers"`
	SetCookie []string          `json:"set_cookie"`
}

type CaConfig struct {
	CaRootPath string `json:"ca_root_path"`
}
