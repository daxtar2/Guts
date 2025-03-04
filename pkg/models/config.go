package models

type Config struct {
	Mitmproxy MitmproxyConfig `mapstructure:"mitmproxy"`
	Redis     RedisConfig     `mapstructure:"redis"`
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

// Implementing ConfigInterface methods
func (c *Config) LoadConfig() (*Config, error) {
	// Logic to load config from Redis or other sources
	// This is just a placeholder; implement your loading logic here
	return c, nil
}

func (c *Config) SaveConfig(config *Config) error {
	// Logic to save config to Redis or other sources
	// This is just a placeholder; implement your saving logic here
	return nil
}
