package config

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/models"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	GConfig   *models.Config
	once      sync.Once
	RedisAddr string
)

// InitConfig 初始化配置
func InitConfig() error {
	// 1. 设置默认配置
	setDefaultConfig()
	var err error
	once.Do(func() {
		err = LoadConfig()
		if err == nil {
			go watchConfig()
		}
	})
	return err
}

// loadConfig 从文件加载配置
func LoadConfig() error {
	// 设置配置文件格式和路径
	viper.SetConfigType("yaml")
	viper.SetConfigFile("./config/config.yaml")

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		logger.Warn("无法读取配置文件，将使用默认配置",
			zap.String("path", viper.ConfigFileUsed()),
			zap.Error(err))
	}

	// 解析配置到结构体
	GConfig = &models.Config{}
	if err := viper.Unmarshal(GConfig); err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 确保关键字段被初始化
	if GConfig.Mitmproxy.FilterSuffix == nil {
		GConfig.Mitmproxy.FilterSuffix = []string{}
	}
	if GConfig.Mitmproxy.IncludeDomain == nil {
		GConfig.Mitmproxy.IncludeDomain = []string{}
	}
	if GConfig.Mitmproxy.ExcludeDomain == nil {
		GConfig.Mitmproxy.ExcludeDomain = []string{}
	}

	// 初始化扫描速率配置默认值
	initDefaultScanRateConfig()

	// 记录加载的配置
	logger.Info("配置加载成功",
		zap.Any("mitmproxy.FilterSuffix", GConfig.Mitmproxy.FilterSuffix),
		zap.Any("mitmproxy.IncludeDomain", GConfig.Mitmproxy.IncludeDomain),
		zap.Any("mitmproxy.ExcludeDomain", GConfig.Mitmproxy.ExcludeDomain),
		zap.String("mitmproxy.AddrPort", GConfig.Mitmproxy.AddrPort),
		zap.Bool("mitmproxy.SslInsecure", GConfig.Mitmproxy.SslInsecure),
	)

	return nil
}

// watchConfig 监控配置文件变化
func watchConfig() {
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		logger.Info("配置文件发生变化，重新加载",
			zap.String("file", e.Name),
			zap.String("operation", e.Op.String()),
		)

		// 重新加载配置
		if err := LoadConfig(); err != nil {
			logger.Error("重新加载配置失败", zap.Error(err))
		} else {
			// 记录重新加载后的配置
			logger.Info("配置重新加载成功",
				zap.Any("mitmproxy.FilterSuffix", GConfig.Mitmproxy.FilterSuffix),
				zap.Any("mitmproxy.IncludeDomain", GConfig.Mitmproxy.IncludeDomain),
				zap.Any("mitmproxy.ExcludeDomain", GConfig.Mitmproxy.ExcludeDomain),
				zap.String("mitmproxy.AddrPort", GConfig.Mitmproxy.AddrPort),
				zap.Bool("mitmproxy.SslInsecure", GConfig.Mitmproxy.SslInsecure),
				zap.Any("templateFilter", GConfig.TemplateFilter),
			)
		}
	})
}

// SaveConfigToFile 保存配置到文件
func SaveConfigToFile(config *models.Config) error {
	// 更新内存中的配置
	GConfig = config

	// 将配置写入viper
	viper.Set("mitmproxy", config.Mitmproxy)
	viper.Set("headermap", config.HeaderMap)
	viper.Set("caconfig", config.CaConfig)
	viper.Set("redis", config.Redis)
	viper.Set("templatefilters", config.TemplateFilter)

	// 写入文件
	if err := viper.WriteConfig(); err != nil {
		return fmt.Errorf("保存配置到文件失败: %v", err)
	}

	// 记录保存的配置
	logger.Info("配置已保存到文件",
		zap.Any("mitmproxy", config.Mitmproxy),
		zap.Any("headerMap", config.HeaderMap),
		zap.Any("caConfig", config.CaConfig),
		zap.Any("redis", config.Redis),
		zap.Any("templateFilter", config.TemplateFilter),
	)

	return nil
}

// GetConfig 获取当前配置的副本
func GetConfig() *models.Config {
	if GConfig == nil {
		return nil
	}
	return &models.Config{
		Mitmproxy: GConfig.Mitmproxy,
		Redis:     GConfig.Redis,
		HeaderMap: GConfig.HeaderMap,
		CaConfig:  GConfig.CaConfig,
	}
}

func SaveTemplateConfigToFile(templateFiltersConfig *models.TemplateFilterConfig) error {
	GConfig.TemplateFilter = *templateFiltersConfig
	// 将配置写入viper
	viper.Set("templatefilters", GConfig.TemplateFilter)

	// 写入文件
	if err := viper.WriteConfig(); err != nil {
		return fmt.Errorf("保存模板配置到文件失败: %v", err)
	}

	return nil
}

// TemplateUpdate 模板更新配置
type TemplateUpdate struct {
	EnableCheck bool `mapstructure:"update_enable_check"` // 是否启用更新检查
}

// GetTemplateBasePath 获取模板基础目录的绝对路径
func GetTemplateBasePath() string {
	// 默认使用相对于执行文件的templates目录
	templatesDir := "./templates"

	// 获取绝对路径，避免不同OS路径问题
	absPath, err := filepath.Abs(templatesDir)
	if err != nil {
		logger.Warn("获取模板绝对路径失败，使用相对路径", zap.Error(err))
		return templatesDir
	}

	return absPath
}

// setDefaultConfig 设置默认配置
func setDefaultConfig() {
	viper.SetDefault("mitmproxy.filtersuffix", []string{})
	viper.SetDefault("mitmproxy.includedomain", []string{})
	viper.SetDefault("mitmproxy.excludedomain", []string{})
	viper.SetDefault("mitmproxy.addr_port", "7777")
	viper.SetDefault("mitmproxy.ssl_insecure", false)
}

// initDefaultScanRateConfig 设置扫描速率配置的默认值
func initDefaultScanRateConfig() {
	// 如果扫描速率配置为空，设置默认值
	if GConfig.ScanRate.GlobalRate == 0 {
		GConfig.ScanRate.GlobalRate = 30
	}
	if GConfig.ScanRate.GlobalRateUnit == "" {
		GConfig.ScanRate.GlobalRateUnit = "second"
	}

	// 并发配置默认值
	if GConfig.ScanRate.TemplateConcurrency == 0 {
		GConfig.ScanRate.TemplateConcurrency = 100
	}
	if GConfig.ScanRate.HostConcurrency == 0 {
		GConfig.ScanRate.HostConcurrency = 100
	}
	if GConfig.ScanRate.HeadlessHostConcurrency == 0 {
		GConfig.ScanRate.HeadlessHostConcurrency = 50
	}
	if GConfig.ScanRate.HeadlessTemplateConcurrency == 0 {
		GConfig.ScanRate.HeadlessTemplateConcurrency = 50
	}
	if GConfig.ScanRate.JavascriptTemplateConcurrency == 0 {
		GConfig.ScanRate.JavascriptTemplateConcurrency = 50
	}
	if GConfig.ScanRate.TemplatePayloadConcurrency == 0 {
		GConfig.ScanRate.TemplatePayloadConcurrency = 25
	}
	if GConfig.ScanRate.ProbeConcurrency == 0 {
		GConfig.ScanRate.ProbeConcurrency = 50
	}
}

// SaveScanRateConfigToFile 保存扫描速率配置到文件
func SaveScanRateConfigToFile(scanRate *models.ScanRateConfig) error {
	// 更新内存中的配置
	GConfig.ScanRate = *scanRate

	// 将配置写入viper
	viper.Set("scanrate.globalrate", scanRate.GlobalRate)
	viper.Set("scanrate.globalrateunit", scanRate.GlobalRateUnit)
	viper.Set("scanrate.templateconcurrency", scanRate.TemplateConcurrency)
	viper.Set("scanrate.hostconcurrency", scanRate.HostConcurrency)
	viper.Set("scanrate.headlesshostconcurrency", scanRate.HeadlessHostConcurrency)
	viper.Set("scanrate.headlesstemplateconcurrency", scanRate.HeadlessTemplateConcurrency)
	viper.Set("scanrate.javascripttemplateconcurrency", scanRate.JavascriptTemplateConcurrency)
	viper.Set("scanrate.templatepayloadconcurrency", scanRate.TemplatePayloadConcurrency)
	viper.Set("scanrate.probeconcurrency", scanRate.ProbeConcurrency)

	// 写入文件
	if err := viper.WriteConfig(); err != nil {
		return fmt.Errorf("保存扫描速率配置到文件失败: %v", err)
	}

	// 记录保存的配置
	logger.Info("扫描速率配置已保存到文件",
		zap.Int("globalRate", scanRate.GlobalRate),
		zap.String("globalRateUnit", scanRate.GlobalRateUnit),
		zap.Int("templateConcurrency", scanRate.TemplateConcurrency),
		zap.Int("hostConcurrency", scanRate.HostConcurrency),
	)

	return nil
}
