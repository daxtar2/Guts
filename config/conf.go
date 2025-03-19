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
	var err error
	once.Do(func() {
		err = loadConfig()
		if err == nil {
			go watchConfig()
		}
	})
	return err
}

// loadConfig 从文件加载配置
func loadConfig() error {
	// 1. 设置默认配置
	setDefaultConfig()

	// 2. 读取配置文件
	viper.SetConfigFile("./config/config.yaml")
	if err := viper.ReadInConfig(); err != nil {
		logger.Warn("无法读取配置文件，将使用默认配置",
			zap.String("path", viper.ConfigFileUsed()),
			zap.Error(err))
	}

	// 3. 解析配置到结构体
	GConfig = &models.Config{}
	if err := viper.Unmarshal(GConfig); err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 4. 确保所有字段都被正确加载
	if GConfig.Mitmproxy.FilterSuffix == nil {
		GConfig.Mitmproxy.FilterSuffix = []string{}
	}
	if GConfig.Mitmproxy.IncludeDomain == nil {
		GConfig.Mitmproxy.IncludeDomain = []string{}
	}
	if GConfig.Mitmproxy.ExcludeDomain == nil {
		GConfig.Mitmproxy.ExcludeDomain = []string{}
	}

	// 5. 记录加载的配置
	logger.Info("配置加载成功",
		zap.Any("mitmproxy", GConfig.Mitmproxy),
		zap.Any("headerMap", GConfig.HeaderMap),
		zap.Any("caConfig", GConfig.CaConfig),
		zap.Any("redis", GConfig.Redis),
		zap.Any("templateFilter", GConfig.TemplateFilter),
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
		if err := loadConfig(); err != nil {
			logger.Error("重新加载配置失败", zap.Error(err))
		} else {
			// 记录重新加载后的配置
			logger.Info("配置重新加载成功",
				zap.Any("mitmproxy", GConfig.Mitmproxy),
				zap.Any("headerMap", GConfig.HeaderMap),
				zap.Any("caConfig", GConfig.CaConfig),
				zap.Any("redis", GConfig.Redis),
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
