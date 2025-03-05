package mitm

import (
	"path/filepath"

	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
	"github.com/daxtar2/Guts/pkg/models"
	"github.com/daxtar2/Guts/pkg/scan"
	"github.com/daxtar2/Guts/pkg/util"
	"github.com/thoas/go-funk"
	"go.uber.org/zap"
)

type InfoAddon struct {
	proxy.BaseAddon
	config     *models.Config
	task       *scan.Task
	filterList []string
}

// 添加配置更新通道
var configUpdateChan = make(chan models.MitmproxyConfig, 1)

// 更新配置的方法
func UpdateConfig(newConfig models.MitmproxyConfig) {
	configUpdateChan <- newConfig
}

// 判断域名黑白名单
func isDomainAllowed(f *proxy.Flow) bool {
	host := f.Request.URL.Host
	cfg := config.GConfig.Mitmproxy

	// 添加日志记录
	logger.Debug("域名检查",
		zap.String("host", host),
		zap.Strings("include_domains", cfg.IncludeDomain),
		zap.Strings("exclude_domains", cfg.ExcludeDomain))

	// 1. 如果有白名单
	if len(cfg.IncludeDomain) > 0 && !(len(cfg.IncludeDomain) == 1 && cfg.IncludeDomain[0] == "") {
		allowed := util.JudgeHostByRegex(cfg.IncludeDomain, host)
		logger.Debug("白名单检查结果",
			zap.String("host", host),
			zap.Bool("allowed", allowed))
		if !allowed {
			return false
		}
	}

	// 2. 如果有黑名单
	if len(cfg.ExcludeDomain) > 0 && !(len(cfg.ExcludeDomain) == 1 && cfg.ExcludeDomain[0] == "") {
		excluded := util.JudgeHostByRegex(cfg.ExcludeDomain, host)
		logger.Debug("黑名单检查结果",
			zap.String("host", host),
			zap.Bool("excluded", excluded))
		if excluded {
			return false
		}
	}

	// 3. 如果都没有配置，默认允许
	logger.Debug("无黑白名单配置，默认允许",
		zap.String("host", host))
	return true
}

// 从后缀判断文件类型
func isSuffixAllowed(f *proxy.Flow) bool {
	ext := filepath.Ext(f.Request.URL.Path)
	allowed := ext == "" || !funk.Contains(config.GConfig.Mitmproxy.FilterSuffix, ext)

	logger.Debug("后缀检查",
		zap.String("path", f.Request.URL.Path),
		zap.String("ext", ext),
		zap.Strings("filter_suffix", config.GConfig.Mitmproxy.FilterSuffix),
		zap.Bool("allowed", allowed))

	return allowed
}

func NewInfoAddon(config *models.Config, task *scan.Task, filterList []string) *InfoAddon {
	return &InfoAddon{
		config:     config,
		task:       task,
		filterList: filterList,
	}
}

func (IA *InfoAddon) Response(f *proxy.Flow) {
	// 非阻塞方式检查配置更新
	select {
	case newConfig := <-configUpdateChan:
		config.GConfig.Mitmproxy = newConfig
	default:
	}

	if f.Request.Method == "CONNECT" {
		return
	} //skip CONNECT request

	logger.Info("收到新的响应",
		zap.String("host", f.Request.URL.Host),
		zap.String("url", f.Request.URL.String()))

	domainAllowed := isDomainAllowed(f)
	suffixAllowed := isSuffixAllowed(f)

	logger.Info("响应过滤结果",
		zap.String("host", f.Request.URL.Host),
		zap.String("url", f.Request.URL.String()),
		zap.Bool("domain_allowed", domainAllowed),
		zap.Bool("suffix_allowed", suffixAllowed))

	if domainAllowed && suffixAllowed {
		logger.Info("开始处理响应",
			zap.String("host", f.Request.URL.Host))

		distrib(f, IA.task)

		logger.Info("响应处理完成",
			zap.String("host", f.Request.URL.Host))
	} else {
		logger.Debug("响应被过滤",
			zap.String("host", f.Request.URL.Host),
			zap.String("path", f.Request.URL.Path),
			zap.String("content-type", f.Response.Header.Get("Content-Type")))
	}
}
