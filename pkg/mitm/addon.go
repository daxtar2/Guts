package mitm

import (
	"bytes"
	"io"

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

// InfoAddon 用于处理代理流量
type infoAddon struct {
	proxy.BaseAddon
	config       *models.Config
	task         *scan.Task
	filterSuffix []string
}

// NewInfoAddon 创建新的 InfoAddon
func newInfoAddon(cfg *models.Config, task *scan.Task, filterSuffix []string) *infoAddon {
	return &infoAddon{
		config:       cfg,
		task:         task,
		filterSuffix: filterSuffix,
	}
}

// Request 处理请求体
func (addon *infoAddon) Request(f *proxy.Flow) {
	if len(f.Request.Body) > 0 {
		logger.Info("Request Body",
			zap.String("host", f.Request.URL.Host),
			zap.String("url", f.Request.URL.String()),
		)
	}
}

// 判断域名黑白名单
func (addon *infoAddon) isDomainAllowed(f *proxy.Flow) bool {
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
func (addon *infoAddon) isSuffixAllowed(f *proxy.Flow) bool {
	ext := filepath.Ext(f.Request.URL.Path)
	allowed := ext == "" || !funk.Contains(config.GConfig.Mitmproxy.FilterSuffix, ext)

	logger.Debug("后缀检查",
		zap.String("path", f.Request.URL.Path),
		zap.String("ext", ext),
		zap.Strings("filter_suffix", config.GConfig.Mitmproxy.FilterSuffix),
		zap.Bool("allowed", allowed))

	return allowed
}

// Response 处理响应体
func (addon *infoAddon) Response(f *proxy.Flow) {

	logger.Info("处理响应",
		zap.String("url", f.Request.URL.String()),
		zap.String("method", f.Request.Method),
		zap.Int("status", f.Response.StatusCode))

	if f.Request.Method == "CONNECT" {
		logger.Debug("跳过 CONNECT 请求")
		return
	}

	// 检查域名黑白名单
	domainAllowed := addon.isDomainAllowed(f)
	if !domainAllowed {
		logger.Debug("域名被过滤",
			zap.String("host", f.Request.URL.Host))
		return
	}

	// 检查文件后缀
	suffixAllowed := addon.isSuffixAllowed(f)
	if !suffixAllowed {
		logger.Debug("文件后缀被过滤",
			zap.String("path", f.Request.URL.Path))
		return
	}

	logger.Info("响应过滤结果",
		zap.String("host", f.Request.URL.Host),
		zap.String("url", f.Request.URL.String()),
		zap.Bool("domain_allowed", domainAllowed),
		zap.Bool("suffix_allowed", suffixAllowed))

	if domainAllowed && suffixAllowed {
		logger.Info("开始处理响应",
			zap.String("url", f.Request.URL.String()))
		distrib(f, addon.task)
	}

	logger.Info("响应处理完成",
		zap.String("url", f.Request.URL.String()))
}

// StreamRequestModifier 处理流式请求
func (addon *infoAddon) StreamRequestModifier(f *proxy.Flow, in io.Reader) io.Reader {
	if in == nil {
		return nil
	}

	pr, pw := io.Pipe()
	writer := io.MultiWriter(pw, &bytes.Buffer{})

	go func() {
		defer pw.Close()
		io.Copy(writer, in)
	}()

	return pr
}

// StreamResponseModifier 处理流式响应
func (addon *infoAddon) StreamResponseModifier(f *proxy.Flow, in io.Reader) io.Reader {
	if in == nil {
		return nil
	}

	pr, pw := io.Pipe()
	writer := io.MultiWriter(pw, &bytes.Buffer{})

	go func() {
		defer pw.Close()
		io.Copy(writer, in)
	}()

	return pr
}
