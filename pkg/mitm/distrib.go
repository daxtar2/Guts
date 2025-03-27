package mitm

import (
	"net/http"
	"sync"
	"time"

	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
	"github.com/daxtar2/Guts/pkg/models"
	"github.com/daxtar2/Guts/pkg/scan"
	"github.com/panjf2000/ants/v2"
	"go.uber.org/zap"
)

var (
	// 用于去重的map
	scannedHosts = sync.Map{} //域名去重
)

type Distributor struct {
	pool         *ants.Pool
	scanTask     *scan.Task
	scannedHosts sync.Map // 用于记录已扫描的主机
	scanInterval time.Duration
}

func distrib(f *proxy.Flow, task *scan.Task) {
	parseUrl := f.Request.URL

	// 处理域名
	logger.Info("开始处理目标",
		zap.String("url", parseUrl.String()),
		zap.String("host", parseUrl.Host),
		zap.String("scheme", parseUrl.Scheme),
		zap.String("method", f.Request.Method))

	// 检查是否已经扫描过该域名
	if _, exists := scannedHosts.LoadOrStore(parseUrl, true); exists {
		logger.Info("目标已经扫描过，跳过",
			zap.String("url", parseUrl.String()))
		return // 如果已经扫描过，直接返回
	}

	// 记录所有请求头
	logger.Debug("请求头信息",
		zap.String("url", parseUrl.String()),
		zap.Any("headers", f.Request.Header))

	// 构建请求头映射
	headerMap := make(http.Header)
	for k, v := range f.Request.Header {
		headerMap[k] = v
	}

	// 构建被动扫描结果
	scanInput := &models.PassiveResult{
		Url:     parseUrl.String(),
		Host:    parseUrl.Hostname(),
		Method:  f.Request.Method,
		Headers: headerMap,
		Body:    string(f.Request.Body),
	}

	logger.Info("创建扫描任务",
		zap.String("url", scanInput.Url),
		zap.String("host", scanInput.Host),
		zap.String("method", scanInput.Method),
		zap.Int("headers_count", len(scanInput.Headers)),
		zap.Int("body_length", len(scanInput.Body)))

	// 使用传入的 task 执行扫描
	go func(input *models.PassiveResult) {
		logger.Info("开始执行扫描任务",
			zap.String("url", input.Url))

		if err := task.ScanPassiveResult(input); err != nil {
			logger.Error("目标扫描失败", zap.String("url", input.Url), zap.Error(err))
		} else {
			logger.Info("目标扫描成功", zap.String("url", input.Url))
		}

		logger.Info("扫描任务完成", zap.String("url", input.Url))
	}(scanInput)
}
