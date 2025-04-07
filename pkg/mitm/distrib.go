package mitm

import (
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
	if task == nil {
		logger.Error("扫描任务未初始化")
		return
	}

	// 创建扫描输入
	scanInput := &models.PassiveResult{
		Url:     f.Request.URL.String(),
		Host:    f.Request.URL.Hostname(),
		Path:    f.Request.URL.Path,
		Method:  f.Request.Method,
		Headers: f.Request.Header,
		Body:    string(f.Request.Body),
	}

	logger.Info("开始处理目标",
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
