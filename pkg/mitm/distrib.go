package mitm

import (
	"strings"
	"sync"
	"time"

	"github.com/daxtar2/Guts/pkg/header"
	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
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
	host := parseUrl.Hostname()
	logger.Info("开始处理目标", zap.String("host", host))
	// 检查是否已经扫描过该域名
	if _, exists := scannedHosts.LoadOrStore(host, true); exists {
		return // 如果已经扫描过，直接返回
	}

	// 构建请求头映射
	headerMap := make(map[string]string)
	for key, value := range f.Request.Header {
		if key == "Set-Cookie" {
			headerMap[key] = strings.Join(value, ";")
		} else {
			headerMap[key] = strings.Join(value, ",")
		}
	}

	// 构建扫描输入
	scanInput := &header.PassiveResult{
		Url:         parseUrl.String(),
		ParseUrl:    parseUrl,
		Host:        host,
		Method:      f.Request.Method,
		Headers:     headerMap,
		RequestBody: string(f.Request.Body),
		ContentType: f.Request.Header.Get("Content-Type"),
		RawRequest:  ReqToString(f.Request),
		RawResponse: RespToString(f),
	}

	// 使用传入的 task 执行扫描
	go func(input *header.PassiveResult) {
		if err := task.ScanPassiveResult(input); err != nil {
			logger.Error("域名扫描失败", zap.String("host", input.Host), zap.Error(err))
		}
		logger.Info("域名扫描完成", zap.String("host", input.Host))
	}(scanInput)
}

func (d *Distributor) Distribute(scanInput *header.PassiveResult) error {
	logger.Info("接收到扫描任务",
		zap.String("host", scanInput.Host),
		zap.String("url", scanInput.Url))

	// 检查是否已经扫描过该域名
	if _, exists := scannedHosts.LoadOrStore(scanInput.Host, true); exists {
		logger.Debug("目标已扫描过，跳过",
			zap.String("host", scanInput.Host))
		return nil
	}

	// 提交扫描任务
	return d.pool.Submit(func() {
		logger.Info("开始执行扫描任务",
			zap.String("host", scanInput.Host))

		if err := d.scanTask.ScanPassiveResult(scanInput); err != nil {
			logger.Error("扫描任务执行失败",
				zap.Error(err),
				zap.String("host", scanInput.Host))
		}

		logger.Info("扫描任务执行完成",
			zap.String("host", scanInput.Host))
	})
}
