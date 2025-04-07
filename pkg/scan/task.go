package scan

import (
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/daxtar2/Guts/pkg/cache"
	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/models"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"go.uber.org/zap"
	"golang.org/x/net/context"
)

// Task 扫描任务结构体
type Task struct {
	MaxPoolsize int // 最大并发数
	Wg          *sync.WaitGroup
	engine      *nuclei.NucleiEngine
	results     chan *output.ResultEvent
	resultChan  chan *models.ScanResult
	scanning    sync.Map      // 用于跟踪正在扫描的目标
	stopChan    chan struct{} // 用于停止扫描
	config      *models.Config
	redis       *cache.RedisClient
}

// 创建扫描任务
func NewTask(config *models.Config) (*Task, error) {
	// 创建 Redis 管理器
	redisManager := cache.NewRedisClient(config.Redis.Address)

	// 获取模板基础路径
	baseTemplatesPath := "./templates"
	workflowsPath := filepath.Join(baseTemplatesPath, "workflows")

	// 创建扫描引擎
	engine, err := nuclei.NewNucleiEngine(
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Severity:             config.TemplateFilter.Severity,
			ExcludeSeverities:    config.TemplateFilter.ExcludeSeverities,
			ProtocolTypes:        config.TemplateFilter.ProtocolTypes,
			ExcludeProtocolTypes: config.TemplateFilter.ExcludeProtocolTypes,
			Authors:              config.TemplateFilter.Authors,
			Tags:                 config.TemplateFilter.Tags,
			ExcludeTags:          config.TemplateFilter.ExcludeTags,
			IncludeTags:          config.TemplateFilter.IncludeTags,
			IDs:                  config.TemplateFilter.IDs,
			ExcludeIDs:           config.TemplateFilter.ExcludeIDs,
			TemplateCondition:    config.TemplateFilter.TemplateCondition,
		}),
		nuclei.DisableUpdateCheck(),
		nuclei.SignedTemplatesOnly(),
		nuclei.EnableStatsWithOpts(nuclei.StatsOptions{MetricServerPort: 6064}),
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{baseTemplatesPath},
			Workflows: []string{workflowsPath},
		}),
		// 从配置中读取扫描速率设置
		func() nuclei.NucleiSDKOptions {
			rateConfig := config.ScanRate
			globalRate := 30
			if rateConfig.GlobalRate > 0 {
				globalRate = rateConfig.GlobalRate
			}
			rateUnit := time.Second
			if rateConfig.GlobalRateUnit == "minute" {
				rateUnit = time.Minute
			} else if rateConfig.GlobalRateUnit == "hour" {
				rateUnit = time.Hour
			}
			return nuclei.WithGlobalRateLimit(globalRate, rateUnit)
		}(),
	)
	if err != nil {
		return nil, fmt.Errorf("创建扫描引擎失败: %v", err)
	}

	task := &Task{
		MaxPoolsize: 10,
		Wg:          &sync.WaitGroup{},
		config:      config,
		engine:      engine,
		redis:       redisManager,
		results:     make(chan *output.ResultEvent, 1000),
		resultChan:  make(chan *models.ScanResult, 1000),
		stopChan:    make(chan struct{}),
		scanning:    sync.Map{},
	}

	// 启动结果处理协程
	go task.processResults()

	return task, nil
}

// 处理扫描结果
func (t *Task) processResults() {
	for result := range t.results {
		// 创建扫描结果
		scanResult := &models.ScanResult{
			ID:          result.TemplateID,
			Target:      result.Matched,
			Name:        result.TemplatePath,
			Severity:    result.Info.SeverityHolder.Severity.String(),
			Type:        "http",
			Host:        result.Host,
			MatchedAt:   result.Matched,
			Description: result.Info.Description,
			Tags:        result.Info.Tags.ToSlice(),
			Reference:   result.Info.Reference.ToSlice(),
			Timestamp:   time.Now(),
		}

		// 保存到 Redis
		if err := t.redis.SaveScanResult(scanResult); err != nil {
			logger.Error("保存扫描结果到 Redis 失败",
				zap.String("url", scanResult.Target),
				zap.Error(err))
		}

		// 发送结果到通道
		t.resultChan <- scanResult
	}
}

// 扫描目标
func (t *Task) ScanTarget(target string) error {
	// 检查是否已停止
	select {
	case <-t.stopChan:
		return fmt.Errorf("扫描已停止")
	default:
	}

	// 检查是否正在扫描
	if _, exists := t.scanning.LoadOrStore(target, true); exists {
		return fmt.Errorf("目标正在扫描中")
	}
	defer t.scanning.Delete(target)

	// 获取路径 fuzz 配置
	pathFuzzConfig := t.config.PathFuzz
	if !pathFuzzConfig.Enabled || len(pathFuzzConfig.Paths) == 0 {
		// 如果未启用路径 fuzz 或路径列表为空，直接扫描目标
		return t.engine.ExecuteCallbackWithCtx(context.Background(), func(event *output.ResultEvent) {
			t.results <- event
		})
	}

	// 解析目标 URL
	targetURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("解析目标 URL 失败: %v", err)
	}

	// 对每个路径进行 fuzz
	for _, path := range pathFuzzConfig.Paths {
		// 检查是否已停止
		select {
		case <-t.stopChan:
			return fmt.Errorf("扫描已停止")
		default:
		}

		// 构建新的 URL
		newURL := *targetURL
		newURL.Path = path
		newTarget := newURL.String()

		// 执行扫描
		if err := t.engine.ExecuteCallbackWithCtx(context.Background(), func(event *output.ResultEvent) {
			t.results <- event
		}); err != nil {
			logger.Error("扫描路径失败",
				zap.String("target", newTarget),
				zap.Error(err))
		}
	}

	return nil
}

// ScanPassiveResult 执行被动扫描
func (t *Task) ScanPassiveResult(passiveResult *models.PassiveResult) error {
	if t == nil {
		return fmt.Errorf("扫描任务未初始化")
	}

	err := t.ExecuteScan(passiveResult)
	if err != nil {
		logger.Warn("扫描失败", zap.String("url", passiveResult.Url), zap.Error(err))
		return err
	}

	return nil
}

func (t *Task) NotifyResult(result *models.ScanResult) {
	select {
	case t.resultChan <- result:
		// 保存到 Redis
		if err := t.redis.SaveScanResult(result); err != nil {
			logger.Error("保存扫描结果到 Redis 失败",
				zap.String("url", result.Target),
				zap.String("name", result.Name),
				zap.Error(err))
		} else {
			logger.Info("扫描结果已保存到 Redis",
				zap.String("url", result.Target),
				zap.String("name", result.Name))
		}
	default:
		logger.Warn("结果通知队列已满")
	}
}

// ExecuteScan 执行具体的扫描任务
func (t *Task) ExecuteScan(passiveResult *models.PassiveResult) error {
	// 检查目标是否已经在扫描中
	if _, exists := t.scanning.LoadOrStore(passiveResult.Url, true); exists {
		logger.Warn("目标已在扫描中，跳过", zap.String("url", passiveResult.Url))
		return nil
	}
	defer func() {
		t.scanning.Delete(passiveResult.Url)
		logger.Info("扫描状态已清理，准备接收新目标", zap.String("url", passiveResult.Url))
	}()

	target := []string{passiveResult.Url}

	// 创建一个带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 使用上下文加载目标
	t.engine.LoadTargets(target, false)

	logger.Info("开始扫描目标",
		zap.String("url", target[0]),
		zap.Int("timeout_seconds", 30))

	// 添加互斥锁保护执行过程
	executionMutex := &sync.Mutex{}

	// 添加调试日志
	logger.Info("扫描前状态",
		zap.Int("templates_count", len(t.engine.GetTemplates())),
		zap.String("target", passiveResult.Url))

	// 执行扫描，使用上下文和互斥锁保护执行过程
	executionMutex.Lock()
	defer executionMutex.Unlock()

	// 使用带缓冲的通道来防止结果处理阻塞
	resultChan := make(chan *output.ResultEvent, 50)
	defer close(resultChan)

	// 启动结果处理协程
	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("结果处理协程发生 panic", zap.Any("recover", r))
			}
			close(done)
			logger.Info("结果处理协程已退出", zap.String("url", passiveResult.Url))
		}()

		for {
			select {
			case event, ok := <-resultChan:
				if !ok {
					logger.Info("结果通道已关闭", zap.String("url", passiveResult.Url))
					return
				}
				if event == nil || event.Info.Name == "" {
					logger.Warn("收到空的扫描结果或没有名称")
					continue
				}

				parseUrl := event.URL
				func() {
					// 添加 recover 来防止 panic
					defer func() {
						if r := recover(); r != nil {
							logger.Error("扫描回调中发生 panic", zap.Any("recover", r))
						}
					}()

					// 确保 Add 和 Done 的调用匹配
					t.Wg.Add(1)
					defer t.Wg.Done()

					logger.Info("执行漏洞扫描", zap.String("url", parseUrl))

					// 在创建scanResult时添加更多的安全检查
					severity := "unknown"

					// 直接使用String()方法获取值，然后检查
					if sevStr := event.Info.SeverityHolder.Severity.String(); sevStr != "" && sevStr != "unknown" && sevStr != "Unknown" {
						severity = sevStr
					}

					// 创建扫描结果，添加空值检查
					scanResult := &models.ScanResult{
						ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
						Target:      parseUrl,
						Name:        getStringValue(event.Info, "Name"),
						Severity:    severity,
						Type:        getStringValue(event, "Type"),
						Host:        getStringValue(event, "Host"),
						MatchedAt:   getStringValue(event, "Matched"),
						Description: getStringValue(event.Info, "Description"),
						Tags:        getStringSlice(event.Info, "Tags"),
						Reference:   getStringSlice(event.Info, "Reference"),
						Timestamp:   time.Now(),
					}

					// 使用 NotifyResult 处理扫描结果
					t.NotifyResult(scanResult)
					logger.Info("扫描结果已处理", zap.String("url", parseUrl))
				}()
			case <-ctx.Done():
				logger.Info("扫描上下文已取消，等待新目标", zap.String("url", passiveResult.Url))
				return
			case <-t.stopChan:
				logger.Info("扫描被停止，等待新目标", zap.String("url", passiveResult.Url))
				return
			}
		}
	}()

	// 创建一个用于控制扫描超时的通道
	scanTimeout := make(chan struct{})
	go func() {
		time.Sleep(30 * time.Second)
		close(scanTimeout)
		logger.Info("扫描超时通道已关闭", zap.String("url", passiveResult.Url))
	}()

	// 执行扫描，使用自定义的结果处理函数
	err := t.engine.ExecuteCallbackWithCtx(ctx, func(event *output.ResultEvent) {
		select {
		case resultChan <- event:
			// 结果已成功发送到处理通道
		case <-ctx.Done():
			logger.Info("扫描上下文已取消", zap.String("url", event.URL))
		case <-t.stopChan:
			logger.Info("扫描被停止", zap.String("url", event.URL))
		case <-scanTimeout:
			logger.Info("扫描超时", zap.String("url", event.URL))
		default:
			logger.Warn("结果处理通道已满，丢弃结果", zap.String("url", event.URL))
		}
	})

	if err != nil {
		logger.Error("扫描执行失败", zap.Error(err))
		return err
	}

	// 等待所有结果处理完成或超时
	select {
	case <-done:
		logger.Info("扫描完成，等待新目标", zap.String("url", passiveResult.Url))
	case <-time.After(1 * time.Minute):
		logger.Warn("扫描超时，等待新目标", zap.String("url", passiveResult.Url))
	case <-scanTimeout:
		logger.Warn("扫描超时，等待新目标", zap.String("url", passiveResult.Url))
	}

	return nil
}

// Close 停止所有扫描任务
func (t *Task) Close() {
	close(t.stopChan)
	if t.engine != nil {
		t.engine.Close()
	}
}

// 添加辅助函数来安全地获取字符串值
func getStringValue(obj interface{}, field string) string {
	if obj == nil {
		return ""
	}

	value := reflect.ValueOf(obj)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}

	if value.Kind() != reflect.Struct {
		return ""
	}

	fieldValue := value.FieldByName(field)
	if !fieldValue.IsValid() {
		return ""
	}

	return fmt.Sprintf("%v", fieldValue.Interface())
}

// 添加辅助函数来安全地获取字符串切片
func getStringSlice(obj interface{}, field string) []string {
	if obj == nil {
		return []string{}
	}

	value := reflect.ValueOf(obj)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}

	if value.Kind() != reflect.Struct {
		return []string{}
	}

	fieldValue := value.FieldByName(field)
	if !fieldValue.IsValid() {
		return []string{}
	}

	if fieldValue.Kind() != reflect.Slice {
		return []string{}
	}

	result := make([]string, fieldValue.Len())
	for i := 0; i < fieldValue.Len(); i++ {
		result[i] = fmt.Sprintf("%v", fieldValue.Index(i).Interface())
	}

	return result
}
