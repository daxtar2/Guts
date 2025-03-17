package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/cache"
	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/models"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"go.uber.org/zap"
	"golang.org/x/net/context"
)

type Task struct {
	MaxPoolsize   int // 最大并发数
	Wg            *sync.WaitGroup
	engine        *nuclei.NucleiEngine
	results       chan *output.ResultEvent
	templateCache *cache.RedisManager // 使用 RedisManager
	resultChan    chan *models.ScanResult
}

// 初始化扫描任务
func NewTask(maxPoolsize int) (*Task, error) {
	// 获取程序运行目录
	execPath, err := os.Getwd()
	if err != nil {
		logger.Error("获取程序运行路径失败", zap.Error(err))
		return nil, err
	}

	// 构建模板路径 - 修正为正确的目录结构
	baseTemplatesPath := filepath.Join(execPath, "templates") // 添加 templates 子目录
	workflowsPath := filepath.Join(baseTemplatesPath, "workflows")

	logger.Info("使用模板路径",
		zap.String("templates", baseTemplatesPath),
		zap.String("workflows", workflowsPath))

	// 验证模板目录是否存在
	if _, err := os.Stat(baseTemplatesPath); os.IsNotExist(err) {
		logger.Error("模板目录不存在",
			zap.String("path", baseTemplatesPath),
			zap.Error(err))
		return nil, fmt.Errorf("模板目录不存在: %s", baseTemplatesPath)
	}

	// 创建 Redis 客户端
	redisManager := cache.NewRedisManager(config.GConfig.Redis.Address)

	// 创建配置包装器
	configWrapper := cache.NewConfigWrapper(redisManager)

	// 设置模板搜索路径
	templateConfig := config.GetLoaderConfig()
	templateConfig.Templates = []string{baseTemplatesPath}
	templateConfig.Workflows = []string{workflowsPath}

	// 从配置包装器获取模板过滤器配置
	templateFilters := configWrapper.GetTemplateFilters()

	options := []nuclei.NucleiSDKOptions{
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Severity:             templateFilters.Severity,
			ExcludeSeverities:    templateFilters.ExcludeSeverities,
			ProtocolTypes:        templateFilters.ProtocolTypes,
			ExcludeProtocolTypes: templateFilters.ExcludeProtocolTypes,
			Authors:              templateFilters.Authors,
			Tags:                 templateFilters.Tags,
			ExcludeTags:          templateFilters.ExcludeTags,
			IncludeTags:          templateFilters.IncludeTags,
			IDs:                  templateFilters.IDs,
			ExcludeIDs:           templateFilters.ExcludeIDs,
			TemplateCondition:    templateFilters.TemplateCondition,
		}),
		//nuclei.EnablePassiveMode(),
		nuclei.DisableUpdateCheck(),
		nuclei.EnableStatsWithOpts(nuclei.StatsOptions{MetricServerPort: 6064}),
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{
				filepath.Join(baseTemplatesPath, "http"),
				filepath.Join(baseTemplatesPath, "passive"),
				filepath.Join(baseTemplatesPath, "cloud"),
				filepath.Join(baseTemplatesPath, "code"),
				filepath.Join(baseTemplatesPath, "dast"),
				filepath.Join(baseTemplatesPath, "dns"),
				filepath.Join(baseTemplatesPath, "file"),
				filepath.Join(baseTemplatesPath, "headless"),
				filepath.Join(baseTemplatesPath, "javascript"),
				filepath.Join(baseTemplatesPath, "ssl"),
			},
			Workflows: []string{workflowsPath},
		}),
		nuclei.WithGlobalRateLimit(30, time.Second), //速率限制
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:           100,
			HostConcurrency:               100,
			HeadlessHostConcurrency:       50,
			HeadlessTemplateConcurrency:   50,
			JavascriptTemplateConcurrency: 50,
			TemplatePayloadConcurrency:    25,
			ProbeConcurrency:              50,
		}),
	}

	engine, err := nuclei.NewNucleiEngineCtx(context.Background(), options...)
	if err != nil {
		logger.Error("创建nuclei引擎失败", zap.Error(err))
		return nil, err
	}

	// 创建任务
	t := &Task{
		MaxPoolsize:   maxPoolsize,
		engine:        engine,
		results:       make(chan *output.ResultEvent, 100),
		Wg:            &sync.WaitGroup{},
		templateCache: redisManager,
		resultChan:    make(chan *models.ScanResult, 100),
	}

	// 加载所有模板
	if err := engine.LoadAllTemplates(); err != nil {
		engine.Close()
		logger.Error("加载模板失败", zap.Error(err))
		return nil, err
	}

	// 添加调试日志
	logger.Info("模板加载完成",
		zap.Int("templates_count", len(engine.Store().Templates())),
		zap.Int("workflows_count", len(engine.Store().Workflows())))

	return t, nil
}

// ScanPassiveResult 执行被动扫描
func (t *Task) ScanPassiveResult(passiveResult *models.PassiveResult) error {

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
	default:
		logger.Warn("结果通知队列已满")
	}
}

// ExecuteScan 执行具体的扫描任务
func (t *Task) ExecuteScan(passiveResult *models.PassiveResult) error {
	target := []string{passiveResult.Url}

	// 创建一个上下文，可以用于控制超时和取消
	Ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// 使用上下文加载目标
	t.engine.LoadTargets(target, false)

	logger.Info("开始扫描目标", zap.String("url", target[0]))

	// 添加互斥锁保护执行过程
	executionMutex := &sync.Mutex{}

	// 添加调试日志
	logger.Info("扫描前状态",
		zap.Int("templates_count", len(t.engine.Store().Templates())),
		zap.String("target", passiveResult.Url))

	// 执行扫描，使用上下文和互斥锁保护执行过程
	executionMutex.Lock()
	err := t.engine.ExecuteCallbackWithCtx(Ctx, func(event *output.ResultEvent) {
		logger.Info("进入回调扫描")

		// 确保 event 和必要的字段不为 nil
		if event == nil || event.Info.Name == "" {
			logger.Warn("收到空的扫描结果或没有名称")
			return
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
			sevStr := event.Info.SeverityHolder.Severity.String()
			if sevStr != "" && sevStr != "unknown" && sevStr != "Unknown" {
				severity = sevStr
			}

			// 创建扫描结果
			scanResult := &models.ScanResult{
				ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
				Target:      event.URL,
				Name:        event.Info.Name,
				Severity:    severity,
				Type:        event.Type,
				Host:        event.Host,
				MatchedAt:   event.Matched,
				Description: event.Info.Description,
				Tags:        event.Info.Tags.ToSlice(),
				Reference:   event.Info.Reference.ToSlice(),
				Timestamp:   time.Now(),
			}

			// 检查 Redis 客户端是否初始化
			if t.templateCache == nil || t.templateCache.Client == nil {
				logger.Error("Redis 客户端未初始化")
				return
			}

			// 保存结果到 Redis
			if err := t.templateCache.Client.SaveScanResult(scanResult); err != nil {
				logger.Error("保存扫描结果到 Redis 失败",
					zap.Error(err),
					zap.String("target", event.URL),
					zap.String("vuln", event.Info.Name))
			} else {
				logger.Info("成功保存扫描结果到 Redis",
					zap.String("id", scanResult.ID),
					zap.String("target", scanResult.Target))
			}

			// 发送结果通知
			t.NotifyResult(scanResult)
		}()
	})
	executionMutex.Unlock()

	if err != nil {
		logger.Error("执行漏洞扫描失败", zap.Error(err))
		return err
	}

	// 重要：不要在每次扫描后关闭引擎
	// 只在应用退出时关闭
	// defer t.engine.Close()

	return nil
}

// 添加一个新方法用于应用退出时清理资源
func (t *Task) Close() {
	if t.engine != nil {
		t.engine.Close()
	}
}
