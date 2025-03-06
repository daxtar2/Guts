package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/cache"
	"github.com/daxtar2/Guts/pkg/header"
	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/models"
	"github.com/panjf2000/ants/v2"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"go.uber.org/zap"
	"golang.org/x/net/context"
)

type Task struct {
	MaxPoolsize   int // 最大并发数
	Pool          *ants.Pool
	Wg            *sync.WaitGroup
	engine        *nuclei.NucleiEngine
	results       chan *output.ResultEvent
	templateCache *cache.RedisManager // 使用 RedisManager
	resultChan    chan *models.ScanResult
	//done          chan struct{} // 添加一个完成信号通道
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
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{
				filepath.Join(baseTemplatesPath, "cloud"),
				filepath.Join(baseTemplatesPath, "code"),
				filepath.Join(baseTemplatesPath, "dast"),
				filepath.Join(baseTemplatesPath, "dns"),
				filepath.Join(baseTemplatesPath, "file"),
				filepath.Join(baseTemplatesPath, "headless"),
				filepath.Join(baseTemplatesPath, "http"),
				filepath.Join(baseTemplatesPath, "javascript"),
				filepath.Join(baseTemplatesPath, "passive"),
				//filepath.Join(baseTemplatesPath, "profiles"),
				filepath.Join(baseTemplatesPath, "ssl"),
			},
			Workflows: []string{workflowsPath},
		}),
		nuclei.EnableStatsWithOpts(nuclei.StatsOptions{MetricServerPort: 8080}),
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine, err := nuclei.NewNucleiEngineCtx(ctx, options...)
	if err != nil {
		logger.Error("创建nuclei引擎失败", zap.Error(err))
		return nil, err
	}

	// 创建工作池
	pool, err := ants.NewPool(maxPoolsize, ants.WithPreAlloc(true))
	if err != nil {
		engine.Close()
		logger.Error("创建工作池失败", zap.Error(err))
		return nil, err
	}
	defer pool.Release()

	// 创建任务
	t := &Task{
		MaxPoolsize:   maxPoolsize,
		Pool:          pool,
		engine:        engine,
		results:       make(chan *output.ResultEvent, 100),
		Wg:            &sync.WaitGroup{},
		templateCache: redisManager,
		resultChan:    make(chan *models.ScanResult, 100),
		//done:          make(chan struct{}),
	}

	// 加载所有模板
	if err := t.engine.LoadAllTemplates(); err != nil {
		engine.Close()
		logger.Error("加载模板失败", zap.Error(err))
		return nil, err
	}

	return t, nil
}

// ScanPassiveResult 执行被动扫描
func (t *Task) ScanPassiveResult(passiveResult *header.PassiveResult) error {

	err := t.executeScan(passiveResult)
	if err != nil {
		return err
	}
	logger.Warn("扫描失败，准备重试",
		zap.String("host", passiveResult.Host),
		zap.Error(err))
	return nil
}

// scanWithTemplatesLoader 从 Redis 加载相关技术栈的模板
func (t *Task) scanWithTemplatesLoader(result *header.PassiveResult) error {
	// 这里不再需要从 Redis 加载模板
	// 直接使用 nuclei 的加载逻辑
	logger.Info("使用已加载的模板进行扫描", zap.String("host", result.Host))

	// 设置扫描目标
	target := []string{result.Host}
	t.engine.LoadTargets(target, false)

	// 使用加载的模板执行扫描
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := t.engine.ExecuteCallbackWithCtx(ctx, func(result *output.ResultEvent) {
		if result != nil && result.Info.Name != "" {
			t.Wg.Add(1)
			_ = t.Pool.Submit(func() {
				defer t.Wg.Done()
				fmt.Printf("[+] %s [%s] %s\n",
					result.Host,
					result.Info.SeverityHolder.Severity.String(),
					result.Info.Name)
			})
		}
	})

	if err != nil {
		logger.Error("模板扫描执行出错", zap.Error(err))
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

// executeScan 执行具体的扫描任务
func (t *Task) executeScan(passiveResult *header.PassiveResult) error {
	start := time.Now()
	target := []string{passiveResult.Host}
	t.engine.LoadTargets(target, false)
	logger.Info("加载目标成功", zap.String("host", passiveResult.Host))

	var workflowHit atomic.Value
	workflowHit.Store(false)
	var hasResults atomic.Value
	hasResults.Store(false) // 添加标志，记录是否有任何结果

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 执行漏洞扫描
	err := t.engine.ExecuteCallbackWithCtx(ctx, func(event *output.ResultEvent) {
		if event != nil && event.Info.Name != "" {
			hasResults.Store(true) // 标记有结果
			t.Wg.Add(1)
			workflowHit.Store(true)
			if err := t.Pool.Submit(func() {
				defer t.Wg.Done()
				logger.Info("执行漏洞扫描", zap.String("host", event.Host))

				// 创建扫描结果
				scanResult := &models.ScanResult{
					ID:          fmt.Sprintf("%s-%d", event.Host, time.Now().UnixNano()),
					Target:      event.Host,
					Name:        event.Info.Name,
					Severity:    event.Info.SeverityHolder.Severity.String(),
					Type:        event.Type,
					Host:        event.Host,
					MatchedAt:   event.Matched,
					Description: event.Info.Description,
					Tags:        event.Info.Tags.ToSlice(),      // 使用 ToSlice() 方法
					Reference:   event.Info.Reference.ToSlice(), // 使用 ToSlice() 方法
					Timestamp:   time.Now(),
				}

				// 保存结果到 Redis
				if err := t.templateCache.Client.SaveScanResult(scanResult); err != nil {
					logger.Error("保存扫描结果到 Redis 失败",
						zap.Error(err),
						zap.String("target", event.Host),
						zap.String("vuln", event.Info.Name))
				} else {
					logger.Info("成功保存扫描结果到 Redis",
						zap.String("id", scanResult.ID),
						zap.String("target", scanResult.Target))
				}

				// 发送结果通知
				t.NotifyResult(scanResult)

				// 打印扫描结果
				logger.Info("发现漏洞",
					zap.String("target", event.Host),
					zap.String("name", event.Info.Name),
					zap.String("severity", event.Info.SeverityHolder.Severity.String()),
					zap.String("type", event.Type),
					zap.String("matched_at", event.Matched))
			}); err != nil {
				logger.Error("提交任务到工作池失败", zap.Error(err))
				t.Wg.Done()
			}
		}
	})
	if err != nil {
		logger.Error("执行漏洞扫描失败", zap.Error(err))
		return err
	}

	// 等待所有扫描任务完成
	t.Wg.Wait()

	// 如果没有任何结果，创建一个"未发现漏洞"的结果
	if !hasResults.Load().(bool) {
		noVulnResult := &models.ScanResult{
			ID:          fmt.Sprintf("%s-%d", passiveResult.Host, time.Now().UnixNano()),
			Target:      passiveResult.Host,
			Name:        "No Vulnerabilities Found",
			Severity:    "info",
			Type:        "info",
			Host:        passiveResult.Host,
			MatchedAt:   "-",
			Description: "No vulnerabilities were detected during the scan",
			Tags:        []string{"safe"},
			Reference:   []string{},
			Timestamp:   time.Now(),
		}

		// 保存无漏洞结果到 Redis
		if err := t.templateCache.Client.SaveScanResult(noVulnResult); err != nil {
			logger.Error("保存无漏洞结果到 Redis 失败",
				zap.Error(err),
				zap.String("target", passiveResult.Host))
		} else {
			logger.Info("保存无漏洞结果到 Redis",
				zap.String("id", noVulnResult.ID),
				zap.String("target", noVulnResult.Target))
		}

		// 发送结果通知
		t.NotifyResult(noVulnResult)
	}

	// 记录扫描耗时
	elapsed := time.Since(start)
	logger.Info("扫描完成",
		zap.String("host", passiveResult.Host),
		zap.Duration("duration", elapsed),
		zap.Bool("workflow_hit", workflowHit.Load().(bool)),
		zap.Bool("has_results", hasResults.Load().(bool)))

	return nil
}
