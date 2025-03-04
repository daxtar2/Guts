package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/cache"
	"github.com/daxtar2/Guts/pkg/header"
	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/models" // 引入模型
	"github.com/panjf2000/ants/v2"
	"github.com/projectdiscovery/gologger"
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
	templateCache *cache.RedisClient // 使用 RedisClient
}

// 初始化扫描任务
func NewTask(maxPoolsize int) (*Task, error) {
	// 获取程序运行目录
	execPath, err := os.Getwd()
	if err != nil {
		logger.Error("获取程序运行路径失败", zap.Error(err))
		return nil, err
	}

	// 构建模板路径
	templatesPath := filepath.Join(execPath, "templates", "nuclei-templates-10.1.3")
	workflowsPath := filepath.Join(templatesPath, "workflows")

	logger.Info("使用模板路径",
		zap.String("templates", templatesPath),
		zap.String("workflows", workflowsPath))

	// 设置模板搜索路径
	templateConfig := config.GetLoaderConfig()
	templateConfig.TemplatesDirectory = templatesPath // 设置模板根目录

	options := []nuclei.NucleiSDKOptions{
		nuclei.WithTemplateFilters(config.GetTemplateFilters()),
		nuclei.WithCatalog(templateConfig.Catalog),
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{templatesPath}, // 使用完整路径
			Workflows: []string{workflowsPath},
		}),
		// 添加自定义模板目录
		nuclei.WithCustomTemplates([]string{
			filepath.Join(templatesPath, "http", "technologies"),
			filepath.Join(templatesPath, "http", "vulnerabilities"),
			// 添加其他需要的模板目录
		}),
		nuclei.EnableStatsWithOpts(nuclei.StatsOptions{MetricServerPort: 8080}),
		nuclei.WithGlobalRateLimit(1, time.Second),
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:           1,
			HostConcurrency:               1,
			HeadlessHostConcurrency:       1,
			HeadlessTemplateConcurrency:   1,
			JavascriptTemplateConcurrency: 1,
			TemplatePayloadConcurrency:    1,
			ProbeConcurrency:              1,
		}),
	}

	// 验证模板目录是否存在
	if _, err := os.Stat(templatesPath); os.IsNotExist(err) {
		logger.Error("模板目录不存在",
			zap.String("path", templatesPath),
			zap.Error(err))
		return nil, fmt.Errorf("模板目录不存在: %s", templatesPath)
	}

	// 检查特定的模板文件是否存在
	techPath := filepath.Join(templatesPath, "http", "technologies")
	if _, err := os.Stat(techPath); os.IsNotExist(err) {
		logger.Error("technologies目录不存在",
			zap.String("path", techPath),
			zap.Error(err))
		return nil, fmt.Errorf("technologies目录不存在: %s", techPath)
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
		templateCache: cache.NewRedisClient(config.RedisAddr), // 使用 RedisClient
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
func (t *Task) ScanPassiveResult(result *header.PassiveResult) error {
	start := time.Now() // 记录任务开始时间
	target := []string{result.Host}
	t.engine.LoadTargets(target, false)

	workflowHit := false //命中指纹
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 保存扫描结果到 Redis
	scanResult := &models.ScanResult{
		ID:         result.Host, // 使用主机作为唯一标识
		Host:       result.Host,
		VulnName:   "Example Vulnerability", // 这里可以根据实际情况设置
		Severity:   "medium",                // 这里可以根据实际情况设置
		CreateTime: time.Now().Format(time.RFC3339),
		Details:    "Details about the vulnerability", // 这里可以根据实际情况设置
	}

	// 执行漏洞扫描
	err := t.engine.ExecuteCallbackWithCtx(ctx, func(result *output.ResultEvent) {
		if result != nil && result.Info.Name != "" {
			t.Wg.Add(1)
			workflowHit = true
			_ = t.Pool.Submit(func() {
				defer t.Wg.Done()
				fmt.Printf("[+] %s [%s] %s\n",
					result.Host,
					result.Info.SeverityHolder.Severity.String(),
					result.Info.Name)
				// 保存结果到 Redis
				if err := t.templateCache.SaveScanResult(scanResult); err != nil {
					logger.Error("保存扫描结果到 Redis 失败", zap.Error(err))
				}
			})
		}
	})
	if err != nil {
		logger.Error("工作流执行出错", zap.Error(err))
		return err
	}

	if !workflowHit {
		gologger.Info().Msg("[未命中任何 Workflow, 通过 Redis 动态加载模板并重新扫描]")
		if err := t.scanWithTemplatesLoader(result); err != nil {
			logger.Error("Redis模板扫描失败", zap.Error(err))
		}
	}
	logger.Info("扫描完成", zap.String("host", result.Host), zap.Duration("duration", time.Since(start)))
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
