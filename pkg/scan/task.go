package scan

import (
	"fmt"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"

	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/cache"
	"github.com/daxtar2/Guts/pkg/header"
	"github.com/panjf2000/ants/v2"
	"github.com/projectdiscovery/gologger"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"golang.org/x/net/context"
)

type Task struct {
	MaxPoolsize   int // 最大并发数
	Pool          *ants.Pool
	Wg            *sync.WaitGroup
	engine        *nuclei.NucleiEngine
	results       chan *output.ResultEvent
	templateCache *cache.TemplateCache //redis cache
	useRedis      bool                 //启动redis服务
}

// 初始化扫描任务
func NewTask(poolSize int) (*Task, error) {
	options := []nuclei.NucleiSDKOptions{
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{}),
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

	engine, err := nuclei.NewNucleiEngineCtx(context.Background(), options...)
	if err != nil {
		return nil, fmt.Errorf("创建nuclei引擎失败: %v", err)
	}

	storetmp, _ := loader.New(config.GetLoaderConfig())

	storetmp.Load() //加载template和workflow

	// 创建工作池
	pool, err := ants.NewPool(poolSize, ants.WithPreAlloc(true))
	if err != nil {
		return nil, fmt.Errorf("创建工作池失败: %v", err)
	}

	// 尝试初始化Redis缓存
	var templateCache *cache.TemplateCache
	var useRedis bool

	if config.RedisAddr != "" {
		if tc := cache.NewTemplateCache(config.RedisAddr); err == nil {
			templateCache = tc
			useRedis = true
			gologger.Info().Msgf("Redis缓存已启用: %s", config.RedisAddr)
		} else {
			gologger.Warning().Msgf("Redis连接失败，将使用默认加载方式: %v", err)
		}
	}

	t := &Task{
		MaxPoolsize:   poolSize,
		Pool:          pool,
		engine:        engine,
		results:       make(chan *output.ResultEvent, 100),
		Wg:            &sync.WaitGroup{},
		templateCache: templateCache,
		useRedis:      useRedis,
	}

	return t, nil
}

// 修改后的扫描方法
func (t *Task) ScanPassiveResult(result *header.PassiveResult) error {
	start := time.Now() // 记录任务开始时间
	target := []string{result.Host}
	t.engine.LoadTargets(target, false)

	workflows := t.engine.Store().LoadWorkflows(config.GetLoaderConfig().WorkflowURLs) //这里workflowsList
	if len(workflows) == 0 {
		return fmt.Errorf("未找到任何有效的workflows，请检查路径")
	}

	workflowHit := false //命中指纹
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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
			})
		}
	})
	if err != nil {
		return fmt.Errorf("工作流执行出错: %v", err)
	}

	if !workflowHit {
		gologger.Info().Msg("[未命中任何 Workflow，通过 Redis 动态加载模板并重新扫描]")
		if err := t.scanWithTemplatesLoader(result); err != nil {
			gologger.Warning().Msgf("Redis模板扫描失败: %v", err)
		}
	}
	gologger.Info().Msgf("[扫描完成] Host: %s, 耗时: %s", result.Host, time.Since(start))
	return nil
}

func (t *Task) scanWithTemplatesLoader(result *header.PassiveResult) error {
	// 从Redis加载相关技术栈的模板
	techTemplates := t.RedisLoader(result)
	if len(techTemplates) == 0 {
		gologger.Info().Msgf("未从Redis中找到相关技术栈的模板: %v", result.Host)
		return nil
	}

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
		return fmt.Errorf("模板扫描执行出错: %v", err)
	}

	return nil
}
