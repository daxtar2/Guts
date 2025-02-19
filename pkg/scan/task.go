package scan

import (
	"fmt"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"sync"
	"time"

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

	// 预加载常用模板到Redis
	if t.useRedis {
		go t.preloadTemplates()
	}

	return t, nil
}

// - **异步预加载**：通过启用 goroutines，逐个异步写入模板，并且记录 Redis 的写入错误数。
// - **TTL 动态配置**：允许用户传入动态 TTL 参数，便于根据任务频率调整缓存时长。
func (t *Task) preloadTemplates() {
	templatesTmp := t.engine.GetTemplates()
	errorCount := 0
	var wg sync.WaitGroup

	for _, tmpl := range templatesTmp {
		wg.Add(1)
		go func(tmpl *templates.Template) {
			defer wg.Done()
			key := "template:" + tmpl.ID
			if err := t.templateCache.SetTemplate(key, tmpl); err != nil {
				errorCount++
				gologger.Warning().Msgf("[Redis Preload Error] Key: %s, Error: %v", key, err)
			}
		}(tmpl)
	}

	wg.Wait()
	if errorCount > 0 {
		gologger.Warning().Msgf("Redis模板加载完成，但 %d 个模板加载失败", errorCount)
	}
}

// 新增方法：执行技术识别工作流
// 增加错误日志和配置化超时时间
func (t *Task) ExecuteFingerprint(target []string, timeout time.Duration) (map[string][]string, error) {
	techStack := make(map[string][]string)

	ctx, cancel := context.WithTimeout(context.Background(), timeout) // timeout 参数化
	defer cancel()

	err := t.engine.ExecuteCallbackWithCtx(ctx, func(result *output.ResultEvent) {
		if result != nil && result.Info.Name != "" {
			gologger.Debug().Msgf("[Fingerprint] Host: %s, Tech: %s", result.Host, result.Info.Name)
			techStack[result.Host] = append(techStack[result.Host], result.Info.Name)
		}
	})

	if err != nil {
		gologger.Error().Msgf("[Fingerprint Error] target: %v, error: %v", target, err)
	}

	return techStack, err
}

// 修改后的扫描方法
func (t *Task) ScanPassiveResult(result *header.PassiveResult) error {
	start := time.Now() // 记录任务开始时间
	techTemplates, err := t.templateCache.MGetTemplates(getTechTemplateKeys(result.TechStack))
	if err != nil {
		gologger.Warning().Msgf("Redis加载模板失败，切换到默认加载方式: %v", err)
		return t.scanWithDefaultLoader(result)
	}

	store := t.engine.Store()
	selectedTemplates := []*templates.Template{}
	for _, tmpl := range store.Templates() {
		for _, techTemplate := range techTemplates {
			if tmpl.Path == techTemplate.Path {
				selectedTemplates = append(selectedTemplates, tmpl)
			}
		}
	}
	if len(selectedTemplates) == 0 {
		return fmt.Errorf("未找到匹配的模板")
	}
	// 1. 从Redis获取技术栈对应的模板
	//gologger.Info().Msgf("[Redis] 模板加载成功, Count: %d", len(techTemplates))
	target := []string{result.Host}
	t.engine.LoadTargets(target, false)

	// 1. 首先执行指纹识别
	techStack, err := t.ExecuteFingerprint(target, 30*time.Second)
	if err != nil {
		return fmt.Errorf("fingerprint scan error: %v", err)
	}

	// 基于识别技术选择模板
	selectedTemplates := getTemplatesForTech(techStack[result.Host])
	if len(selectedTemplates) > 0 {
		t.engine.SetTemplateConfig(selectedTemplates)
	}

	// 2. 基于识别结果选择相应的模板
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 重新加载目标
	t.engine.LoadTargets(target, false)

	// 执行漏洞扫描
	err = t.engine.ExecuteCallbackWithCtx(ctx, func(result *output.ResultEvent) {
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
	gologger.Info().Msgf("[扫描完成] Host: %s, 耗时: %s", result.Host, time.Since(start))
	return err
}

// getTechTemplateKeys 根据技术栈生成 Redis 模板键名
func getTechTemplateKeys(techStack map[string][]string) []string {
	keys := make([]string, 0) // 初始化空的键列表

	// 遍历每个主机以及对应的技术栈
	for _, techs := range techStack {
		for _, tech := range techs {
			// 将主机的技术栈元素转换为 Redis 键，例如 "template:wordpress"
			key := fmt.Sprintf("template:%s", tech)
			keys = append(keys, key)
		}
	}
	return keys // 返回拼接好的 Redis 键名列表
}

func (t *Task) scanWithDefaultLoader(result *header.Passi)

// 辅助函数：根据技术选择模板
func getTemplatesForTech(techs []string) []string {
	templates := []string{}
	for _, tech := range techs {
		switch tech {
		case "wordpress":
			templates = append(templates, "templates/vulnerabilities/wordpress/")
		case "apache":
			templates = append(templates, "templates/vulnerabilities/apache/")
			// 添加更多技术对应的模板
		}
	}
	return templates
}

// 添加关闭方法
func (t *Task) Close() {
	t.Pool.Release() // 释放工作池资源
}
