package scan

import (
	"fmt"
	"sync"
	"time"

	"github.com/daxtar2/Guts/pkg/header"
	"github.com/panjf2000/ants/v2"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"golang.org/x/net/context"
)

type Task struct {
	MaxPoolsize int // 最大并发数
	Pool        *ants.Pool
	Wg          *sync.WaitGroup
	engine      *nuclei.NucleiEngine
	results     chan *output.ResultEvent
}

// 初始化扫描任务
func NewTask(poolSize int) (*Task, error) {
	options := []nuclei.NucleiSDKOptions{
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{}),
		nuclei.EnableStatsWithOpts(nuclei.StatsOptions{MetricServerPort: 8080}),
		// 修正模板路径设置
		nuclei.WithTemplatesPath("nuclei-templates", "custom-templates"), // 可以指定多个模板目录
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

	// 创建工作池
	pool, err := ants.NewPool(poolSize, ants.WithPreAlloc(true))
	if err != nil {
		return nil, fmt.Errorf("创建工作池失败: %v", err)
	}

	t := &Task{
		MaxPoolsize: poolSize,
		Pool:        pool,
		engine:      engine,
		results:     make(chan *output.ResultEvent, 100),
		Wg:          &sync.WaitGroup{},
	}

	return t, nil
}

// 新增方法：执行技术识别工作流
func (t *Task) ExecuteFingerprint(target []string) (map[string][]string, error) {
	// 存储识别结果
	techStack := make(map[string][]string)

	// 加载指纹识别工作流
	workflow := []string{"workflows/fingerprint-scan.yaml"}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.engine.LoadTargets(target, false)
	t.engine.LoadWorkflows(workflow)

	err := t.engine.ExecuteCallbackWithCtx(ctx, func(result *output.ResultEvent) {
		if result != nil {
			techStack[result.Host] = append(techStack[result.Host], result.Info.Name)
		}
	})

	return techStack, err
}

// 修改后的扫描方法
func (t *Task) ScanPassiveResult(result *header.PassiveResult) error {
	target := []string{result.Host}

	// 1. 首先执行指纹识别
	techStack, err := t.ExecuteFingerprint(target)
	if err != nil {
		return fmt.Errorf("fingerprint scan error: %v", err)
	}

	// 2. 基于识别结果选择相应的模板
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 重新加载目标
	t.engine.LoadTargets(target, false)

	// 设置与识别到的技术相关的模板
	if techs, exists := techStack[result.Host]; exists {
		// 这里可以根据识别到的技术选择相应的模板
		t.engine.GetExecuterOptions().Options.Templates = getTemplatesForTech(techs)
	}

	// 执行漏洞扫描
	err = t.engine.ExecuteCallbackWithCtx(ctx, func(result *output.ResultEvent) {
		if result != nil {
			t.Wg.Add(1)
			_ = t.Pool.Submit(func() {
				defer t.Wg.Done()
				// output [+] example.com: CVE-2023-1234
				// output [+] example.com: CVE-2023-1234
				fmt.Printf("[+] %s: %s\n", result.Host, result.Info.Name)
			})
		}
	})

	return err
}

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
