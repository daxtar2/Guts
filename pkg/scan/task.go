package scan

import (
	"fmt"
	"sync"
	"time"

	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/header"
	"github.com/panjf2000/ants/v2"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"golang.org/x/net/context"
)

type Task struct {
	MaxPoolsize int // 最大并发数
	Pool        *ants.Pool
	Wg          *sync.WaitGroup
	engine      *types.Engine
	results     chan *output.ResultEvent
}

// 初始化扫描任务
func NewTask(poolSize int) (*Task, error) {
	options := &types.Options{
		Templates:       []string{"templates"},
		TemplateThreads: poolSize,
		Silent:          true,
		NoInteractsh:    true,
		// 针对被动扫描的优化配置
		RateLimit: 100,
		BulkSize:  50,
		Timeout:   5,
	}

	engine, err := types.NewEngine(options)
	if err != nil {
		return nil, fmt.Errorf("创建nuclei引擎失败: %v", err)
	}

	return &Task{
		MaxPoolsize: poolSize,
		engine:      engine,
		results:     make(chan *output.ResultEvent, 100),
	}, nil
}

func (t Task) ScanBegin() {
	// 设置合理的超时时间，基于任务量动态计算
	timeout := time.Duration(t.MaxPoolsize*30) * time.Second // 每个任务预留30秒
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel() // 防止内存泄漏

	// 配置 Nuclei 引擎选项
	options := []nuclei.Option{
		nuclei.WithTemplateFilters(config.GetTemplateFilters()),
		nuclei.WithTemplatesDirectory("templates"), // 指定模板目录
		nuclei.WithRate(t.MaxPoolsize),             // 设置扫描速率
		nuclei.WithHeadless(false),                 // 是否启用Headless模式
		nuclei.WithVerbose(false),                  // 详细日志输出
	}

	ne, err := nuclei.NewNucleiEngineCtx(ctx, options...)
	if err != nil {
		fmt.Printf("初始化Nuclei引擎失败: %v\n", err)
		return
	}
	defer ne.Close()

	// 使用WaitGroup跟踪扫描任务
	var wg sync.WaitGroup
	wg.Add(1)

	// 创建结果通道
	resultChan := make(chan *output.ResultEvent, 100)
	errorChan := make(chan error, 100)

	// 启动结果处理协程
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case result := <-resultChan:
				if result == nil {
					return
				}
				// 根据漏洞严重程度进行不同处理
				switch result.Info.SeverityHolder.Severity {
				case "critical", "high":
					fmt.Printf("【严重漏洞】%s: %s\n", result.Host, result.Info.Name)
				case "medium":
					fmt.Printf("【中危漏洞】%s: %s\n", result.Host, result.Info.Name)
				default:
					fmt.Printf("【低危漏洞】%s: %s\n", result.Host, result.Info.Name)
				}

				// TODO: 这里可以添加漏洞结果持久化逻辑
			case err := <-errorChan:
				if err != nil {
					fmt.Printf("扫描过程出错: %v\n", err)
				}
			}
		}
	}()

	// 执行扫描
	err = ne.ExecuteCallbackWithCtx(ctx, func(event *output.ResultEvent) {
		select {
		case resultChan <- event:
		default:
			// 通道已满时的处理
			fmt.Println("警告：结果通道已满，部分结果可能丢失")
		}
	})

	if err != nil {
		errorChan <- fmt.Errorf("执行扫描失败: %v", err)
	}

	// 关闭通道
	close(resultChan)
	close(errorChan)

	// 等待所有处理完成
	wg.Wait()
}

// 处理被动扫描结果
func (t *Task) ScanPassiveResult(result *header.PassiveResult) error {
	// 构建扫描目标
	target := &contextargs.MetaInput{
		Input: result.Url,
		Raw:   []byte(result.RawRequest),
		Meta:  make(map[string]interface{}),
	}

	// 添加原始请求响应信息
	target.Meta["original_request"] = result.RawRequest
	target.Meta["original_response"] = result.RawResponse
	target.Meta["headers"] = result.Headers

	// 执行扫描
	err := t.engine.ExecuteWithResults(target, func(result *output.ResultEvent) {
		// 实时处理扫描结果
		if result != nil {
			switch result.Info.SeverityHolder.Severity {
			case types.High, types.Critical:
				fmt.Printf("【严重漏洞】%s: %s\n", result.Host, result.Info.Name)
			case types.Medium:
				fmt.Printf("【中危漏洞】%s: %s\n", result.Host, result.Info.Name)
			default:
				fmt.Printf("【低危漏洞】%s: %s\n", result.Host, result.Info.Name)
			}
		}
	})

	return err
}
