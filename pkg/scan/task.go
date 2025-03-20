package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	scanning      sync.Map      // 用于跟踪正在扫描的目标
	stopChan      chan struct{} // 用于停止扫描
}

// 初始化扫描任务
func NewTask(maxPoolsize int) (*Task, error) {
	// 设置环境变量禁用nuclei默认模板下载
	os.Setenv("DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD", "true")

	// 获取程序运行目录
	execPath, err := os.Getwd()
	if err != nil {
		logger.Error("获取程序运行路径失败", zap.Error(err))
		return nil, err
	}
	logger.Info("当前运行文件：%s", zap.String("path", execPath))
	// 获取可执行文件所在目录
	// executablePath, err := os.Executable()
	// if err != nil {
	// 	logger.Error("获取可执行文件路径失败", zap.Error(err))
	// 	return nil, err
	// }
	// executableDir := filepath.Dir(executablePath)

	// 根据操作系统选择合适的基础路径
	var baseTemplatesPath string
	if runtime.GOOS == "windows" {
		// Windows下使用可执行文件所在目录
		baseTemplatesPath = filepath.Join(execPath, "templates")
	} else {
		// macOS/Linux下优先使用当前工作目录
		baseTemplatesPath = filepath.Join(execPath, "templates")

		// 如果当前工作目录下没有templates目录，则尝试使用可执行文件所在目录
		// if _, err := os.Stat(baseTemplatesPath); os.IsNotExist(err) {
		// 	baseTemplatesPath = filepath.Join(executableDir, "templates")
		// }
	}

	workflowsPath := filepath.Join(baseTemplatesPath, "workflows")

	logger.Info("使用模板路径",
		zap.String("templates", baseTemplatesPath),
		zap.String("workflows", workflowsPath),
		zap.String("os", runtime.GOOS),
		zap.Bool("disable_default_templates", os.Getenv("DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD") == "true"))

	// 验证模板目录是否存在
	if _, err := os.Stat(baseTemplatesPath); os.IsNotExist(err) {
		logger.Error("模板目录不存在",
			zap.String("path", baseTemplatesPath),
			zap.Error(err))
		return nil, fmt.Errorf("模板目录不存在: %s", baseTemplatesPath)
	}

	// 输出模板子目录
	httpDir := filepath.Join(baseTemplatesPath, "http")
	if _, err := os.Stat(httpDir); err == nil {
		logger.Info("HTTP模板目录存在", zap.String("path", httpDir))
	} else {
		logger.Warn("HTTP模板目录不存在", zap.String("path", httpDir), zap.Error(err))
	}

	// 创建 Redis 客户端
	redisManager := cache.NewRedisManager(config.GConfig.Redis.Address)

	// 创建配置包装器
	configWrapper := cache.NewConfigWrapper(redisManager)

	// 设置模板搜索路径
	// templateConfig := config.GetLoaderConfig()
	// templateConfig.Templates = []string{baseTemplatesPath}
	// templateConfig.Workflows = []string{workflowsPath}

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

		// 自动遍历baseTemplatesPath下的子目录
		func() nuclei.NucleiSDKOptions {
			// 准备模板目录列表
			var templateDirs []string

			// 读取baseTemplatesPath下的所有条目
			entries, err := os.ReadDir(baseTemplatesPath)
			if err != nil {
				logger.Error("读取模板目录失败", zap.String("path", baseTemplatesPath), zap.Error(err))
				// 如果读取失败，至少包含workflows目录
				return nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
					Templates: []string{baseTemplatesPath},
					Workflows: []string{workflowsPath},
				})
			}

			// 遍历所有条目，添加目录
			for _, entry := range entries {
				if entry.IsDir() {
					subDirPath := filepath.Join(baseTemplatesPath, entry.Name())
					// 排除workflows目录，因为它会单独添加
					if subDirPath != workflowsPath {
						templateDirs = append(templateDirs, subDirPath)
						logger.Info("添加模板目录", zap.String("dir", subDirPath))
					}
				}
			}

			// 如果没有找到任何子目录，至少包含baseTemplatesPath本身
			if len(templateDirs) == 0 {
				templateDirs = append(templateDirs, baseTemplatesPath)
				logger.Warn("未找到任何模板子目录，使用基础目录", zap.String("base_dir", baseTemplatesPath))
			}

			// 返回包含所有找到的目录的选项
			return nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
				Templates: templateDirs,
				Workflows: []string{workflowsPath},
			})
		}(),

		// 从配置中读取扫描速率设置
		func() nuclei.NucleiSDKOptions {
			// 获取速率配置
			rateConfig := config.GConfig.ScanRate

			// 默认速率
			globalRate := 30
			if rateConfig.GlobalRate > 0 {
				globalRate = rateConfig.GlobalRate
			}

			// 默认单位是秒
			rateUnit := time.Second
			if rateConfig.GlobalRateUnit == "minute" {
				rateUnit = time.Minute
			} else if rateConfig.GlobalRateUnit == "hour" {
				rateUnit = time.Hour
			}

			logger.Info("使用配置的扫描速率",
				zap.Int("globalRate", globalRate),
				zap.String("rateUnit", rateConfig.GlobalRateUnit),
			)

			return nuclei.WithGlobalRateLimit(globalRate, rateUnit)
		}(),

		// 从配置中读取并发设置
		func() nuclei.NucleiSDKOptions {
			// 获取并发配置
			concurrencyConfig := config.GConfig.ScanRate

			// 使用配置的值，如果配置为0则使用默认值
			templateConcurrency := 100
			if concurrencyConfig.TemplateConcurrency > 0 {
				templateConcurrency = concurrencyConfig.TemplateConcurrency
			}

			hostConcurrency := 100
			if concurrencyConfig.HostConcurrency > 0 {
				hostConcurrency = concurrencyConfig.HostConcurrency
			}

			headlessHostConcurrency := 50
			if concurrencyConfig.HeadlessHostConcurrency > 0 {
				headlessHostConcurrency = concurrencyConfig.HeadlessHostConcurrency
			}

			headlessTemplateConcurrency := 50
			if concurrencyConfig.HeadlessTemplateConcurrency > 0 {
				headlessTemplateConcurrency = concurrencyConfig.HeadlessTemplateConcurrency
			}

			javascriptTemplateConcurrency := 50
			if concurrencyConfig.JavascriptTemplateConcurrency > 0 {
				javascriptTemplateConcurrency = concurrencyConfig.JavascriptTemplateConcurrency
			}

			templatePayloadConcurrency := 25
			if concurrencyConfig.TemplatePayloadConcurrency > 0 {
				templatePayloadConcurrency = concurrencyConfig.TemplatePayloadConcurrency
			}

			probeConcurrency := 50
			if concurrencyConfig.ProbeConcurrency > 0 {
				probeConcurrency = concurrencyConfig.ProbeConcurrency
			}

			logger.Info("使用配置的并发设置",
				zap.Int("templateConcurrency", templateConcurrency),
				zap.Int("hostConcurrency", hostConcurrency),
			)

			return nuclei.WithConcurrency(nuclei.Concurrency{
				TemplateConcurrency:           templateConcurrency,
				HostConcurrency:               hostConcurrency,
				HeadlessHostConcurrency:       headlessHostConcurrency,
				HeadlessTemplateConcurrency:   headlessTemplateConcurrency,
				JavascriptTemplateConcurrency: javascriptTemplateConcurrency,
				TemplatePayloadConcurrency:    templatePayloadConcurrency,
				ProbeConcurrency:              probeConcurrency,
			})
		}(),
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
		stopChan:      make(chan struct{}),
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
	// 检查目标是否已经在扫描中
	if _, exists := t.scanning.LoadOrStore(passiveResult.Url, true); exists {
		logger.Warn("目标已在扫描中，跳过", zap.String("url", passiveResult.Url))
		return nil
	}
	defer t.scanning.Delete(passiveResult.Url)

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
	defer executionMutex.Unlock() // 确保解锁

	// 使用带缓冲的通道来防止结果处理阻塞
	resultChan := make(chan *output.ResultEvent, 1000)
	defer close(resultChan)

	// 启动结果处理协程
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case event, ok := <-resultChan:
				if !ok {
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
					sevStr := event.Info.SeverityHolder.Severity.String()
					if sevStr != "" && sevStr != "unknown" && sevStr != "Unknown" {
						severity = sevStr
					}

					// 创建扫描结果
					scanResult := &models.ScanResult{
						ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
						Target:      parseUrl,
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

					// 使用带超时的发送操作
					select {
					case t.resultChan <- scanResult:
						logger.Info("扫描结果已发送到结果通道", zap.String("url", parseUrl))
					case <-time.After(5 * time.Second):
						logger.Warn("发送扫描结果超时", zap.String("url", parseUrl))
					case <-t.stopChan:
						logger.Info("扫描被停止", zap.String("url", parseUrl))
						return
					}
				}()
			case <-t.stopChan:
				logger.Info("结果处理被停止", zap.String("url", passiveResult.Url))
				return
			}
		}
	}()

	// 执行扫描，使用自定义的结果处理函数
	err := t.engine.ExecuteCallbackWithCtx(Ctx, func(event *output.ResultEvent) {
		select {
		case resultChan <- event:
			// 结果已成功发送到处理通道
		case <-t.stopChan:
			logger.Info("扫描被停止", zap.String("url", event.URL))
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
		logger.Info("扫描完成", zap.String("url", passiveResult.Url))
	case <-time.After(5 * time.Minute):
		logger.Warn("扫描超时", zap.String("url", passiveResult.Url))
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
