package config

import (
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// TemplateFilters 定义模板过滤器配置
var TemplateFilters = nuclei.TemplateFilters{
	Severity:          "critical,high,medium",
	ExcludeSeverities: "low,info",
	ProtocolTypes:     "http",
	Authors:           []string{},
	Tags: []string{
		"cve",
	},
	ExcludeTags: []string{"dos", "fuzz"},
	IncludeTags: []string{},
	IDs:         []string{},
	ExcludeIDs:  []string{},
}

// 初始化配置，后续会更新为绝对路径
var DefaultConfig = &types.Options{
	Templates:                []string{"./templates"},
	NewTemplatesDirectory:    "./templates",
	Workflows:                []string{},
	RemoteTemplateDomainList: []string{},
	TemplateURLs:             []string{},
	WorkflowURLs:             []string{},
	ExcludedTemplates:        []string{},
	Tags:                     []string{"cve", "rce", "sqli", "xss", "ssrf", "lfi", "rfi", "upload"},
	ExcludeTags:              []string{"dos", "fuzz"},
	IncludeTemplates:         []string{},
	Authors:                  []string{},
	Severities:               severity.Severities{severity.Critical, severity.High, severity.Medium},
	ExcludeSeverities:        severity.Severities{severity.Low, severity.Info},
	IncludeTags:              []string{},
	IncludeIds:               []string{},
	ExcludeIds:               []string{},
	Protocols:                templateTypes.ProtocolTypes{templateTypes.HTTPProtocol},
	ExcludeProtocols:         templateTypes.ProtocolTypes{},
	IncludeConditions:        []string{},
}

// 初始化为nil，后续会在更新模板路径后再创建
// var catalog *disk.DiskCatalog
var LoaderConfig *loader.Config

var ExecutorOptions = protocols.ExecutorOptions{
	Options: &types.Options{
		//Protocols:       []string{"http"},
		TemplateThreads: 10,
		Timeout:         5,
		Retries:         1,
		RateLimit:       150,
		BulkSize:        25,
		TemplateDisplay: false,
		//NoColor:         false,
		//JSON:            false,
		JSONRequests: false,
		NoMeta:       false,
		//NoTimestamp:     false,
		Silent:         false,
		VerboseVerbose: false,
		Debug:          false,
		DebugRequests:  false,
		DebugResponse:  false,
		StoreResponse:  false,
		// 其他选项...
	},
}

// 初始化模板加载配置
func InitTemplateLoader() {
	// 获取模板目录的绝对路径
	templatesPath := GetTemplateBasePath()

	// 更新配置中的模板路径
	DefaultConfig.Templates = []string{templatesPath}
	DefaultConfig.NewTemplatesDirectory = templatesPath

	// 使用更新后的路径创建目录扫描器
	//catalog = disk.NewCatalog(DefaultConfig.NewTemplatesDirectory)

	// 创建加载器配置
	LoaderConfig = &loader.Config{
		Templates:    DefaultConfig.Templates,
		WorkflowURLs: DefaultConfig.WorkflowURLs,
		Workflows:    DefaultConfig.Workflows,

		// 添加必要的过滤器配置
		Tags:              DefaultConfig.Tags,
		ExcludeTags:       DefaultConfig.ExcludeTags,
		Authors:           DefaultConfig.Authors,
		Severities:        DefaultConfig.Severities,
		ExcludeSeverities: DefaultConfig.ExcludeSeverities,
		IncludeIds:        DefaultConfig.IncludeIds,
		ExcludeIds:        DefaultConfig.ExcludeIds,
		Protocols:         DefaultConfig.Protocols,
		//Catalog:           catalog,
		ExcludeProtocols: DefaultConfig.ExcludeProtocols,
	}
}

// GetLoaderConfig 返回模板加载器配置
func GetLoaderConfig() *loader.Config {
	// 确保LoaderConfig已初始化
	if LoaderConfig == nil {
		InitTemplateLoader()
	}
	return LoaderConfig
}
