package config

import (
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
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

var catalog = disk.NewCatalog(DefaultConfig.NewTemplatesDirectory)

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

var LoaderConfig = &loader.Config{
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
	Catalog:           catalog,
	ExcludeProtocols:  DefaultConfig.ExcludeProtocols,
}

// LoaderConfig 定义模板加载器配置
// var LoaderConfig1 = &loader.Config{
// 	Templates:    []string{"nuclei-templates"},
// 	TemplateURLs: []string{},
// 	Workflows:    []string{},
// 	WorkflowURLs: []string{},

// 	// 过滤配置
// 	Tags:              []string{"xss", "rce"},
// 	ExcludeTags:       []string{"slow"},
// 	IncludeTags:       []string{"critical"},
// 	Authors:           []string{"admin", "security_team"},
// 	Severities:        severity.Severities{severity.High, severity.Critical},
// 	ExcludeSeverities: severity.Severities{severity.Low, severity.Info},
// 	IncludeIds:        []string{},
// 	ExcludeIds:        []string{},
// 	Protocols:         templateTypes.ProtocolTypes{templateTypes.HTTPProtocol},
// 	ExcludeProtocols:  templateTypes.ProtocolTypes{},
// }

// GetLoaderConfig 返回模板加载器配置
func GetLoaderConfig() *loader.Config {
	return LoaderConfig
}
