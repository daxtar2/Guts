package config

import (
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

// TemplateFilters 定义模板过滤器配置
var TemplateFilters = nuclei.TemplateFilters{
	Severity:          "high",
	ExcludeSeverities: "low,info",
	ProtocolTypes:     "http",
	Authors:           []string{"admin", "security_team"},
	Tags:              []string{"xss", "rce"},
	ExcludeTags:       []string{"slow"},
	IncludeTags:       []string{"critical"},
	IDs:               []string{"CVE-2024-5678"},
	ExcludeIDs:        []string{"CVE-2023-1234"},
	TemplateCondition: []string{"status_code == 200"},
}

// LoaderConfig 定义模板加载器配置
var LoaderConfig = &loader.Config{
	// 基础模板和工作流配置
	Templates:        []string{"nuclei-templates", "custom-templates"},
	TemplateURLs:     []string{"https://github.com/projectdiscovery/nuclei-templates"},
	Workflows:        []string{"workflows/fingerprint-scan.yaml"},
	WorkflowURLs:     []string{"https://github.com/projectdiscovery/nuclei-templates/tree/main/workflows"},
	ExcludeTemplates: []string{},
	IncludeTemplates: []string{},

	// 过滤器配置
	Tags:              []string{"xss", "rce"},
	ExcludeTags:       []string{"slow"},
	Protocols:         types.ProtocolTypes{types.HTTPProtocol},
	ExcludeProtocols:  types.ProtocolTypes{},
	Authors:           []string{"admin", "security_team"},
	Severities:        severity.Severities{severity.High},
	ExcludeSeverities: severity.Severities{severity.Low, severity.Info},
	IncludeTags:       []string{"critical"},
	IncludeIds:        []string{"CVE-2024-5678"},
	ExcludeIds:        []string{"CVE-2023-1234"},
	IncludeConditions: []string{"status_code == 200"},
}

// 加载模板和工作流的配置
// type LoaderConfig struct {
// 	Templates []string
// 	TemplateURLs []string
// 	Workflows []string
// 	WorkflowURLs []string
// 	ExcludeTemplates []string
// 	IncludeTemplates []string
// 	RemoteTemplateDomainList []string
// }

// GetTemplateFilters 返回模板过滤器配置
func GetTemplateFilters() nuclei.TemplateFilters {
	return TemplateFilters
}

// GetLoaderConfig 返回模板加载器配置
func GetLoaderConfig() *loader.Config {
	return LoaderConfig
}
