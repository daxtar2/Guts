package config

import nuclei "github.com/projectdiscovery/nuclei/v3/lib"

// 扫描相关的配置文件

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

var LoaderConfig = LoaderConfig{
	Templates:    []string{"nuclei-templates", "custom-templates"},
	TemplateURLs: []string{"https://github.com/projectdiscovery/nuclei-templates"},
	Workflows:    []string{"workflows/fingerprint-scan.yaml"},
	WorkflowURLs: []string{"https://github.com/projectdiscovery/nuclei-workflows"},
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

func GetTemplateFilters() nuclei.TemplateFilters {
	return TemplateFilters
}

func GetLoaderConfig() LoaderConfig {
	return LoaderConfig
}
