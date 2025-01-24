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

func GetTemplateFilters() nuclei.TemplateFilters {
	return TemplateFilters
}
