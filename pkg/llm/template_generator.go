package llm

import (
	"context"
	"fmt"
	"strings"
)

// NucleiTemplate Nuclei YAML 模板结构（简化版）
type NucleiTemplate struct {
	ID          string                 `yaml:"id"`
	Info        TemplateInfo           `yaml:"info"`
	HTTPRequests []HTTPRequest         `yaml:"http,omitempty"`
	RawTemplate string                 `yaml:"-"` // 完整 YAML 内容
}

// TemplateInfo 模板元信息
type TemplateInfo struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags,omitempty"`
}

// HTTPRequest HTTP 请求块
type HTTPRequest struct {
	Method    string   `yaml:"method"`
	Path      []string `yaml:"path"`
	Headers   map[string]string `yaml:"headers,omitempty"`
	Body      string   `yaml:"body,omitempty"`
	Matchers  []Matcher `yaml:"matchers,omitempty"`
	Extractors []Extractor `yaml:"extractors,omitempty"`
}

// Matcher 匹配器
type Matcher struct {
	Type  string   `yaml:"type"` // word/regex/status/dsl
	Words []string `yaml:"words,omitempty"`
	Regex []string `yaml:"regex,omitempty"`
	DSL   []string `yaml:"dsl,omitempty"`
	Part  string   `yaml:"part,omitempty"` // body/header/response
}

// Extractor 提取器（用于动态变量提纯）
type Extractor struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"` // regex/kval/xpath/json
	Regex    []string `yaml:"regex,omitempty"`
	Part     string   `yaml:"part,omitempty"`
	Internal bool     `yaml:"internal,omitempty"` // true=提取结果用于链式传递
}

// TemplateGeneratorConfig 模板生成器配置
type TemplateGeneratorConfig struct {
	SandboxEnabled bool   // 是否启用沙盒预检（nuclei -validate）
	MaxIterations  int    // LLM 迭代修正最大次数
}

// TemplateGenerator 动态 Nuclei 模板生成器
type TemplateGenerator struct {
	llm    *OpenAIClient
	config TemplateGeneratorConfig
}

// NewTemplateGenerator 创建模板生成器
func NewTemplateGenerator(llm *OpenAIClient, cfg TemplateGeneratorConfig) *TemplateGenerator {
	if cfg.MaxIterations <= 0 {
		cfg.MaxIterations = 3
	}
	return &TemplateGenerator{
		llm:    llm,
		config: cfg,
	}
}

// GenerateTemplate 根据目标描述使用 LLM 生成 Nuclei YAML 模板
//
// context 参数包含:
//   - target_info: 目标技术栈、API 文档片段等
//   - vuln_type: 漏洞类型（sqli/xss/ssrf 等）
//   - swagger_snippet: OpenAPI/Swagger 文档片段（可选）
func (g *TemplateGenerator) GenerateTemplate(ctx context.Context, templateContext map[string]string) (*NucleiTemplate, error) {
	systemPrompt := `You are a security researcher specializing in writing Nuclei vulnerability detection templates.
Generate valid Nuclei YAML templates following the official Nuclei template format.
Templates must include: id, info (name, author, severity, description, tags), and http section with matchers.
For dynamic data extraction, use extractors with internal: true.
Return ONLY the raw YAML content, no explanation.`

	userPrompt := buildTemplatePrompt(templateContext)

	var lastErr error
	for i := 0; i < g.config.MaxIterations; i++ {
		yamlContent, err := g.llm.ChatCompletion(ctx, systemPrompt, userPrompt)
		if err != nil {
			return nil, fmt.Errorf("LLM 生成模板失败: %w", err)
		}

		yamlContent = strings.TrimSpace(yamlContent)
		// 去除可能的 markdown 代码块标记
		yamlContent = strings.TrimPrefix(yamlContent, "```yaml")
		yamlContent = strings.TrimPrefix(yamlContent, "```")
		yamlContent = strings.TrimSuffix(yamlContent, "```")
		yamlContent = strings.TrimSpace(yamlContent)

		tmpl := &NucleiTemplate{RawTemplate: yamlContent}

		// 沙盒预检
		if g.config.SandboxEnabled {
			validationErr := validateTemplate(yamlContent)
			if validationErr != nil {
				lastErr = validationErr
				// 将错误反馈给 LLM，进行迭代修正
				userPrompt = buildFixPrompt(userPrompt, yamlContent, validationErr.Error())
				continue
			}
		}

		return tmpl, nil
	}

	return nil, fmt.Errorf("模板生成失败，已达最大迭代次数 (%d): %w", g.config.MaxIterations, lastErr)
}

// buildTemplatePrompt 构建模板生成提示词
func buildTemplatePrompt(ctx map[string]string) string {
	var sb strings.Builder
	sb.WriteString("Generate a Nuclei template for the following target:\n\n")
	if info, ok := ctx["target_info"]; ok {
		sb.WriteString("Target Info:\n" + info + "\n\n")
	}
	if vulnType, ok := ctx["vuln_type"]; ok {
		sb.WriteString("Vulnerability Type: " + vulnType + "\n\n")
	}
	if swagger, ok := ctx["swagger_snippet"]; ok {
		sb.WriteString("API Endpoint Info:\n" + swagger + "\n\n")
	}
	return sb.String()
}

// buildFixPrompt 构建错误修正提示词
func buildFixPrompt(originalPrompt, yamlContent, errMsg string) string {
	return fmt.Sprintf(`%s

The previously generated template had validation errors. Please fix it:

Template:
%s

Error:
%s

Generate a corrected version.`, originalPrompt, yamlContent, errMsg)
}

// validateTemplate 使用 nuclei -validate 进行模板沙盒预检
// 这里是占位实现，实际调用 nuclei CLI 的 -validate 标志
func validateTemplate(yamlContent string) error {
	if len(strings.TrimSpace(yamlContent)) == 0 {
		return fmt.Errorf("模板内容为空")
	}
	if !strings.Contains(yamlContent, "id:") {
		return fmt.Errorf("模板缺少 id 字段")
	}
	if !strings.Contains(yamlContent, "info:") {
		return fmt.Errorf("模板缺少 info 块")
	}
	if !strings.Contains(yamlContent, "matchers:") {
		return fmt.Errorf("模板缺少 matchers 块")
	}
	return nil
}
