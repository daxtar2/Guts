package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/models"
	"go.uber.org/zap"
)

// NucleiMCPConfig Nuclei MCP 服务配置
type NucleiMCPConfig struct {
	NucleiBinaryPath string        // nuclei 二进制路径
	TemplatesPath    string        // 模板目录
	OutputDir        string        // 输出目录
	Timeout          time.Duration // 单次扫描超时
	RateLimit        int           // 每秒请求数
	BulkSize         int           // 批量请求大小
	MaxHostErrors    int           // 最大主机错误容忍数
}

// NucleiMCPServer Nuclei MCP 服务端（通过 MCP 协议暴露 Nuclei 扫描能力）
type NucleiMCPServer struct {
	config   NucleiMCPConfig
	registry *ToolRegistry
}

// NewNucleiMCPServer 创建 Nuclei MCP 服务端并注册工具
func NewNucleiMCPServer(cfg NucleiMCPConfig) *NucleiMCPServer {
	s := &NucleiMCPServer{
		config:   cfg,
		registry: NewToolRegistry(),
	}
	s.registerTools()
	return s
}

// registerTools 注册所有 Nuclei MCP 工具
func (s *NucleiMCPServer) registerTools() {
	tools := []*ToolDefinition{
		{
			Name:        "list_templates",
			Description: "根据标签/严重级别过滤并列出可用的 Nuclei 模板",
			InputSchema: map[string]interface{}{
				"tags":     "逗号分隔的标签过滤，如 cve,apache",
				"severity": "严重级别过滤，如 critical,high",
			},
			Handler: s.handleListTemplates,
		},
		{
			Name:        "run_scan",
			Description: "对指定目标执行 Nuclei 扫描并返回 JSONL 结果",
			InputSchema: map[string]interface{}{
				"target":    "扫描目标 URL",
				"tags":      "模板标签过滤（可选）",
				"severity":  "严重级别过滤（可选）",
				"templates": "指定模板路径列表（可选）",
				"rate_limit": "速率限制覆盖（可选）",
			},
			Handler: s.handleRunScan,
		},
		{
			Name:        "validate_template",
			Description: "使用 nuclei -validate 验证自定义模板的语法正确性",
			InputSchema: map[string]interface{}{
				"template_content": "YAML 模板内容字符串",
			},
			Handler: s.handleValidateTemplate,
		},
	}

	for _, tool := range tools {
		if err := s.registry.Register(tool); err != nil {
			logger.Error("注册 MCP 工具失败",
				zap.String("tool", tool.Name),
				zap.Error(err))
		}
	}
}

// GetRegistry 获取工具注册表（供 Nuclei Subagent 使用）
func (s *NucleiMCPServer) GetRegistry() *ToolRegistry {
	return s.registry
}

// handleListTemplates 列出模板工具实现
func (s *NucleiMCPServer) handleListTemplates(ctx context.Context, input ToolInput) (*ToolOutput, error) {
	tags, _ := input["tags"].(string)
	severity, _ := input["severity"].(string)

	args := []string{"-list", "-tpath", s.config.TemplatesPath}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	if severity != "" {
		args = append(args, "-severity", severity)
	}

	cmd := exec.CommandContext(ctx, s.config.NucleiBinaryPath, args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("列出模板失败: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	templates := make([]string, 0, len(lines))
	for _, line := range lines {
		if line = strings.TrimSpace(line); line != "" {
			templates = append(templates, line)
		}
	}

	return &ToolOutput{
		Success: true,
		Data:    map[string]interface{}{"templates": templates, "count": len(templates)},
	}, nil
}

// handleRunScan 执行扫描工具实现
func (s *NucleiMCPServer) handleRunScan(ctx context.Context, input ToolInput) (*ToolOutput, error) {
	target, ok := input["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("target 参数不能为空")
	}

	args := []string{
		"-target", target,
		"-jsonl",
		"-silent",
		"-no-color",
		"-tpath", s.config.TemplatesPath,
	}

	if tags, ok := input["tags"].(string); ok && tags != "" {
		args = append(args, "-tags", tags)
	}
	if severity, ok := input["severity"].(string); ok && severity != "" {
		args = append(args, "-severity", severity)
	}

	// 速率限制
	rateLimit := s.config.RateLimit
	if override, ok := input["rate_limit"].(int); ok && override > 0 {
		rateLimit = override
	}
	if rateLimit > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", rateLimit))
	}

	if s.config.BulkSize > 0 {
		args = append(args, "-bulk-size", fmt.Sprintf("%d", s.config.BulkSize))
	}
	if s.config.MaxHostErrors > 0 {
		args = append(args, "-mhe", fmt.Sprintf("%d", s.config.MaxHostErrors))
	}

	cmd := exec.CommandContext(ctx, s.config.NucleiBinaryPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("创建输出管道失败: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动 nuclei 失败: %w", err)
	}

	// 逐行解析 JSONL 输出
	var results []models.NucleiResultEvent
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var event models.NucleiResultEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			logger.Warn("解析 Nuclei JSONL 行失败",
				zap.String("line", line),
				zap.Error(err))
			continue
		}
		results = append(results, event)
	}

	if err := cmd.Wait(); err != nil {
		// 有漏洞发现时 nuclei 退出码非 0，这是正常行为
		logger.Info("Nuclei 扫描完成", zap.String("target", target), zap.Error(err))
	}

	return &ToolOutput{
		Success: true,
		Data: map[string]interface{}{
			"results": results,
			"count":   len(results),
			"target":  target,
		},
	}, nil
}

// handleValidateTemplate 验证模板工具实现
func (s *NucleiMCPServer) handleValidateTemplate(ctx context.Context, input ToolInput) (*ToolOutput, error) {
	content, ok := input["template_content"].(string)
	if !ok || content == "" {
		return nil, fmt.Errorf("template_content 参数不能为空")
	}

	// 写入临时文件后验证
	tmpFile := fmt.Sprintf("/tmp/nuclei_validate_%d.yaml", time.Now().UnixNano())
	cmd := exec.CommandContext(ctx, s.config.NucleiBinaryPath, "-validate", "-t", tmpFile)

	// 通过标准输入传入模板内容
	cmd.Stdin = strings.NewReader(content)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return &ToolOutput{
			Success: false,
			Error:   string(output),
		}, nil
	}

	return &ToolOutput{
		Success: true,
		Data:    map[string]interface{}{"message": "模板验证通过", "output": string(output)},
	}, nil
}
